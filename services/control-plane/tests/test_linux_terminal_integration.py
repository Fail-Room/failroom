"""Opt-in proof of the trusted Linux Docker terminal vertical slice."""

import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from failroom_api import BackendCapabilityAuthority, CapabilityCodec
from failroom_sandbox.pty import DockerPtyRuntime, PtyLimits
from failroom_sandbox.terminal_gateway import TerminalGatewayAuthority
from failroom_state import (
    Action,
    BackendStore,
    CleanupTarget,
    ControlPlaneStore,
    Database,
    Role,
    ServiceIdentity,
    UserIdentity,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from test_linux_docker_integration import (
    _assert_hardening,
    _database_directory,
    _profile_from_environment,
    _required,
    build_runtime_from_required_environment,
)

from failroom_control_plane import ControlPlaneTerminalService
from failroom_control_plane.websocket import WebSocketLimits, mount_terminal_route

_TERMINAL_REQUIRED = (
    "FAILROOM_CAPABILITY_SECRET",
    "FAILROOM_CAPABILITY_LIFETIME_SECONDS",
    "FAILROOM_TERMINAL_INPUT_BYTES",
    "FAILROOM_TERMINAL_SESSION_SECONDS",
    "FAILROOM_TERMINAL_ROWS",
    "FAILROOM_TERMINAL_COLUMNS",
    "FAILROOM_TERMINAL_LEASE_SECONDS",
    "FAILROOM_TERMINAL_AUTH_TIMEOUT_SECONDS",
    "FAILROOM_TERMINAL_FRAME_BYTES",
    "FAILROOM_TERMINAL_POLL_INTERVAL_SECONDS",
)


def _terminal_limits() -> tuple[PtyLimits, WebSocketLimits]:
    return (
        PtyLimits(
            input_bytes=int(_required("FAILROOM_TERMINAL_INPUT_BYTES")),
            output_bytes=_profile_from_environment().terminal_output_limit_bytes,
            session_seconds=int(_required("FAILROOM_TERMINAL_SESSION_SECONDS")),
            rows=int(_required("FAILROOM_TERMINAL_ROWS")),
            columns=int(_required("FAILROOM_TERMINAL_COLUMNS")),
        ),
        WebSocketLimits(
            authorization_timeout_seconds=int(
                _required("FAILROOM_TERMINAL_AUTH_TIMEOUT_SECONDS")
            ),
            max_frame_bytes=int(_required("FAILROOM_TERMINAL_FRAME_BYTES")),
            max_input_bytes=int(_required("FAILROOM_TERMINAL_INPUT_BYTES")),
            max_output_bytes=_profile_from_environment().terminal_output_limit_bytes,
            max_rows=int(_required("FAILROOM_TERMINAL_ROWS")),
            max_columns=int(_required("FAILROOM_TERMINAL_COLUMNS")),
            poll_interval_seconds=float(
                _required("FAILROOM_TERMINAL_POLL_INTERVAL_SECONDS")
            ),
        ),
    )


@unittest.skipUnless(
    os.environ.get("FAILROOM_TERMINAL_INTEGRATION") == "1",
    "UNVERIFIED: opt-in required",
)
@unittest.skipUnless(
    sys.platform == "linux", "UNVERIFIED: trusted Linux controller required"
)
class LinuxTerminalIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        for name in _TERMINAL_REQUIRED:
            _required(name)
        self.database_root = _database_directory()
        self.database_temp = tempfile.TemporaryDirectory(dir=self.database_root)
        self.addCleanup(self.database_temp.cleanup)
        self.database_path = Path(self.database_temp.name) / "state.sqlite3"
        self.database = Database(
            self.database_path,
            busy_timeout_ms=int(_required("FAILROOM_DATABASE_BUSY_TIMEOUT_MS")),
        )
        self.database.initialize()
        self.backend = BackendStore(self.database)
        self.control = ControlPlaneStore(self.database)
        self.now = datetime(2026, 9, 9, tzinfo=UTC)
        self.deadline = self.now + timedelta(
            seconds=int(_required("FAILROOM_ABSOLUTE_TTL_SECONDS"))
        )
        suffix = uuid4().hex
        self.user = UserIdentity(
            "linux-terminal-" + suffix,
            frozenset({"disk-full"}),
        )
        self.backend_identity = ServiceIdentity(
            "linux-terminal-backend-" + suffix,
            Role.BACKEND,
            frozenset({Action.CREATE, Action.PUBLISH, Action.RECONCILE}),
        )
        self.control_identity = ServiceIdentity(
            "linux-terminal-control-" + suffix,
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.TRANSITION, Action.RECONCILE}),
        )
        self.gateway_identity = ServiceIdentity(
            "linux-terminal-gateway-" + suffix,
            Role.GATEWAY,
            frozenset({Action.CONSUME, Action.ATTACH}),
        )
        self.profile = _profile_from_environment()
        self.provisioning, self.cleanup = build_runtime_from_required_environment()
        from failroom_control_plane import LifecycleOrchestrator

        self.orchestrator = LifecycleOrchestrator(
            self.backend, self.control, self.provisioning
        )
        from failroom_state import DockerCleanupWorker

        self.cleanup_worker = DockerCleanupWorker(
            self.control,
            self.backend,
            self.cleanup,
            retry_delay=timedelta(seconds=10),
        )
        pty_limits, websocket_limits = _terminal_limits()
        self.websocket_limits = websocket_limits
        self.terminal = ControlPlaneTerminalService(
            self.control,
            DockerPtyRuntime(
                context=_required("FAILROOM_DOCKER_CONTEXT"),
                limits=pty_limits,
            ),
            self.control_identity,
            lambda: self.now,
        )
        self.codec = CapabilityCodec(
            _required("FAILROOM_CAPABILITY_SECRET").encode("utf-8"),
            max_lifetime=timedelta(
                seconds=int(_required("FAILROOM_CAPABILITY_LIFETIME_SECONDS"))
            ),
        )
        self.authority = BackendCapabilityAuthority(self.backend, self.codec)
        self.gateway = TerminalGatewayAuthority(
            self.authority,
            self.control,
            self.gateway_identity,
            lease_duration=timedelta(
                seconds=int(_required("FAILROOM_TERMINAL_LEASE_SECONDS"))
            ),
        )
        self.inspect_cli = self._inspect_cli()

    def _inspect_cli(self):
        from failroom_sandbox.docker_cli import DockerCli

        return DockerCli(
            context=_required("FAILROOM_DOCKER_CONTEXT"),
            timeout=float(_required("FAILROOM_DOCKER_TIMEOUT_SECONDS")),
            max_output_bytes=int(_required("FAILROOM_DOCKER_MAX_OUTPUT_BYTES")),
        )

    def _provision(self):
        receipt = self.backend.create(
            self.user,
            "disk-full",
            key=uuid4().hex,
            expires_at=self.deadline,
            now=lambda: self.now,
        )
        self.orchestrator.provision(
            receipt,
            backend_identity=self.backend_identity,
            control_identity=self.control_identity,
            key=uuid4().hex,
            now=lambda: self.now,
        )
        return receipt

    def _app(self) -> FastAPI:
        app = FastAPI()
        mount_terminal_route(
            app,
            gateway=self.gateway,
            terminal=self.terminal,
            limits=self.websocket_limits,
            now=lambda: self.now,
        )
        return app

    @staticmethod
    def _receive_until(socket, marker: str) -> str:
        for _ in range(200):
            message = socket.receive_json()
            if message.get("type") == "output" and marker in message.get("data", ""):
                return message["data"]
        raise AssertionError("terminal marker not observed")

    def _cleanup(self, receipt) -> None:
        resource = self.control.inspect(self.control_identity, receipt.ref)
        if resource.state != "DESTROYED":
            self.backend.leave(
                self.user,
                receipt.ref,
                key="leave-" + uuid4().hex,
                now=lambda: self.now,
            )
            self.cleanup_worker.run_once(
                self.control_identity,
                self.backend_identity,
                now=lambda: self.now,
                limit=1,
            )
        resource = self.control.inspect(self.control_identity, receipt.ref)
        target = CleanupTarget(
            receipt.ref,
            resource.container_id,
            resource.runtime_operation_id,
            "linux-terminal-finally",
        )
        self.cleanup.destroy_and_verify_absent(target)

    def test_real_terminal_relays_input_ansi_and_resize(self) -> None:
        receipt = self._provision()
        try:
            issued = self.authority.issue(
                self.user,
                receipt.attempt_id,
                now=lambda: self.now,
            )
            resource = self.control.inspect(self.control_identity, receipt.ref)
            self.assertIsNotNone(resource.container_id)
            data = self.inspect_cli.inspect_container(resource.container_id)
            self.assertIsNotNone(data)
            _assert_hardening(self, data, self.profile)

            with TestClient(self._app()).websocket_connect("/v1/terminal") as socket:
                socket.send_json({"type": "authorize", "capability": issued.token})
                self.assertEqual(socket.receive_json(), {"type": "authorized"})
                socket.send_json({"type": "resize", "rows": 30, "columns": 120})
                marker = "FAILROOM_ANSI_MARKER"
                socket.send_json(
                    {
                        "type": "input",
                        "data": f"printf '\\033[31m{marker}\\033[0m\\n'\n",
                    }
                )
                output = self._receive_until(socket, marker)
                self.assertIn("\x1b[31m", output)
                socket.send_json({"type": "close"})
        finally:
            self._cleanup(receipt)

    def test_real_terminal_signal_and_capability_replay_are_denied(self) -> None:
        receipt = self._provision()
        try:
            issued = self.authority.issue(
                self.user,
                receipt.attempt_id,
                now=lambda: self.now,
            )
            with TestClient(self._app()).websocket_connect("/v1/terminal") as socket:
                socket.send_json({"type": "authorize", "capability": issued.token})
                self.assertEqual(socket.receive_json(), {"type": "authorized"})
                socket.send_json({"type": "input", "data": "sleep 30\n"})
                socket.send_json({"type": "signal", "value": 2})
                marker = "FAILROOM_INTERRUPT_MARKER"
                socket.send_json({"type": "input", "data": f"printf {marker}\\n"})
                self._receive_until(socket, marker)
                socket.send_json({"type": "close"})

            with TestClient(self._app()).websocket_connect("/v1/terminal") as socket:
                socket.send_json({"type": "authorize", "capability": issued.token})
                with self.assertRaises(WebSocketDisconnect) as raised:
                    socket.receive_json()
            self.assertEqual(raised.exception.code, 4403)
        finally:
            self._cleanup(receipt)


if __name__ == "__main__":
    unittest.main()
