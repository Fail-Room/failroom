"""Opt-in HTTP-to-real-PTY proof for the local trusted runtime."""

import os
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from failroom_sandbox.docker_lifecycle import DockerDiagnosticLifecycle
from failroom_sandbox.docker_profile import DockerBinding
from failroom_sandbox.models import DenialCode
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from failroom_control_plane import cli as control_plane_cli
from failroom_control_plane.local_runtime import (
    LocalRuntimeConfig,
    build_runtime,
)
from failroom_control_plane.qualification_collector import (
    QualificationError,
    qualification_attempt,
)
from failroom_control_plane.qualification_workspace import (
    WORKSPACE_NAME,
    workspace_id,
)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise unittest.SkipTest("UNVERIFIED: missing explicit operator input")
    return value


@unittest.skipUnless(
    os.environ.get("FAILROOM_LOCAL_RUNTIME_INTEGRATION") == "1",
    "UNVERIFIED: opt-in required",
)
@unittest.skipUnless(
    sys.platform == "linux", "UNVERIFIED: trusted Linux controller required"
)
class LinuxLocalRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database_root = Path(_required("FAILROOM_DATABASE_DIR"))
        if not self.database_root.is_absolute() or not self.database_root.is_dir():
            raise unittest.SkipTest(
                "UNVERIFIED: FAILROOM_DATABASE_DIR must be an existing absolute directory"
            )
        self.database_temp = tempfile.TemporaryDirectory(dir=self.database_root)
        self.addCleanup(self.database_temp.cleanup)
        self.token = _required("FAILROOM_LOCAL_BEARER_TOKEN")

    @staticmethod
    def _receive_until(
        socket, marker: str, *, required_fragment: str | None = None
    ) -> str:
        for _ in range(200):
            message = socket.receive_json()
            output = message.get("data", "")
            if (
                message.get("type") == "output"
                and marker in output
                and (required_fragment is None or required_fragment in output)
            ):
                return output
        raise AssertionError("terminal marker not observed")

    @staticmethod
    def _wait_for_attempt_state(
        client, attempt_id: str, headers: dict[str, str], expected: str
    ) -> dict[str, object]:
        deadline = time.monotonic() + 5
        while True:
            response = client.get(
                "/v1/attempts/" + attempt_id + "/status", headers=headers
            )
            if response.status_code == 200 and response.json().get("state") == expected:
                return response.json()
            if time.monotonic() >= deadline:
                raise AssertionError("attempt did not reach " + expected)
            time.sleep(0.05)

    def test_enter_capability_terminal_and_leave_through_local_app(self) -> None:
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        config = LocalRuntimeConfig.from_environment(environment)
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}

        with TestClient(runtime.app) as client:
            attempt_id: str | None = None
            try:
                entered = client.post(
                    "/v1/rooms/disk-full/attempts",
                    headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
                )
                self.assertEqual(entered.status_code, 201)
                attempt_id = entered.json()["attempt_id"]

                capability = client.post(
                    "/v1/attempts/" + attempt_id + "/terminal-capability",
                    headers=headers,
                )
                self.assertEqual(capability.status_code, 200)

                with client.websocket_connect("/v1/terminal") as socket:
                    socket.send_json(
                        {
                            "type": "authorize",
                            "capability": capability.json()["capability"],
                        }
                    )
                    self.assertEqual(socket.receive_json(), {"type": "authorized"})
                    marker = "FAILROOM_LOCAL_RUNTIME_" + uuid4().hex
                    socket.send_json(
                        {
                            "type": "input",
                            "data": f"printf '\\033[31m{marker}\\033[0m\\n'\n",
                        }
                    )
                    self.assertIn(
                        "\x1b[31m",
                        self._receive_until(
                            socket,
                            marker,
                            required_fragment="\x1b[31m",
                        ),
                    )
                    socket.send_json({"type": "close"})
            finally:
                if attempt_id is not None:
                    left = client.post(
                        "/v1/attempts/" + attempt_id + "/leave",
                        headers={
                            **headers,
                            "idempotency-key": "leave-" + uuid4().hex,
                        },
                    )
                    self.assertEqual(left.status_code, 202)

    def test_room_allocation_needs_the_live_sentinel_of_a_passing_report(
        self,
    ) -> None:
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        config = LocalRuntimeConfig.from_environment(environment)
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}
        docker = config.controller.docker_cli()

        with TestClient(runtime.app) as client:
            self.assertTrue(runtime.qualification.decide().allowed)
            # serve-local holds the workspace, so a report-only collection
            # against the same database is refused before any Docker call.
            with self.assertRaises(QualificationError) as raised:
                control_plane_cli._qualify_local(environment)
            self.assertEqual(raised.exception.code, "COLLECTION_IN_PROGRESS")
            attempt = qualification_attempt(
                workspace_id(Path(self.database_temp.name) / WORKSPACE_NAME)
            )
            (sentinel,) = docker.list_containers(
                (
                    "label=failroom.kind=diagnostic",
                    "label=failroom.attempt_id=" + attempt,
                )
            )
            data = docker.inspect_container(sentinel)
            labels = data["Config"]["Labels"]
            # The sentinel lives as long as the report is valid, not the TTL.
            validity = config.qualification_max_age.total_seconds()
            self.assertGreater(validity, config.controller.profile.absolute_ttl_seconds)
            self.assertGreaterEqual(int(data["Config"]["Cmd"][0]), validity - 5)
            DockerDiagnosticLifecycle(
                docker, config.controller.seccomp_policy_store()
            ).destroy(
                DockerBinding(attempt, labels["failroom.sandbox_id"], 1),
                sentinel,
                operation_id=labels["failroom.operation_id"],
            )
            before = set(docker.list_containers(("label=failroom.kind=diagnostic",)))

            refused = client.post(
                "/v1/rooms/disk-full/attempts",
                headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
            )
            try:
                self.assertEqual(
                    (refused.status_code, refused.json()),
                    (503, {"code": "ENTRY_FAILED"}),
                )
                self.assertEqual(
                    set(docker.list_containers(("label=failroom.kind=diagnostic",))),
                    before,
                )
                self.assertEqual(
                    {denial.code for denial in runtime.qualification.decide().denials},
                    {DenialCode.CONTEXT_INVALID},
                )
            finally:
                if refused.status_code == 201:
                    # A wrongly admitted Room is left so shutdown maintenance
                    # removes it even when this test fails.
                    client.post(
                        "/v1/attempts/" + refused.json()["attempt_id"] + "/leave",
                        headers={**headers, "idempotency-key": "leave-" + uuid4().hex},
                    )

    def test_report_is_refreshed_before_it_expires(self) -> None:
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        # A short validity and maintenance interval bring the refresh quickly.
        environment["FAILROOM_QUALIFICATION_MAX_AGE_SECONDS"] = "150"
        environment["FAILROOM_MAINTENANCE_INTERVAL_SECONDS"] = "5"
        config = LocalRuntimeConfig.from_environment(environment)
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}
        docker = config.controller.docker_cli()

        with TestClient(runtime.app) as client:
            attempt = qualification_attempt(
                workspace_id(Path(self.database_temp.name) / WORKSPACE_NAME)
            )

            def collector_sandboxes() -> tuple[str, ...]:
                return docker.list_containers(
                    (
                        "label=failroom.kind=diagnostic",
                        "label=failroom.attempt_id=" + attempt,
                    )
                )

            (first,) = collector_sandboxes()
            # Half the validity passes, a refresh collects, and only its
            # sentinel stays.
            deadline = time.monotonic() + 150
            current = (first,)
            while time.monotonic() < deadline:
                current = collector_sandboxes()
                if len(current) == 1 and current[0] != first:
                    break
                time.sleep(2)
            self.assertEqual(len(current), 1)
            self.assertNotEqual(current[0], first)
            self.assertIsNone(docker.inspect_container(first))
            self.assertTrue(runtime.qualification.decide().allowed)

            entered = client.post(
                "/v1/rooms/disk-full/attempts",
                headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
            )
            self.assertEqual(entered.status_code, 201)
            left = client.post(
                "/v1/attempts/" + entered.json()["attempt_id"] + "/leave",
                headers={**headers, "idempotency-key": "leave-" + uuid4().hex},
            )
            self.assertEqual(left.status_code, 202)

    def test_an_expired_sandbox_is_removed_while_the_runtime_is_down(self) -> None:
        """No Failroom process runs at the deadline, yet the sandbox is gone (~2 min)."""
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        # A short TTL brings the deadline quickly, a short interval the record.
        environment["FAILROOM_ABSOLUTE_TTL_SECONDS"] = "60"
        environment["FAILROOM_MAINTENANCE_INTERVAL_SECONDS"] = "5"
        config = LocalRuntimeConfig.from_environment(environment)
        headers = {"authorization": "Bearer " + self.token}
        docker = config.controller.docker_cli()

        with TestClient(
            build_runtime(config, now=lambda: datetime.now(UTC)).app
        ) as client:
            entered = client.post(
                "/v1/rooms/disk-full/attempts",
                headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
            )
            self.assertEqual(entered.status_code, 201)
        attempt_id = entered.json()["attempt_id"]
        expires_at = datetime.fromisoformat(entered.json()["expires_at"])

        def room_sandboxes() -> tuple[str, ...]:
            return docker.list_containers(
                (
                    "label=failroom.kind=diagnostic",
                    "label=failroom.attempt_id=" + attempt_id,
                )
            )

        try:
            # Shutdown leaves an attempt that has not expired running.
            (sandbox,) = room_sandboxes()
            self.assertIs(docker.inspect_container(sandbox)["State"]["Running"], True)

            # Nothing runs maintenance now; Docker removes the sandbox itself
            # once PID 1 exits, before the deadline.
            give_up = time.monotonic() + 90
            while room_sandboxes() and time.monotonic() < give_up:
                time.sleep(1)
            self.assertEqual(room_sandboxes(), ())
            self.assertLessEqual(datetime.now(UTC), expires_at)
            time.sleep(max(0.0, (expires_at - datetime.now(UTC)).total_seconds()) + 1)

            # Started again, the runtime records the absence it verifies.
            with TestClient(
                build_runtime(config, now=lambda: datetime.now(UTC)).app
            ) as client:
                give_up = time.monotonic() + 30
                while True:
                    status = client.get(
                        "/v1/attempts/" + attempt_id + "/status", headers=headers
                    )
                    self.assertEqual(status.status_code, 200)
                    if status.json()["state"] == "DESTROYED":
                        break
                    self.assertLess(time.monotonic(), give_up, status.json())
                    time.sleep(1)
        finally:
            # Should Docker not remove it, leave nothing behind for other tests.
            lifecycle = DockerDiagnosticLifecycle(
                docker, config.controller.seccomp_policy_store()
            )
            for left in room_sandboxes():
                data = docker.inspect_container(left)
                if data is None:
                    continue
                labels = data["Config"]["Labels"]
                lifecycle.destroy(
                    DockerBinding(
                        attempt_id,
                        labels["failroom.sandbox_id"],
                        int(labels["failroom.generation"]),
                    ),
                    left,
                    operation_id=labels["failroom.operation_id"],
                )

    def test_enter_rejects_unreviewed_and_unauthorized_rooms_without_state(
        self,
    ) -> None:
        environment = dict(os.environ)
        database_path = Path(self.database_temp.name) / "state.sqlite3"
        environment["FAILROOM_DATABASE_PATH"] = str(database_path)
        # The local operator identity may enter only a Room with no scenario.
        environment["FAILROOM_LOCAL_ROOM_SCOPES"] = "scenario-less-room"
        config = LocalRuntimeConfig.from_environment(environment)
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}

        with TestClient(runtime.app) as client:
            unreviewed = client.post(
                "/v1/rooms/scenario-less-room/attempts",
                headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
            )
            unauthorized = client.post(
                "/v1/rooms/disk-full/attempts",
                headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
            )

        self.assertEqual(
            (unreviewed.status_code, unreviewed.json()),
            (404, {"code": "ROOM_UNAVAILABLE"}),
        )
        self.assertEqual(
            (unauthorized.status_code, unauthorized.json()),
            (403, {"code": "AUTHORIZATION_FAILED"}),
        )
        with closing(sqlite3.connect(database_path)) as connection:
            attempts = connection.execute("SELECT COUNT(*) FROM room_attempts")
            self.assertEqual(attempts.fetchone(), (0,))

    def test_terminal_session_outlives_sixty_seconds_through_local_app(self) -> None:
        """Keep one learner terminal responsive for 70 seconds (slow, opt-in)."""
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        config = LocalRuntimeConfig.from_environment(environment)
        if (
            config.controller.profile.absolute_ttl_seconds < 120
            or config.pty_limits.session_seconds < 90
        ):
            raise unittest.SkipTest(
                "UNVERIFIED: requires FAILROOM_ABSOLUTE_TTL_SECONDS >= 120 and "
                "FAILROOM_TERMINAL_SESSION_SECONDS >= 90"
            )
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}

        with TestClient(runtime.app) as client:
            attempt_id: str | None = None
            try:
                entered = client.post(
                    "/v1/rooms/disk-full/attempts",
                    headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
                )
                self.assertEqual(entered.status_code, 201)
                attempt_id = entered.json()["attempt_id"]
                capability = client.post(
                    "/v1/attempts/" + attempt_id + "/terminal-capability",
                    headers=headers,
                )
                self.assertEqual(capability.status_code, 200)

                with client.websocket_connect("/v1/terminal") as socket:
                    socket.send_json(
                        {
                            "type": "authorize",
                            "capability": capability.json()["capability"],
                        }
                    )
                    self.assertEqual(socket.receive_json(), {"type": "authorized"})
                    started = time.monotonic()
                    tick = 0
                    while time.monotonic() - started < 70:
                        tick += 1
                        socket.send_json(
                            {"type": "input", "data": f"echo T$((1000+{tick}))\n"}
                        )
                        self._receive_until(socket, f"T{1000 + tick}")
                        time.sleep(5)
                    socket.send_json({"type": "close"})

                status = client.get(
                    "/v1/attempts/" + attempt_id + "/status", headers=headers
                )
                self.assertEqual(status.status_code, 200)
                self.assertEqual(status.json()["state"], "READY")
            finally:
                if attempt_id is not None:
                    left = client.post(
                        "/v1/attempts/" + attempt_id + "/leave",
                        headers={
                            **headers,
                            "idempotency-key": "leave-" + uuid4().hex,
                        },
                    )
                    self.assertEqual(left.status_code, 202)

    def test_terminal_recovery_verification_and_leave_through_local_app(self) -> None:
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        config = LocalRuntimeConfig.from_environment(environment)
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}

        with TestClient(runtime.app) as client:
            attempt_id: str | None = None
            try:
                entered = client.post(
                    "/v1/rooms/disk-full/attempts",
                    headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
                )
                self.assertEqual(entered.status_code, 201)
                attempt_id = entered.json()["attempt_id"]

                unrecovered = client.post(
                    "/v1/attempts/" + attempt_id + "/verify-recovery",
                    headers={
                        **headers,
                        "idempotency-key": "unrecovered-" + uuid4().hex,
                    },
                )
                self.assertEqual(unrecovered.status_code, 409)
                self.assertEqual(unrecovered.json(), {"code": "RECOVERY_NOT_VERIFIED"})
                status = client.get(
                    "/v1/attempts/" + attempt_id + "/status", headers=headers
                )
                self.assertEqual(status.status_code, 200)
                self.assertEqual(status.json()["state"], "RUNNING")

                capability = client.post(
                    "/v1/attempts/" + attempt_id + "/terminal-capability",
                    headers=headers,
                )
                self.assertEqual(capability.status_code, 200)

                with client.websocket_connect("/v1/terminal") as socket:
                    socket.send_json(
                        {
                            "type": "authorize",
                            "capability": capability.json()["capability"],
                        }
                    )
                    self.assertEqual(socket.receive_json(), {"type": "authorized"})
                    marker = "FAILROOM_LOCAL_RECOVERY_" + uuid4().hex
                    socket.send_json(
                        {
                            "type": "input",
                            "data": (
                                "rm -- /workspace/.failroom-disk-full && "
                                + "printf '\\033[32m"
                                + marker
                                + "\\033[0m\\n'\n"
                            ),
                        }
                    )
                    # The echoed command also contains the marker; only the
                    # printf that runs after a successful rm emits the ANSI byte.
                    self.assertIn(
                        marker,
                        self._receive_until(
                            socket, marker, required_fragment="\x1b[32m"
                        ),
                    )
                    socket.send_json({"type": "close"})

                recovered = client.post(
                    "/v1/attempts/" + attempt_id + "/verify-recovery",
                    headers={
                        **headers,
                        "idempotency-key": "recover-" + uuid4().hex,
                    },
                )
                self.assertEqual(recovered.status_code, 200)
                self.assertEqual(recovered.json()["state"], "RESOLVED")
            finally:
                if attempt_id is not None:
                    left = client.post(
                        "/v1/attempts/" + attempt_id + "/leave",
                        headers={
                            **headers,
                            "idempotency-key": "leave-" + uuid4().hex,
                        },
                    )
                    self.assertEqual(left.status_code, 202)
                    # Leave runs one bounded cleanup pass, which may already
                    # finish destruction; either way it must end DESTROYED.
                    self.assertIn(left.json()["state"], {"STOPPING", "DESTROYED"})
                    self.assertTrue(left.json()["destroy_intent"])
                    destroyed = self._wait_for_attempt_state(
                        client, attempt_id, headers, "DESTROYED"
                    )
                    self.assertEqual(destroyed["state"], "DESTROYED")

    def test_reused_capability_is_denied_through_local_app(self) -> None:
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        config = LocalRuntimeConfig.from_environment(environment)
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}

        with TestClient(runtime.app) as client:
            attempt_id: str | None = None
            try:
                entered = client.post(
                    "/v1/rooms/disk-full/attempts",
                    headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
                )
                self.assertEqual(entered.status_code, 201)
                attempt_id = entered.json()["attempt_id"]

                capability = client.post(
                    "/v1/attempts/" + attempt_id + "/terminal-capability",
                    headers=headers,
                )
                self.assertEqual(capability.status_code, 200)
                token = capability.json()["capability"]

                with client.websocket_connect("/v1/terminal") as socket:
                    socket.send_json({"type": "authorize", "capability": token})
                    self.assertEqual(socket.receive_json(), {"type": "authorized"})
                    socket.send_json({"type": "close"})

                with client.websocket_connect("/v1/terminal") as socket:
                    socket.send_json({"type": "authorize", "capability": token})
                    with self.assertRaises(WebSocketDisconnect) as raised:
                        socket.receive_json()
                self.assertEqual(raised.exception.code, 4403)
            finally:
                if attempt_id is not None:
                    left = client.post(
                        "/v1/attempts/" + attempt_id + "/leave",
                        headers={
                            **headers,
                            "idempotency-key": "leave-" + uuid4().hex,
                        },
                    )
                    self.assertEqual(left.status_code, 202)

    def test_reset_invalidates_issued_capability_through_local_app(self) -> None:
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        config = LocalRuntimeConfig.from_environment(environment)
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}

        with TestClient(runtime.app) as client:
            attempt_id: str | None = None
            try:
                entered = client.post(
                    "/v1/rooms/disk-full/attempts",
                    headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
                )
                self.assertEqual(entered.status_code, 201)
                attempt_id = entered.json()["attempt_id"]

                capability = client.post(
                    "/v1/attempts/" + attempt_id + "/terminal-capability",
                    headers=headers,
                )
                self.assertEqual(capability.status_code, 200)

                reset = client.post(
                    "/v1/attempts/" + attempt_id + "/reset",
                    headers={**headers, "idempotency-key": "reset-" + uuid4().hex},
                )
                self.assertEqual(reset.status_code, 202)
                self.assertEqual(reset.json()["state"], "RESETTING")

                with client.websocket_connect("/v1/terminal") as socket:
                    socket.send_json(
                        {
                            "type": "authorize",
                            "capability": capability.json()["capability"],
                        }
                    )
                    with self.assertRaises(WebSocketDisconnect) as raised:
                        socket.receive_json()
                self.assertEqual(raised.exception.code, 4403)
            finally:
                if attempt_id is not None:
                    left = client.post(
                        "/v1/attempts/" + attempt_id + "/leave",
                        headers={
                            **headers,
                            "idempotency-key": "leave-" + uuid4().hex,
                        },
                    )
                    self.assertEqual(left.status_code, 202)

    def test_reset_maintenance_destroys_prior_sandbox(self) -> None:
        environment = dict(os.environ)
        environment["FAILROOM_DATABASE_PATH"] = str(
            Path(self.database_temp.name) / "state.sqlite3"
        )
        config = LocalRuntimeConfig.from_environment(environment)
        runtime = build_runtime(config, now=lambda: datetime.now(UTC))
        headers = {"authorization": "Bearer " + self.token}

        with TestClient(runtime.app) as client:
            attempt_id: str | None = None
            try:
                entered = client.post(
                    "/v1/rooms/disk-full/attempts",
                    headers={**headers, "idempotency-key": "enter-" + uuid4().hex},
                )
                self.assertEqual(entered.status_code, 201)
                attempt_id = entered.json()["attempt_id"]

                reset = client.post(
                    "/v1/attempts/" + attempt_id + "/reset",
                    headers={**headers, "idempotency-key": "reset-" + uuid4().hex},
                )
                self.assertEqual(reset.status_code, 202)

                maintenance = runtime.maintenance.run_once()
                self.assertEqual(maintenance.cleanup.destroyed, 1)
                self.assertEqual(maintenance.cleanup.deferred, 0)

                status = client.get(
                    "/v1/attempts/" + attempt_id + "/status", headers=headers
                )
                self.assertEqual(status.status_code, 200)
                self.assertEqual(status.json()["state"], "READY")
            finally:
                if attempt_id is not None:
                    left = client.post(
                        "/v1/attempts/" + attempt_id + "/leave",
                        headers={
                            **headers,
                            "idempotency-key": "leave-" + uuid4().hex,
                        },
                    )
                    self.assertEqual(left.status_code, 202)


class LocalRuntimeTerminalOutputEvidenceTests(unittest.TestCase):
    def test_receive_until_requires_requested_output_fragment(self) -> None:
        marker = "FAILROOM_LOCAL_RUNTIME_ANSI_MARKER"
        messages = iter(
            (
                {
                    "type": "output",
                    "data": f"printf '\\033[31m{marker}\\033[0m\\n'\r\n",
                },
                {"type": "output", "data": f"\x1b[31m{marker}\x1b[0m\r\n"},
            )
        )
        socket = SimpleNamespace(receive_json=lambda: next(messages))

        output = LinuxLocalRuntimeIntegrationTests._receive_until(
            socket,
            marker,
            required_fragment="\x1b[31m",
        )

        self.assertEqual(output, f"\x1b[31m{marker}\x1b[0m\r\n")


if __name__ == "__main__":
    unittest.main()
