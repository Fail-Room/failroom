"""Opt-in HTTP-to-real-PTY proof for the local trusted runtime."""

import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from failroom_control_plane.local_runtime import (
    LocalRuntimeConfig,
    build_runtime,
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
