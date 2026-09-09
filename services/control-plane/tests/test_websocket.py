import queue
import unittest
from datetime import UTC, datetime, timedelta

from failroom_sandbox.terminal_gateway import GatewayAttachment, GatewayError
from failroom_state import AttachmentLease, CapabilityUse, ResourceRef
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from failroom_control_plane.websocket import (
    WebSocketLimits,
    mount_terminal_route,
)


class RecordingSession:
    def __init__(self) -> None:
        self._output: queue.Queue[bytes] = queue.Queue()
        self.closed = 0

    def read(self, maximum: int) -> bytes:
        try:
            return self._output.get_nowait()
        except queue.Empty:
            return b""

    def write(self, data: bytes) -> None:
        if data == b"printf ok\n":
            self._output.put(b"ok\n")

    def resize(self, rows: int, columns: int) -> None:
        return None

    def signal(self, value: int) -> None:
        return None

    def close(self) -> None:
        self.closed += 1


class RecordingGateway:
    def __init__(self, attachment: GatewayAttachment) -> None:
        self.attachment = attachment
        self.calls: list[tuple[str, str, str]] = []
        self.error: GatewayError | None = None

    def authorize_and_lease(
        self,
        token: str,
        *,
        gateway_session_id: str,
        idempotency_key: str,
        now,
    ) -> GatewayAttachment:
        self.calls.append((token, gateway_session_id, idempotency_key))
        if self.error is not None:
            raise self.error
        return self.attachment


class RecordingTerminal:
    def __init__(self, session: RecordingSession) -> None:
        self.session = session
        self.leases: list[AttachmentLease] = []

    def attach(self, lease: AttachmentLease) -> RecordingSession:
        self.leases.append(lease)
        return self.session


class WebSocketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 9, tzinfo=UTC)
        ref = ResourceRef("attempt-1", "sandbox-1", 1)
        consumed = CapabilityUse(
            "a" * 64,
            ref,
            0,
            self.now + timedelta(seconds=30),
        )
        lease = AttachmentLease(
            "lease-1",
            ref,
            consumed.jti_hash,
            "b" * 64,
            0,
            self.now,
            self.now + timedelta(seconds=10),
            self.now,
        )
        self.session = RecordingSession()
        self.gateway = RecordingGateway(GatewayAttachment(consumed, lease))
        self.terminal = RecordingTerminal(self.session)
        self.app = FastAPI()
        mount_terminal_route(
            self.app,
            gateway=self.gateway,
            terminal=self.terminal,
            limits=WebSocketLimits(
                authorization_timeout_seconds=1,
                max_frame_bytes=4096,
                max_input_bytes=1024,
                max_output_bytes=4096,
                max_rows=100,
                max_columns=200,
                poll_interval_seconds=0.001,
            ),
            now=lambda: self.now,
        )
        self.client = TestClient(self.app)

    def test_first_frame_authorizes_and_relays_session_output(self) -> None:
        with self.client.websocket_connect("/v1/terminal") as socket:
            socket.send_json({"type": "authorize", "capability": "secret-capability"})
            self.assertEqual(socket.receive_json(), {"type": "authorized"})
            socket.send_json({"type": "input", "data": "printf ok\n"})
            self.assertEqual(socket.receive_json(), {"type": "output", "data": "ok\n"})
            socket.send_json({"type": "close"})

        self.assertEqual(len(self.gateway.calls), 1)
        self.assertEqual(len(self.terminal.leases), 1)
        self.assertEqual(self.session.closed, 1)

    def test_second_authorize_frame_is_protocol_denied(self) -> None:
        with self.client.websocket_connect("/v1/terminal") as socket:
            socket.send_json({"type": "authorize", "capability": "secret-capability"})
            self.assertEqual(socket.receive_json(), {"type": "authorized"})
            socket.send_json({"type": "authorize", "capability": "secret-capability"})
            with self.assertRaises(WebSocketDisconnect) as raised:
                socket.receive_json()

        self.assertEqual(raised.exception.code, 4400)
        self.assertEqual(len(self.gateway.calls), 1)

    def test_gateway_denial_closes_without_secret_details(self) -> None:
        self.gateway.error = GatewayError("CAPABILITY_REPLAY")

        with self.client.websocket_connect("/v1/terminal") as socket:
            socket.send_json({"type": "authorize", "capability": "secret-capability"})
            with self.assertRaises(WebSocketDisconnect) as raised:
                socket.receive_json()

        self.assertEqual(raised.exception.code, 4403)
        self.assertNotIn("secret-capability", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
