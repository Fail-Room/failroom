"""serve-local's listener completes a terminal WebSocket over a real socket."""

import json
import socket
import threading
import time
import unittest
from datetime import UTC, datetime
from types import SimpleNamespace

import uvicorn
from fastapi import FastAPI
from wsproto import ConnectionType, WSConnection
from wsproto.events import (
    AcceptConnection,
    CloseConnection,
    RejectConnection,
    Request,
    TextMessage,
)

from failroom_control_plane import cli
from failroom_control_plane.websocket import WebSocketLimits, mount_terminal_route


class _Session:
    def __init__(self, closed: threading.Event) -> None:
        self._closed = closed

    def read(self, maximum: int) -> bytes:
        return b""

    def write(self, data: bytes) -> None:
        return None

    def resize(self, rows: int, columns: int) -> None:
        return None

    def signal(self, value: int) -> None:
        return None

    def close(self) -> None:
        self._closed.set()


class _Gateway:
    def authorize_and_lease(self, token, *, gateway_session_id, idempotency_key, now):
        return SimpleNamespace(lease=object())


class _Terminal:
    def __init__(self) -> None:
        self.closed = threading.Event()

    def admit(self, lease):
        return SimpleNamespace(release=lambda: None)

    def attach(self, lease, *, rows=None, columns=None):
        return _Session(self.closed)


def _terminal_exchange(port: int) -> tuple[list[object], int | None]:
    """Authorize and then close over a real socket; return messages and code."""
    connection = WSConnection(ConnectionType.CLIENT)
    messages: list[object] = []
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(
            connection.send(Request(host=f"127.0.0.1:{port}", target="/v1/terminal"))
        )
        while True:
            data = client.recv(65536)
            connection.receive_data(data or None)
            for event in connection.events():
                if isinstance(event, AcceptConnection):
                    frame = {
                        "type": "authorize",
                        "capability": "capability",
                        "rows": 24,
                        "columns": 80,
                    }
                    client.sendall(connection.send(TextMessage(data=json.dumps(frame))))
                elif isinstance(event, RejectConnection):
                    return messages, None
                elif isinstance(event, TextMessage):
                    message = json.loads(event.data)
                    messages.append(message)
                    if message == {"type": "authorized"}:
                        frame = {"type": "close"}
                        client.sendall(
                            connection.send(TextMessage(data=json.dumps(frame)))
                        )
                elif isinstance(event, CloseConnection):
                    client.sendall(connection.send(event.response()))
                    return messages, event.code
            if not data:
                return messages, None


class LocalServerTests(unittest.TestCase):
    def test_the_serve_local_listener_serves_the_terminal_websocket(self) -> None:
        terminal = _Terminal()
        app = FastAPI()
        mount_terminal_route(
            app,
            gateway=_Gateway(),
            terminal=terminal,
            limits=WebSocketLimits(
                authorization_timeout_seconds=5,
                max_frame_bytes=4096,
                max_input_bytes=1024,
                max_output_bytes=4096,
                max_rows=40,
                max_columns=120,
                poll_interval_seconds=0.01,
            ),
            now=lambda: datetime.now(UTC),
            origins=frozenset({"http://127.0.0.1"}),
        )
        server = uvicorn.Server(cli._server_config(app, "127.0.0.1", 0))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 10)
        self.addCleanup(setattr, server, "should_exit", True)
        deadline = time.monotonic() + 10
        while not server.started:
            self.assertTrue(thread.is_alive(), "the listener did not start")
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        port = server.servers[0].sockets[0].getsockname()[1]

        messages, code = _terminal_exchange(port)

        self.assertEqual(messages, [{"type": "authorized"}])
        self.assertEqual(code, 1000)
        self.assertTrue(terminal.closed.wait(5))


if __name__ == "__main__":
    unittest.main()
