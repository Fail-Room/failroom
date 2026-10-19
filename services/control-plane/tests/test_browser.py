import unittest

from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from failroom_control_plane.browser import (
    LoopbackGuard,
    LoopbackOrigin,
    loopback_origin,
)

HARDENING = {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cross-origin-resource-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
}


class LoopbackOriginTests(unittest.TestCase):
    def test_names_the_listener_by_its_address_and_localhost(self) -> None:
        origin = loopback_origin("127.0.0.1", 18765)

        self.assertEqual(
            origin.hosts, frozenset({"127.0.0.1:18765", "localhost:18765"})
        )
        self.assertEqual(
            origin.origins,
            frozenset({"http://127.0.0.1:18765", "http://localhost:18765"}),
        )
        self.assertEqual(
            loopback_origin("::1", 8080).hosts,
            frozenset({"[::1]:8080", "localhost:8080"}),
        )
        # A browser leaves the default port out of Host and Origin.
        self.assertEqual(
            loopback_origin("127.0.0.1", 80).hosts,
            frozenset({"127.0.0.1:80", "localhost:80", "127.0.0.1", "localhost"}),
        )

    def test_refuses_a_listener_that_is_not_loopback(self) -> None:
        for host, port in (
            ("0.0.0.0", 18765),
            ("localhost", 18765),
            ("127.0.0.1", 0),
            ("127.0.0.1", 65_536),
            ("127.0.0.1", "18765"),
        ):
            with self.subTest(host=host, port=port), self.assertRaises(ValueError):
                loopback_origin(host, port)

    def test_allows_only_its_own_origins(self) -> None:
        origin = loopback_origin("127.0.0.1", 18765)

        self.assertTrue(origin.allows("http://127.0.0.1:18765"))
        self.assertTrue(origin.allows("http://localhost:18765"))
        for other in (
            None,
            "",
            "null",
            "http://127.0.0.1:18766",
            "https://127.0.0.1:18765",
            "http://attacker.example",
        ):
            with self.subTest(origin=other):
                self.assertFalse(origin.allows(other))

    def test_values_are_explicit(self) -> None:
        for hosts, origins in (
            (frozenset(), frozenset({"http://a"})),
            (frozenset({"a"}), frozenset()),
            ({"a"}, frozenset({"http://a"})),
            (frozenset({""}), frozenset({"http://a"})),
        ):
            with self.subTest(hosts=hosts, origins=origins):
                with self.assertRaises(ValueError):
                    LoopbackOrigin(hosts, origins)


class LoopbackGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        app = FastAPI()

        @app.get("/v1/ping")
        def ping() -> dict[str, bool]:
            return {"ok": True}

        @app.get("/v1/own-policy")
        def own_policy() -> JSONResponse:
            return JSONResponse(
                {"ok": True}, headers={"content-security-policy": "default-src 'self'"}
            )

        @app.websocket("/v1/socket")
        async def socket(websocket: WebSocket) -> None:
            await websocket.accept()
            await websocket.send_json({"ok": True})
            await websocket.close()

        app.add_middleware(LoopbackGuard, origin=loopback_origin("127.0.0.1", 18765))
        self.app = app

    def client(self, host: str) -> TestClient:
        return TestClient(self.app, base_url="http://" + host)

    def test_a_request_naming_the_runtime_passes_with_hardening_headers(
        self,
    ) -> None:
        for host in ("127.0.0.1:18765", "localhost:18765"):
            with self.subTest(host=host):
                response = self.client(host).get("/v1/ping")
                self.assertEqual(
                    (response.status_code, response.json()), (200, {"ok": True})
                )
                for name, value in HARDENING.items():
                    self.assertEqual(response.headers[name], value)

    def test_a_route_keeps_a_header_it_sets_itself(self) -> None:
        response = self.client("127.0.0.1:18765").get("/v1/own-policy")

        self.assertEqual(
            response.headers["content-security-policy"], "default-src 'self'"
        )
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_any_other_host_is_refused(self) -> None:
        for host in (
            "attacker.example",
            "attacker.example:18765",
            "127.0.0.1:8080",
            "127.0.0.1",
            "localhost",
        ):
            with self.subTest(host=host):
                response = self.client(host).get("/v1/ping")
                self.assertEqual(
                    (response.status_code, response.json()),
                    (400, {"code": "HOST_NOT_ALLOWED"}),
                )
                self.assertEqual(response.headers["cache-control"], "no-store")

    def test_a_websocket_naming_another_host_closes_before_the_application(
        self,
    ) -> None:
        with self.assertRaises(WebSocketDisconnect) as raised:
            with self.client("attacker.example").websocket_connect(
                "ws://attacker.example/v1/socket"
            ):
                pass
        self.assertEqual(raised.exception.code, 1008)

        with self.client("127.0.0.1:18765").websocket_connect(
            "ws://127.0.0.1:18765/v1/socket"
        ) as socket:
            self.assertEqual(socket.receive_json(), {"ok": True})

    def test_the_guard_needs_a_loopback_origin(self) -> None:
        with self.assertRaises(ValueError):
            LoopbackGuard(FastAPI(), origin={"127.0.0.1:18765"})


if __name__ == "__main__":
    unittest.main()
