"""The loopback origin a browser must use, and the guard that enforces it."""

from dataclasses import dataclass

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocketClose

SESSION_COOKIE = "failroom_session"
# Applied to every HTTP response; a route may set its own value first.
_RESPONSE_HEADERS = {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cross-origin-resource-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
}


@dataclass(frozen=True)
class LoopbackOrigin:
    """The Host values and browser origins that name this runtime."""

    hosts: frozenset[str]
    origins: frozenset[str]

    def __post_init__(self) -> None:
        if (
            type(self.hosts) is not frozenset
            or type(self.origins) is not frozenset
            or not self.hosts
            or not self.origins
            or not all(type(value) is str and value for value in self.hosts)
            or not all(type(value) is str and value for value in self.origins)
        ):
            raise ValueError("invalid loopback origin")

    def allows(self, origin: str | None) -> bool:
        """Whether a browser's Origin header names this runtime."""
        return origin is not None and origin in self.origins


def loopback_origin(bind_host: str, port: int) -> LoopbackOrigin:
    """The names a browser on this host uses to reach a loopback listener."""
    if bind_host == "127.0.0.1":
        names = ("127.0.0.1", "localhost")
    elif bind_host == "::1":
        names = ("[::1]", "localhost")
    else:
        raise ValueError("listener is not on a loopback address")
    if type(port) is not int or not 1 <= port <= 65_535:
        raise ValueError("invalid port")
    hosts = {f"{name}:{port}" for name in names}
    if port == 80:
        # A browser leaves the default port out of Host and Origin.
        hosts.update(names)
    return LoopbackOrigin(
        frozenset(hosts), frozenset("http://" + host for host in hosts)
    )


class LoopbackGuard:
    """Refuse requests whose Host does not name this runtime.

    A page on another site can make a browser send requests to a loopback
    port; when its own name resolves to 127.0.0.1, only the Host header still
    shows that the request was not meant for this runtime. Refused WebSocket
    handshakes close with 1008 before the application sees them.
    """

    def __init__(self, app: ASGIApp, *, origin: LoopbackOrigin) -> None:
        if type(origin) is not LoopbackOrigin:
            raise ValueError("invalid loopback origin")
        self.app = app
        self.origin = origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        if Headers(scope=scope).get("host") not in self.origin.hosts:
            if scope["type"] == "http":
                refused = JSONResponse(
                    {"code": "HOST_NOT_ALLOWED"},
                    status_code=400,
                    headers=_RESPONSE_HEADERS,
                )
                await refused(scope, receive, send)
            else:
                await WebSocketClose(code=1008)(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _RESPONSE_HEADERS.items():
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)
