"""The built browser interface, served from the runtime's own origin."""

import os
from pathlib import Path

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse, Response
from starlette.staticfiles import StaticFiles
from starlette.types import Message, Receive, Scope, Send
from starlette.websockets import WebSocketClose

# Pages run only this origin's scripts. xterm.js draws the terminal with
# <style> elements it writes at run time, so those alone may be inline.
PAGE_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "style-src-elem 'self' 'unsafe-inline'",
        "connect-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    )
)
_API_PREFIX = "/v1"
# Fixed so that the host's MIME registry cannot change how a browser treats a
# file it may not sniff.
_MEDIA_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".txt": "text/plain; charset=utf-8",
    ".woff2": "font/woff2",
}


class _ExportFiles(StaticFiles):
    def file_response(
        self,
        full_path: str | os.PathLike[str],
        stat_result: os.stat_result,
        scope: Scope,
        status_code: int = 200,
    ) -> Response:
        response = super().file_response(full_path, stat_result, scope, status_code)
        media_type = _MEDIA_TYPES.get(Path(full_path).suffix.lower())
        if media_type is not None and response.status_code != 304:
            response.headers["content-type"] = media_type
        return response


class WebInterface:
    """Serve a static export, mounted at the root, under the page policy.

    Paths under /v1 belong to the API: an unknown one gets the API's JSON 404,
    never a page. Only files inside the export are served.
    """

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise ValueError("invalid web root")
        self._files = _ExportFiles(directory=root, html=True)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await WebSocketClose()(scope, receive, send)
            return
        path = scope["path"]
        if path == _API_PREFIX or path.startswith(_API_PREFIX + "/"):
            await JSONResponse({"detail": "Not Found"}, status_code=404)(
                scope, receive, send
            )
            return

        async def send_with_policy(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["content-security-policy"] = PAGE_POLICY
            await send(message)

        await self._files(scope, receive, send_with_policy)
