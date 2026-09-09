"""Injected FastAPI authority boundary for terminal capability issuance."""

from collections.abc import Callable
from datetime import datetime

from failroom_api import (
    AuthenticationError,
    AuthorityError,
    BackendCapabilityAuthority,
    IdentityVerifier,
)
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .terminal import ControlPlaneTerminalService
from .websocket import (
    TerminalGatewayProtocol,
    WebSocketLimits,
    mount_terminal_route,
)

_AUTHORITY_STATUS = {
    "ATTEMPT_UNAVAILABLE": 409,
    "NOT_AUTHORIZED": 403,
    "INVALID_REQUEST": 400,
    "CAPABILITY_LIFETIME": 422,
}


def _error(code: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"code": code})


def create_app(
    *,
    authority: BackendCapabilityAuthority,
    verifier: IdentityVerifier,
    now: Callable[[], datetime],
    gateway: TerminalGatewayProtocol | None = None,
    terminal: ControlPlaneTerminalService | None = None,
    terminal_limits: WebSocketLimits | None = None,
) -> FastAPI:
    """Build an API app with all trust dependencies supplied by the caller."""

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/attempts/{attempt_id}/terminal-capability")
    def issue_terminal_capability(attempt_id: str, request: Request) -> JSONResponse:
        try:
            identity = verifier.verify(request.headers.get("authorization", ""))
        except AuthenticationError as error:
            return _error(error.code, 401)
        except Exception:
            return _error("AUTHENTICATION_REQUIRED", 401)
        try:
            issued = authority.issue(identity, attempt_id, now=now)
        except AuthorityError as error:
            status = _AUTHORITY_STATUS.get(error.code, 403)
            code = error.code if status != 403 else "AUTHORIZATION_FAILED"
            return _error(code, status)
        except Exception:
            return _error("AUTHORIZATION_FAILED", 500)
        return JSONResponse(
            status_code=200,
            content={
                "capability": issued.token,
                "expires_at": issued.expires_at.isoformat(),
            },
        )

    if any(value is not None for value in (gateway, terminal, terminal_limits)):
        if gateway is None or terminal is None or terminal_limits is None:
            raise ValueError("terminal dependencies must be configured together")
        mount_terminal_route(
            app,
            gateway=gateway,
            terminal=terminal,
            limits=terminal_limits,
            now=now,
        )

    return app
