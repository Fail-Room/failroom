"""Injected FastAPI authority boundary for terminal capability issuance."""

from collections.abc import Callable
from datetime import datetime

from failroom_api import (
    AuthenticationError,
    AuthorityError,
    BackendCapabilityAuthority,
    IdentityVerifier,
)
from failroom_state import UserIdentity
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .lifecycle import LifecycleError, RoomLifecycleService, RoomStatus
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
_LIFECYCLE_STATUS = {
    "ATTEMPT_UNAVAILABLE": 409,
    "NOT_AUTHORIZED": 403,
    "INVALID_REQUEST": 400,
    "CLEANUP_PENDING": 202,
}


class _AuthenticationFailure(RuntimeError):
    """Carry a verifier failure without coupling it to lifecycle errors."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in {"AUTHENTICATION_REQUIRED", "AUTHENTICATION_EXPIRED"}
            else "AUTHENTICATION_REQUIRED"
        )
        super().__init__(self.code)


def _error(code: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"code": code})


def _authenticated_identity(
    verifier: IdentityVerifier, request: Request
) -> UserIdentity:
    try:
        return verifier.verify(request.headers.get("authorization", ""))
    except AuthenticationError as error:
        raise _AuthenticationFailure(error.code) from None
    except Exception:
        raise _AuthenticationFailure("AUTHENTICATION_REQUIRED") from None


def _status_response(status: RoomStatus, *, code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=code,
        content={
            "attempt_id": status.attempt_id,
            "room_id": status.room_id,
            "state": status.state,
            "expires_at": status.expires_at.isoformat(),
            "destroy_intent": status.destroy_intent,
        },
    )


def _lifecycle_error(error: LifecycleError) -> JSONResponse:
    if error.code in {"AUTHENTICATION_REQUIRED", "AUTHENTICATION_EXPIRED"}:
        return _error(error.code, 401)
    status = _LIFECYCLE_STATUS.get(error.code, 500)
    code = error.code if status != 403 else "AUTHORIZATION_FAILED"
    return _error(code, status)


def create_app(
    *,
    authority: BackendCapabilityAuthority,
    verifier: IdentityVerifier,
    now: Callable[[], datetime],
    gateway: TerminalGatewayProtocol | None = None,
    terminal: ControlPlaneTerminalService | None = None,
    terminal_limits: WebSocketLimits | None = None,
    lifecycle: RoomLifecycleService | None = None,
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

    if lifecycle is not None:

        @app.get("/v1/attempts/{attempt_id}/status")
        def room_status(attempt_id: str, request: Request) -> JSONResponse:
            try:
                return _status_response(
                    lifecycle.status(
                        _authenticated_identity(verifier, request), attempt_id
                    )
                )
            except _AuthenticationFailure as error:
                return _error(error.code, 401)
            except LifecycleError as error:
                return _lifecycle_error(error)

        @app.post("/v1/attempts/{attempt_id}/leave")
        def leave_room(attempt_id: str, request: Request) -> JSONResponse:
            key = request.headers.get("idempotency-key", "")
            if not key:
                return _error("INVALID_REQUEST", 400)
            try:
                return _status_response(
                    lifecycle.leave(
                        _authenticated_identity(verifier, request), attempt_id, key=key
                    ),
                    code=202,
                )
            except _AuthenticationFailure as error:
                return _error(error.code, 401)
            except LifecycleError as error:
                return _lifecycle_error(error)

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
