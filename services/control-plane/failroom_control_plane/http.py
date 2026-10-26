"""Injected FastAPI authority boundary for terminal capability issuance."""

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import cast

from failroom_api import (
    AuthenticationError,
    AuthorityError,
    BackendCapabilityAuthority,
    BrowserSessionAuthority,
    CredentialVerifier,
    IdentityVerifier,
)
from failroom_state import UserIdentity
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.types import Lifespan

from .browser import SESSION_COOKIE, LoopbackGuard, LoopbackOrigin
from .entry import EntryError, RoomEntry, RoomEntryService
from .lifecycle import LifecycleError, RoomLifecycleService, RoomStatus
from .recovery import RecoveryError, RecoveryVerificationService
from .reset import ResetError, RoomResetService
from .terminal import ControlPlaneTerminalService
from .web import WebInterface
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
_ENTRY_STATUS = {
    "NOT_AUTHORIZED": 403,
    "ROOM_UNAVAILABLE": 404,
}
_RECOVERY_STATUS = {
    "ATTEMPT_UNAVAILABLE": 409,
    "NOT_AUTHORIZED": 403,
    "INVALID_REQUEST": 400,
    "RECOVERY_NOT_VERIFIED": 409,
    "RECOVERY_UNAVAILABLE": 503,
}


_SAFE_METHODS = frozenset({"GET", "HEAD"})


class _AuthenticationFailure(RuntimeError):
    """Carry a verifier failure without coupling it to lifecycle errors."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code
            in {
                "AUTHENTICATION_REQUIRED",
                "AUTHENTICATION_EXPIRED",
                "ORIGIN_NOT_ALLOWED",
            }
            else "AUTHENTICATION_REQUIRED"
        )
        self.status = 403 if self.code == "ORIGIN_NOT_ALLOWED" else 401
        super().__init__(self.code)


def _error(code: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"code": code})


def _authenticated_identity(
    verifier: IdentityVerifier,
    sessions: BrowserSessionAuthority | None,
    origin: LoopbackOrigin,
    request: Request,
) -> UserIdentity:
    """Authenticate a bearer header, or else a browser session cookie.

    A browser sends the cookie on its own, so a request that changes state
    with it must also come from this runtime's origin.
    """
    authorization = request.headers.get("authorization")
    token = request.cookies.get(SESSION_COOKIE)
    try:
        if authorization is not None or sessions is None or token is None:
            return verifier.verify(authorization or "")
        if request.method not in _SAFE_METHODS and not origin.allows(
            request.headers.get("origin")
        ):
            raise _AuthenticationFailure("ORIGIN_NOT_ALLOWED")
        return sessions.verify(token)
    except _AuthenticationFailure:
        raise
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


def _entry_response(entry: RoomEntry) -> JSONResponse:
    return JSONResponse(
        status_code=201,
        content={
            "attempt_id": entry.attempt_id,
            "room_id": entry.room_id,
            "state": entry.state,
            "expires_at": entry.expires_at.isoformat(),
        },
    )


def _entry_error(error: EntryError) -> JSONResponse:
    status = _ENTRY_STATUS.get(error.code, 503)
    code = error.code if status != 403 else "AUTHORIZATION_FAILED"
    return _error(code, status)


def _lifecycle_error(error: LifecycleError) -> JSONResponse:
    if error.code in {"AUTHENTICATION_REQUIRED", "AUTHENTICATION_EXPIRED"}:
        return _error(error.code, 401)
    status = _LIFECYCLE_STATUS.get(error.code, 500)
    code = error.code if status != 403 else "AUTHORIZATION_FAILED"
    return _error(code, status)


def _reset_error(error: ResetError) -> JSONResponse:
    status = _LIFECYCLE_STATUS.get(error.code, 500)
    code = error.code if status != 403 else "AUTHORIZATION_FAILED"
    return _error(code, status)


def _recovery_error(error: RecoveryError) -> JSONResponse:
    status = _RECOVERY_STATUS.get(error.code, 503)
    code = error.code if status != 403 else "AUTHORIZATION_FAILED"
    return _error(code, status)


def create_app(
    *,
    authority: BackendCapabilityAuthority,
    verifier: IdentityVerifier,
    origin: LoopbackOrigin,
    now: Callable[[], datetime],
    sessions: BrowserSessionAuthority | None = None,
    gateway: TerminalGatewayProtocol | None = None,
    terminal: ControlPlaneTerminalService | None = None,
    terminal_limits: WebSocketLimits | None = None,
    lifecycle: RoomLifecycleService | None = None,
    entry: RoomEntryService | None = None,
    reset: RoomResetService | None = None,
    recovery: RecoveryVerificationService | None = None,
    lifespan: Lifespan[FastAPI] | None = None,
    web_root: Path | None = None,
) -> FastAPI:
    """Build an API app with all trust dependencies supplied by the caller.

    With a web root, the app also serves that static export at its root.
    """

    if type(origin) is not LoopbackOrigin:
        raise ValueError("invalid loopback origin")
    if sessions is not None and (
        type(sessions) is not BrowserSessionAuthority
        or not isinstance(verifier, CredentialVerifier)
    ):
        raise ValueError("browser sessions need a credential verifier")
    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(LoopbackGuard, origin=origin)

    def identity(request: Request) -> UserIdentity:
        return _authenticated_identity(verifier, sessions, origin, request)

    if sessions is not None:
        # Checked above; this only narrows the type for the routes below.
        credentials = cast(CredentialVerifier, verifier)

        @app.post("/v1/session")
        def open_session(request: Request) -> Response:
            # Only a page of this runtime may sign the browser in.
            if not origin.allows(request.headers.get("origin")):
                return _error("ORIGIN_NOT_ALLOWED", 403)
            try:
                credential = credentials.credential(
                    request.headers.get("authorization", "")
                )
                issued = sessions.open(
                    credential.identity, credential_expires_at=credential.expires_at
                )
            except AuthenticationError as error:
                code = (
                    error.code
                    if error.code == "AUTHENTICATION_EXPIRED"
                    else "AUTHENTICATION_REQUIRED"
                )
                return _error(code, 401)
            except Exception:
                return _error("AUTHENTICATION_REQUIRED", 401)
            response = JSONResponse(
                status_code=201, content={"expires_at": issued.expires_at.isoformat()}
            )
            response.set_cookie(
                SESSION_COOKIE,
                issued.token,
                max_age=issued.lifetime_seconds,
                path="/v1",
                httponly=True,
                samesite="strict",
            )
            return response

        @app.delete("/v1/session")
        def close_session(request: Request) -> Response:
            if not origin.allows(request.headers.get("origin")):
                return _error("ORIGIN_NOT_ALLOWED", 403)
            token = request.cookies.get(SESSION_COOKIE)
            if token is not None:
                sessions.close(token)
            response = Response(status_code=204)
            response.delete_cookie(
                SESSION_COOKIE, path="/v1", httponly=True, samesite="strict"
            )
            return response

    if entry is not None:

        @app.post("/v1/rooms/{room_id}/attempts")
        def enter_room(room_id: str, request: Request) -> JSONResponse:
            key = request.headers.get("idempotency-key", "")
            if not key:
                return _error("INVALID_REQUEST", 400)
            try:
                return _entry_response(entry.enter(identity(request), room_id, key=key))
            except _AuthenticationFailure as error:
                return _error(error.code, error.status)
            except EntryError as error:
                return _entry_error(error)
            except Exception:
                return _error("ENTRY_FAILED", 503)

    @app.post("/v1/attempts/{attempt_id}/terminal-capability")
    def issue_terminal_capability(attempt_id: str, request: Request) -> JSONResponse:
        try:
            caller = identity(request)
        except _AuthenticationFailure as error:
            return _error(error.code, error.status)
        try:
            issued = authority.issue(caller, attempt_id, now=now)
        except AuthorityError as error:
            status = _AUTHORITY_STATUS.get(error.code, 403)
            code = error.code if status != 403 else "AUTHORIZATION_FAILED"
            return _error(code, status)
        except Exception:
            return _error("AUTHORIZATION_FAILED", 500)
        content: dict[str, object] = {
            "capability": issued.token,
            "expires_at": issued.expires_at.isoformat(),
        }
        if terminal_limits is not None:
            # A frame beyond these bounds closes the terminal, so the browser
            # sizes its terminal and splits its input to fit them.
            content["terminal"] = {
                "rows": terminal_limits.max_rows,
                "columns": terminal_limits.max_columns,
                "input_bytes": terminal_limits.max_input_bytes,
                "frame_bytes": terminal_limits.max_frame_bytes,
            }
        return JSONResponse(status_code=200, content=content)

    if lifecycle is not None:

        @app.get("/v1/attempts/{attempt_id}/status")
        def room_status(attempt_id: str, request: Request) -> JSONResponse:
            try:
                return _status_response(lifecycle.status(identity(request), attempt_id))
            except _AuthenticationFailure as error:
                return _error(error.code, error.status)
            except LifecycleError as error:
                return _lifecycle_error(error)

        @app.post("/v1/attempts/{attempt_id}/leave")
        def leave_room(attempt_id: str, request: Request) -> JSONResponse:
            key = request.headers.get("idempotency-key", "")
            if not key:
                return _error("INVALID_REQUEST", 400)
            try:
                return _status_response(
                    lifecycle.leave(identity(request), attempt_id, key=key),
                    code=202,
                )
            except _AuthenticationFailure as error:
                return _error(error.code, error.status)
            except LifecycleError as error:
                return _lifecycle_error(error)

    if reset is not None:

        @app.post("/v1/attempts/{attempt_id}/reset")
        def reset_room(attempt_id: str, request: Request) -> JSONResponse:
            key = request.headers.get("idempotency-key", "")
            if not key:
                return _error("INVALID_REQUEST", 400)
            try:
                return _status_response(
                    reset.reset(identity(request), attempt_id, key=key),
                    code=202,
                )
            except _AuthenticationFailure as error:
                return _error(error.code, error.status)
            except ResetError as error:
                return _reset_error(error)

    if recovery is not None:

        @app.post("/v1/attempts/{attempt_id}/verify-recovery")
        def verify_recovery(attempt_id: str, request: Request) -> JSONResponse:
            key = request.headers.get("idempotency-key", "")
            if not key:
                return _error("INVALID_REQUEST", 400)
            try:
                return _status_response(
                    recovery.verify(identity(request), attempt_id, key=key)
                )
            except _AuthenticationFailure as error:
                return _error(error.code, error.status)
            except RecoveryError as error:
                return _recovery_error(error)

    if any(value is not None for value in (gateway, terminal, terminal_limits)):
        if gateway is None or terminal is None or terminal_limits is None:
            raise ValueError("terminal dependencies must be configured together")
        mount_terminal_route(
            app,
            gateway=gateway,
            terminal=terminal,
            limits=terminal_limits,
            now=now,
            origins=origin.origins,
        )

    if web_root is not None:
        # Mounted last, so every API route above matches first.
        app.mount("/", WebInterface(web_root))

    return app
