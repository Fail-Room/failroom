"""Trusted owner-scoped Room status and leave composition."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn, Protocol, runtime_checkable

from failroom_state import (
    Action,
    Attempt,
    BackendStore,
    CleanupRun,
    Role,
    ServiceIdentity,
    StoreError,
    UserIdentity,
)

Clock = Callable[[], datetime]


class LifecycleError(RuntimeError):
    """A fixed lifecycle failure without runtime or resource details."""

    def __init__(self, code: str) -> None:
        if code not in {
            "ATTEMPT_UNAVAILABLE",
            "NOT_AUTHORIZED",
            "INVALID_REQUEST",
            "CLEANUP_PENDING",
            "INVALID_CONFIGURATION",
        }:
            code = "ATTEMPT_UNAVAILABLE"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RoomStatus:
    """Learner-safe view of one owned Room attempt."""

    attempt_id: str
    room_id: str
    state: str
    expires_at: datetime
    destroy_intent: bool


@runtime_checkable
class CleanupWorker(Protocol):
    def run_once(
        self,
        control_identity: ServiceIdentity,
        backend_identity: ServiceIdentity,
        *,
        now: Clock,
        limit: int,
    ) -> CleanupRun: ...


def _status(attempt: Attempt) -> RoomStatus:
    return RoomStatus(
        attempt_id=attempt.attempt_id,
        room_id=attempt.room_id,
        state=attempt.state,
        expires_at=attempt.expires_at,
        destroy_intent=attempt.destroy_intent,
    )


def _raise_store_error(error: StoreError) -> NoReturn:
    if error.code in {"ATTEMPT_UNAVAILABLE", "NOT_AUTHORIZED", "INVALID_REQUEST"}:
        raise LifecycleError(error.code) from None
    raise LifecycleError("ATTEMPT_UNAVAILABLE") from None


class RoomLifecycleService:
    """Compose owned attempt views with one bounded durable cleanup pass."""

    def __init__(
        self,
        backend: BackendStore,
        cleanup: CleanupWorker,
        *,
        control_identity: ServiceIdentity,
        backend_identity: ServiceIdentity,
        cleanup_limit: int,
        now: Clock,
    ) -> None:
        if (
            type(backend) is not BackendStore
            or not isinstance(cleanup, CleanupWorker)
            or type(control_identity) is not ServiceIdentity
            or control_identity.role is not Role.CONTROL_PLANE
            or not {Action.RECONCILE, Action.INSPECT, Action.TRANSITION}.issubset(
                control_identity.scopes
            )
            or type(backend_identity) is not ServiceIdentity
            or backend_identity.role is not Role.BACKEND
            or not {Action.RECONCILE, Action.PUBLISH}.issubset(backend_identity.scopes)
            or type(cleanup_limit) is not int
            or not 1 <= cleanup_limit <= 1000
            or not callable(now)
        ):
            raise LifecycleError("INVALID_CONFIGURATION")
        self._backend = backend
        self._cleanup = cleanup
        self._control_identity = control_identity
        self._backend_identity = backend_identity
        self._cleanup_limit = cleanup_limit
        self._now = now

    def status(self, identity: UserIdentity, attempt_id: str) -> RoomStatus:
        try:
            return _status(self._backend.inspect(identity, attempt_id))
        except StoreError as error:
            _raise_store_error(error)

    def leave(self, identity: UserIdentity, attempt_id: str, *, key: str) -> RoomStatus:
        try:
            attempt = self._backend.inspect(identity, attempt_id)
            self._backend.leave(identity, attempt.ref, key=key, now=self._now)
        except StoreError as error:
            _raise_store_error(error)
        try:
            result = self._cleanup.run_once(
                self._control_identity,
                self._backend_identity,
                now=self._now,
                limit=self._cleanup_limit,
            )
            if type(result) is not CleanupRun:
                raise TypeError
        except Exception:
            raise LifecycleError("CLEANUP_PENDING") from None
        return self.status(identity, attempt_id)
