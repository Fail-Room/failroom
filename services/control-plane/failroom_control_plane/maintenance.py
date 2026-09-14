"""Bounded trusted maintenance for expiry, cleanup, and finalization."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from failroom_state import (
    Action,
    BackendStore,
    CleanupRun,
    Role,
    ServiceIdentity,
)

from .lifecycle import CleanupWorker

Clock = Callable[[], datetime]


class MaintenanceError(RuntimeError):
    """A fixed maintenance failure without runtime or store details."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in {"INVALID_CONFIGURATION", "MAINTENANCE_INCOMPLETE"}
            else "MAINTENANCE_INCOMPLETE"
        )
        super().__init__(self.code)


@dataclass(frozen=True)
class MaintenanceRun:
    """One bounded maintenance pass result."""

    expired: int
    cleanup: CleanupRun


class LifecycleMaintenanceService:
    """Persist expiry intent before one bounded cleanup/finalization pass."""

    def __init__(
        self,
        backend: BackendStore,
        cleanup: CleanupWorker,
        *,
        control_identity: ServiceIdentity,
        backend_identity: ServiceIdentity,
        limit: int,
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
            or not {Action.EXPIRE, Action.RECONCILE, Action.PUBLISH}.issubset(
                backend_identity.scopes
            )
            or type(limit) is not int
            or not 1 <= limit <= 1000
            or not callable(now)
        ):
            raise MaintenanceError("INVALID_CONFIGURATION")
        self._backend = backend
        self._cleanup = cleanup
        self._control_identity = control_identity
        self._backend_identity = backend_identity
        self._limit = limit
        self._now = now

    def run_once(self) -> MaintenanceRun:
        try:
            expired = self._backend.expire(
                self._backend_identity,
                now=self._now,
                limit=self._limit,
            )
            cleanup = self._cleanup.run_once(
                self._control_identity,
                self._backend_identity,
                now=self._now,
                limit=self._limit,
            )
            if type(cleanup) is not CleanupRun:
                raise TypeError
        except Exception:
            raise MaintenanceError("MAINTENANCE_INCOMPLETE") from None
        return MaintenanceRun(expired=len(expired), cleanup=cleanup)
