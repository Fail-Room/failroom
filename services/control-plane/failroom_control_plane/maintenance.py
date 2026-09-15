"""Bounded trusted maintenance for expiry, cleanup, and finalization."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from failroom_state import (
    Action,
    BackendStore,
    CleanupRun,
    Receipt,
    Role,
    ServiceIdentity,
)

from .lifecycle import CleanupWorker

Clock = Callable[[], datetime]


@runtime_checkable
class ResetProvisioner(Protocol):
    def provision(
        self,
        receipt: Receipt,
        *,
        backend_identity: ServiceIdentity,
        control_identity: ServiceIdentity,
        key: str,
        now: Clock,
    ) -> None: ...


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
        reset_provisioner: ResetProvisioner | None = None,
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
            or not (
                {Action.EXPIRE, Action.RECONCILE, Action.PUBLISH}
                | ({Action.CREATE} if reset_provisioner is not None else set())
            ).issubset(backend_identity.scopes)
            or type(limit) is not int
            or not 1 <= limit <= 1000
            or not callable(now)
            or (
                reset_provisioner is not None
                and not isinstance(reset_provisioner, ResetProvisioner)
            )
        ):
            raise MaintenanceError("INVALID_CONFIGURATION")
        self._backend = backend
        self._cleanup = cleanup
        self._control_identity = control_identity
        self._backend_identity = backend_identity
        self._limit = limit
        self._now = now
        self._reset_provisioner = reset_provisioner

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
            if self._reset_provisioner is not None:
                for receipt in self._backend.pending_reset_provisioning(
                    self._backend_identity,
                    limit=self._limit,
                ):
                    self._reset_provisioner.provision(
                        receipt,
                        backend_identity=self._backend_identity,
                        control_identity=self._control_identity,
                        key="reset-resume:" + receipt.operation_id,
                        now=self._now,
                    )
        except Exception:
            raise MaintenanceError("MAINTENANCE_INCOMPLETE") from None
        return MaintenanceRun(expired=len(expired), cleanup=cleanup)
