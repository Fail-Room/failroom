"""Bounded cleanup coordination; runtime absence verification is injected.

This module neither imports Docker nor turns a cleanup operation into a create
label. The trusted runtime must resolve original create labels independently and
verify absence of every resource owned by the exact reserved tuple, even when
container_id is unknown. A well-formed digest alone is not absence evidence.
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from .backend import BackendStore
from .common import digest, instant, positive, read_clock, request_hash, service
from .control_plane import ControlPlaneStore
from .models import (
    Action,
    CleanupTask,
    Clock,
    ResourceRef,
    ResourceState,
    Role,
    ServiceIdentity,
    StoreError,
)

_RUNTIME_FAILURES = frozenset({"RUNTIME_UNAVAILABLE", "CLEANUP_INCOMPLETE"})
_DEFERRED_STORE_ERRORS = frozenset(
    {
        "STORE_BUSY",
        "STORE_FAILURE",
        "STALE_BINDING",
        "STALE_VERSION",
        "INVALID_TRANSITION",
        "IDEMPOTENCY_CONFLICT",
        "CLEANUP_UNVERIFIED",
    }
)


@dataclass(frozen=True)
class CleanupTarget:
    ref: ResourceRef
    container_id: str | None
    runtime_operation_id: str | None
    operation_id: str


class RuntimeCleanupError(Exception):
    """Safe runtime failure reason; never accepts raw runtime output."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _RUNTIME_FAILURES:
            raise ValueError("INVALID_CLEANUP_ERROR")
        self.code = code
        super().__init__(code)


class CleanupRuntime(Protocol):
    def destroy_and_verify_absent(self, target: CleanupTarget) -> str:
        """Idempotently remove and verify all exact-tuple resources; return digest.

        operation_id identifies durable cleanup work, not the original create
        operation label. Implementations must bound runtime calls, validate exact
        labels, and establish absence of containers, processes, PTYs, volumes,
        networks and sessions before returning their canonical SHA-256 evidence.
        """
        ...


@dataclass(frozen=True)
class CleanupRun:
    """Successful destruction/finalization receipts and deferred operations.

    Destruction and finalization may count the same tuple. A scan that cannot
    acquire store state counts as one deferral. Counts are not exclusive leases
    or exactly-once runtime execution metrics.
    """

    destroyed: int
    deferred: int
    finalized: int


def _key(action: str, ref: ResourceRef, *values: object) -> str:
    return (
        "docker-cleanup:"
        + action
        + ":"
        + request_hash(
            action, [ref.attempt_id, ref.sandbox_id, ref.generation, *values]
        )
    )


def _defer_or_raise(error: StoreError) -> None:
    if error.code not in _DEFERRED_STORE_ERRORS:
        raise error


class DockerCleanupWorker:
    def __init__(
        self,
        control: ControlPlaneStore,
        backend: BackendStore,
        runtime: CleanupRuntime,
        *,
        retry_delay: timedelta,
    ) -> None:
        if type(retry_delay) is not timedelta or retry_delay <= timedelta(0):
            raise StoreError("INVALID_CONFIGURATION")
        self._control = control
        self._backend = backend
        self._runtime = runtime
        self._retry_delay = retry_delay

    def run_once(
        self,
        control_identity: ServiceIdentity,
        backend_identity: ServiceIdentity,
        *,
        now: Clock,
        limit: int,
    ) -> CleanupRun:
        """Visit at most limit pending finalizations and cleanup tasks in total.

        This is one synchronous pass, without a scheduler or an exclusive work
        claim. The caller must run further passes after interruptions or retries.
        """
        for action in (Action.RECONCILE, Action.INSPECT, Action.TRANSITION):
            service(control_identity, Role.CONTROL_PLANE, action)
        for action in (Action.RECONCILE, Action.PUBLISH):
            service(backend_identity, Role.BACKEND, action)
        positive(limit, maximum=1000)
        read_clock(now)

        destroyed = deferred = finalized = 0
        try:
            pending = self._backend.pending_finalizations(backend_identity, limit=limit)
        except StoreError as error:
            _defer_or_raise(error)
            return CleanupRun(0, 1, 0)
        for ref in pending:
            if self._finalize(backend_identity, ref, now):
                finalized += 1
            else:
                deferred += 1

        remaining = limit - len(pending)
        if remaining == 0:
            return CleanupRun(destroyed, deferred, finalized)
        try:
            tasks = self._control.reconcile(control_identity, now=now, limit=remaining)
        except StoreError as error:
            _defer_or_raise(error)
            return CleanupRun(destroyed, deferred + 1, finalized)

        for task in tasks:
            if not self._destroy(control_identity, task, now):
                deferred += 1
                continue
            destroyed += 1
            if self._finalize(backend_identity, task.ref, now):
                finalized += 1
            else:
                deferred += 1
        return CleanupRun(destroyed, deferred, finalized)

    def _finalize(
        self, identity: ServiceIdentity, ref: ResourceRef, now: Clock
    ) -> bool:
        try:
            self._backend.complete_cleanup(
                identity, ref, key=_key("finalize", ref), now=now
            )
            return True
        except StoreError as error:
            _defer_or_raise(error)
            return False

    def _destroy(
        self, identity: ServiceIdentity, task: CleanupTask, now: Clock
    ) -> bool:
        try:
            resource = self._control.inspect(identity, task.ref)
        except StoreError as error:
            _defer_or_raise(error)
            return False
        if (
            resource.ref != task.ref
            or resource.version != task.version
            or resource.state != ResourceState.STOPPING
            or not resource.destroy_intent
        ):
            return False

        failure: str | None = None
        evidence: str | None = None
        try:
            evidence = digest(
                self._runtime.destroy_and_verify_absent(
                    CleanupTarget(
                        task.ref,
                        resource.container_id,
                        resource.runtime_operation_id,
                        task.operation_id,
                    )
                )
            )
        except RuntimeCleanupError as error:
            # Recheck even a mutated exception so raw text cannot reach storage.
            failure = (
                error.code
                if type(error.code) is str and error.code in _RUNTIME_FAILURES
                else "CLEANUP_INCOMPLETE"
            )
        except Exception:
            failure = "CLEANUP_INCOMPLETE"

        # Store/CAS failures are outside the runtime exception boundary. They do
        # not establish a runtime failure and must not increment cleanup retries.
        if failure is not None:
            self._failed(identity, task, failure, now)
            return False
        try:
            self._control.transition(
                identity,
                task.ref,
                expected_version=task.version,
                state=ResourceState.DESTROYED,
                key=_key("destroy", task.ref, task.operation_id, task.version),
                now=now,
                evidence_digest=evidence,
            )
            return True
        except StoreError as error:
            _defer_or_raise(error)
            return False

    def _failed(
        self, identity: ServiceIdentity, task: CleanupTask, code: str, now: Clock
    ) -> None:
        try:
            retry_at = instant(read_clock(now)) + self._retry_delay
        except OverflowError:
            raise StoreError("INVALID_CONFIGURATION") from None
        try:
            self._control.cleanup_failed(
                identity,
                task.ref,
                operation_id=task.operation_id,
                expected_version=task.version,
                key=_key("failed", task.ref, task.operation_id, task.version),
                error_code=code,
                retry_at=retry_at,
                now=now,
            )
        except StoreError as error:
            if error.code == "INVALID_REQUEST" and instant(read_clock(now)) >= retry_at:
                # The store samples time after its writer lock. If waiting used
                # up the retry interval, keep pending work for the next pass.
                return
            _defer_or_raise(error)
