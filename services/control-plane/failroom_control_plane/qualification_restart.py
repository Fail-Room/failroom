"""Restart-cleanup evidence: a crashed control plane's sandbox is still removed.

The scenario enters the Disk Full Room through the real orchestrator into a
scratch SQLite store in the collector's workspace, with a deadline a few
seconds away. It persists the resource binding before any Docker call, checks
that the sandbox runs, and then drops every in-memory object, as a crash would.
Docker removes the sandbox itself once its PID 1 exits before the deadline.
After the deadline, fresh store, cleanup-worker and maintenance instances built
only from the persisted files run the same maintenance pass the local runtime
runs when it starts. The check passes only when the sandbox is then absent
from the Docker inventory and that pass records it destroyed. The same
recovery removes the state a crashed collection left behind before the next
collection starts.
"""

import json
import os
import re
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import uuid4

from failroom_sandbox.docker_profile import DockerBinding
from failroom_sandbox.models import Check, Outcome
from failroom_sandbox.qualification_probe import Judgement
from failroom_state import (
    Action,
    BackendStore,
    CleanupRuntime,
    ControlPlaneStore,
    Database,
    DockerCleanupWorker,
    ResourceRef,
    ResourceState,
    Role,
    ServiceIdentity,
    StoreError,
    UserIdentity,
)

from .maintenance import LifecycleMaintenanceService, MaintenanceError
from .orchestrator import LifecycleError, LifecycleOrchestrator, ProvisioningRuntime

Clock = Callable[[], datetime]

RESTART_DIRECTORY = "restart"
_DATABASE = "restart.sqlite3"
_BINDING = "binding.json"
_ROOM = "disk-full"
_USER = UserIdentity("qualification", frozenset({_ROOM}))
_BACKEND = ServiceIdentity(
    "qualification-restart-backend",
    Role.BACKEND,
    frozenset({Action.CREATE, Action.EXPIRE, Action.PUBLISH, Action.RECONCILE}),
)
_CONTROL = ServiceIdentity(
    "qualification-restart-control",
    Role.CONTROL_PLANE,
    frozenset({Action.INSPECT, Action.RECONCILE, Action.TRANSITION}),
)
# Long enough for PID 1 to outlive the Disk Full bootstrap after the
# lifecycle's start margin, short enough to keep a collection brief.
_DEADLINE_SECONDS = 20
_CLEANUP_SECONDS = 30.0
_POLL_SECONDS = 0.5
_PASS_LIMIT = 10
_RETRY_DELAY = timedelta(seconds=1)
_MAX_BINDING_BYTES = 512
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@runtime_checkable
class ContainerInventory(Protocol):
    def list_containers(self, filters: tuple[str, ...]) -> tuple[str, ...]: ...

    def inspect_container(self, selector: str) -> dict[str, object] | None: ...


@runtime_checkable
class SandboxDestroyer(Protocol):
    def destroy(
        self,
        binding: DockerBinding,
        container_id: str | None,
        *,
        operation_id: str | None = None,
    ) -> str: ...


class RestartCleanupError(RuntimeError):
    """The persisted sandbox was not shown absent; its state is kept."""


@dataclass(frozen=True)
class RestartRecovery:
    """What one restart from the persisted files did."""

    passes: int
    failed_passes: int
    absent_after_restart: bool
    attempt_state: str
    resource_state: str


def _unverified(reason: str) -> Judgement:
    return Judgement(
        Check.RESTART_CLEANUP, Outcome.UNVERIFIED, reason, MappingProxyType({})
    )


def _write_binding(directory: Path, ref: ResourceRef) -> None:
    payload = json.dumps(
        {
            "attempt_id": ref.attempt_id,
            "generation": ref.generation,
            "sandbox_id": ref.sandbox_id,
        },
        sort_keys=True,
    ).encode("ascii")
    temporary = directory / (_BINDING + ".tmp")
    with open(temporary, "xb") as file:
        file.write(payload)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, directory / _BINDING)
    if sys.platform == "linux":
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _read_binding(directory: Path) -> ResourceRef | None:
    try:
        raw = (directory / _BINDING).read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        raise RestartCleanupError() from None
    try:
        if len(raw) > _MAX_BINDING_BYTES:
            raise ValueError
        data = json.loads(raw)
        if (
            type(data) is not dict
            or set(data) != {"attempt_id", "generation", "sandbox_id"}
            or type(data["attempt_id"]) is not str
            or _UUID.fullmatch(data["attempt_id"]) is None
            or type(data["sandbox_id"]) is not str
            or _UUID.fullmatch(data["sandbox_id"]) is None
            or type(data["generation"]) is not int
            or not 1 <= data["generation"] <= 1_000_000
        ):
            raise ValueError
    except ValueError:
        raise RestartCleanupError() from None
    return ResourceRef(data["attempt_id"], data["sandbox_id"], data["generation"])


class RestartScenario:
    """Abandon one real Room sandbox, then restart and judge its cleanup."""

    def __init__(
        self,
        docker: ContainerInventory,
        lifecycle: SandboxDestroyer,
        provisioning: ProvisioningRuntime,
        cleanup: CleanupRuntime,
        *,
        busy_timeout_ms: int,
        now: Clock,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._docker = docker
        self._lifecycle = lifecycle
        self._provisioning = provisioning
        self._cleanup = cleanup
        self._busy_timeout_ms = busy_timeout_ms
        self._now = now
        self._monotonic = monotonic
        self._sleep = sleep

    def begin(self, workspace: Path) -> Judgement | None:
        """Enter the Room in a new scratch store, then abandon it.

        Returns None once a READY sandbox is running, or the UNVERIFIED result
        to report when none was provisioned. `finish` must follow either way.
        """
        directory = workspace / RESTART_DIRECTORY
        directory.mkdir(mode=0o700)
        database = Database(
            directory / _DATABASE, busy_timeout_ms=self._busy_timeout_ms
        )
        database.initialize()
        backend, control = BackendStore(database), ControlPlaneStore(database)
        receipt = backend.create(
            _USER,
            _ROOM,
            key=uuid4().hex,
            expires_at=self._utc_now() + timedelta(seconds=_DEADLINE_SECONDS),
            now=self._now,
        )
        # Persisted before any Docker call: from here on a crash always leaves
        # a binding the next collection can clean up.
        _write_binding(directory, receipt.ref)
        try:
            LifecycleOrchestrator(backend, control, self._provisioning).provision(
                receipt,
                backend_identity=_BACKEND,
                control_identity=_CONTROL,
                key=uuid4().hex,
                now=self._now,
            )
            resource = control.inspect(_CONTROL, receipt.ref)
        except (LifecycleError, StoreError):
            return _unverified("SANDBOX_NOT_PROVISIONED")
        if (
            resource.state != ResourceState.READY
            or resource.container_id is None
            or not self._running(resource.container_id)
        ):
            return _unverified("SANDBOX_NOT_PROVISIONED")
        # Every object above is dropped here; only the files and Docker remain.
        return None

    def finish(self, workspace: Path, started: Judgement | None) -> Judgement:
        """Restart from the persisted files and judge the cleanup it did."""
        recovery = self.recover(workspace)
        if started is not None:
            return started
        if recovery is None:
            return _unverified("SCENARIO_UNAVAILABLE")
        facts: dict[str, object] = {
            "passes": recovery.passes,
            "failed_passes": recovery.failed_passes,
            "attempt": recovery.attempt_state,
            "resource": recovery.resource_state,
        }
        if not recovery.absent_after_restart:
            failure = "CONTAINER_REMAINS"
        elif recovery.attempt_state != "DESTROYED" or (
            recovery.resource_state != ResourceState.DESTROYED
        ):
            failure = "CLEANUP_NOT_RECORDED"
        else:
            return Judgement(
                Check.RESTART_CLEANUP, Outcome.PASS, "", MappingProxyType(facts)
            )
        return Judgement(
            Check.RESTART_CLEANUP, Outcome.FAIL, failure, MappingProxyType(facts)
        )

    def recover(self, workspace: Path) -> RestartRecovery | None:
        """Clean up the persisted restart state as a restarted control plane would.

        Nothing from `begin` is reused: the store, cleanup worker and maintenance
        service are built from the persisted files. A sandbox the restart leaves
        behind is destroyed directly before the state is removed; the state is
        kept, and RestartCleanupError raised, while absence cannot be shown.
        """
        directory = workspace / RESTART_DIRECTORY
        if not os.path.lexists(directory):
            return None
        ref = _read_binding(directory)
        if ref is None:
            # No binding was persisted, so no Docker call was made for it.
            shutil.rmtree(directory)
            return None
        passes = failed = 0
        attempt_state = resource_state = "UNREADABLE"
        try:
            database = Database(
                directory / _DATABASE, busy_timeout_ms=self._busy_timeout_ms
            )
            backend, control = BackendStore(database), ControlPlaneStore(database)
            maintenance = LifecycleMaintenanceService(
                backend,
                DockerCleanupWorker(
                    control, backend, self._cleanup, retry_delay=_RETRY_DELAY
                ),
                control_identity=_CONTROL,
                backend_identity=_BACKEND,
                limit=_PASS_LIMIT,
                now=self._now,
            )
            self._await(backend.inspect(_USER, ref.attempt_id).expires_at)
            give_up = self._monotonic() + _CLEANUP_SECONDS
            while True:
                try:
                    maintenance.run_once()
                except MaintenanceError:
                    failed += 1
                passes += 1
                attempt_state, resource_state = self._states(backend, control, ref)
                if (
                    attempt_state == resource_state == ResourceState.DESTROYED
                    or self._monotonic() >= give_up
                ):
                    break
                self._sleep(_POLL_SECONDS)
        except (StoreError, MaintenanceError):
            # An unreadable store cannot restart; absence is still proven below.
            pass
        absent = not self._present(ref)
        if not absent:
            self._destroy(ref)
        shutil.rmtree(directory)
        return RestartRecovery(passes, failed, absent, attempt_state, resource_state)

    def _utc_now(self) -> datetime:
        return self._now().astimezone(UTC)

    def _await(self, deadline: datetime) -> None:
        # Expiry selects only attempts whose deadline has passed.
        give_up = self._monotonic() + _DEADLINE_SECONDS + _POLL_SECONDS
        while self._utc_now() < deadline and self._monotonic() < give_up:
            self._sleep(_POLL_SECONDS)

    def _states(
        self, backend: BackendStore, control: ControlPlaneStore, ref: ResourceRef
    ) -> tuple[str, str]:
        try:
            attempt = backend.inspect(_USER, ref.attempt_id).state
        except StoreError:
            attempt = "UNREADABLE"
        try:
            resource = str(control.inspect(_CONTROL, ref).state)
        except StoreError:
            resource = "UNREADABLE"
        return attempt, resource

    def _running(self, container_id: str) -> bool:
        data = self._docker.inspect_container(container_id)
        state = data.get("State") if data is not None else None
        return type(state) is dict and state.get("Running") is True

    def _present(self, ref: ResourceRef) -> bool:
        try:
            return bool(
                self._docker.list_containers(
                    (
                        "label=failroom.kind=diagnostic",
                        "label=failroom.attempt_id=" + ref.attempt_id,
                        "label=failroom.sandbox_id=" + ref.sandbox_id,
                        "label=failroom.generation=" + str(ref.generation),
                    )
                )
            )
        except Exception:
            raise RestartCleanupError() from None

    def _destroy(self, ref: ResourceRef) -> None:
        try:
            self._lifecycle.destroy(
                DockerBinding(ref.attempt_id, ref.sandbox_id, ref.generation), None
            )
        except Exception:
            raise RestartCleanupError() from None
        if self._present(ref):
            raise RestartCleanupError()
