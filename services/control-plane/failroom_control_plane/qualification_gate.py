"""Admit Room allocation only while a current report qualifies the runtime.

`serve-local` holds the collector's workspace for its whole life, collects one
report before it serves, and keeps that collection's sentinel running: the
sentinel's container ID and start time are the daemon epoch the report is
bound to. Before every Room allocation the gate rebuilds the current context
from the engine, the sentinel and the image, and admits the allocation only
when the report matches it, passes every check and is younger than its
validity. A denial, or any failure to read the runtime, refuses the allocation
before any Docker call for it; nothing here stops cleanup.

A refresh collects a new report in the same workspace, keeping the current
sentinel out of the collector's sweep, then swaps report and sentinel at once
and removes the old sentinel. Allocation keeps using the current report while
a refresh runs, and a refresh that does not complete leaves it in place.
"""

import threading
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, runtime_checkable

from failroom_sandbox.docker_cli import DockerError, EngineIdentity
from failroom_sandbox.docker_lifecycle import ContainerLifetime
from failroom_sandbox.docker_profile import (
    DockerBinding,
    StrictDockerProfile,
    profile_fingerprint,
)
from failroom_sandbox.models import (
    Denial,
    DenialCode,
    QualificationContext,
    QualificationDecision,
)
from failroom_sandbox.qualification import evaluate_qualification
from failroom_sandbox.qualification_probe import parse_runtime_identity

from .orchestrator import ProvisioningRuntime, ProvisioningSession
from .qualification_collector import (
    QualificationCollection,
    QualificationError,
    RetainedSentinel,
    format_decision,
    runtime_identity,
    sentinel_epoch,
)
from .qualification_workspace import (
    WORKSPACE_FAILURES,
    CollectionWorkspace,
    WorkspaceError,
)

Clock = Callable[[], datetime]


@runtime_checkable
class GateDocker(Protocol):
    def engine_identity(self) -> EngineIdentity: ...

    def inspect_container(self, selector: str) -> dict[str, object] | None: ...

    def inspect_image(self, image: str) -> dict[str, object]: ...

    def read_runtime_identity(self, container_id: str) -> bytes: ...


@runtime_checkable
class SentinelDestroyer(Protocol):
    def destroy(
        self,
        binding: DockerBinding,
        container_id: str | None,
        *,
        operation_id: str | None = None,
    ) -> str: ...


@runtime_checkable
class RetainingCollector(Protocol):
    def collect(
        self,
        *,
        retain_sentinel: bool = False,
        keep: frozenset[str] = frozenset(),
    ) -> QualificationCollection: ...


CollectorFactory = Callable[[CollectionWorkspace], RetainingCollector]


class AllocationGate(Protocol):
    def require(self) -> None: ...


class HeldWorkspace:
    """A workspace whose exclusive lock the caller already holds."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @contextmanager
    def hold(self) -> Iterator[Path]:
        yield self._path


class QualificationGate:
    """Hold one report and its sentinel; admit allocation only while it qualifies."""

    def __init__(
        self,
        docker: GateDocker,
        lifecycle: SentinelDestroyer,
        profile: StrictDockerProfile,
        *,
        workspace: CollectionWorkspace,
        collector: CollectorFactory,
        max_age: timedelta,
        now: Clock,
    ) -> None:
        if (
            not isinstance(docker, GateDocker)
            or not isinstance(lifecycle, SentinelDestroyer)
            or type(profile) is not StrictDockerProfile
            or not isinstance(workspace, CollectionWorkspace)
            or not callable(collector)
            or type(max_age) is not timedelta
            or max_age < timedelta(seconds=60)
            or not callable(now)
        ):
            raise QualificationError("INVALID_CONFIGURATION")
        self._docker = docker
        self._lifecycle = lifecycle
        self._profile = profile
        self._workspace = workspace
        self._collector = collector
        self._max_age = max_age
        self._now = now
        self._held = ExitStack()
        self._scratch: Path | None = None
        self._state = threading.Lock()
        # One collection at a time; closing waits for a running one.
        self._refreshing = threading.Lock()
        self._closed = False
        self._collection: QualificationCollection | None = None

    def start(self) -> str:
        """Collect the first report; the same as a refresh."""
        return self.refresh()

    def refresh(self) -> str:
        """Hold the workspace, collect a report keeping its sentinel, swap it in.

        It never raises and returns one status line. Without a passing report
        every allocation is refused; when no new collection completes, the
        current report stays until it expires.
        """
        with self._refreshing:
            if self._closed:
                return "QUALIFICATION_UNAVAILABLE RUNTIME_UNAVAILABLE"
            try:
                if self._scratch is None:
                    self._scratch = self._held.enter_context(self._workspace.hold())
            except WorkspaceError as error:
                return "QUALIFICATION_UNAVAILABLE " + WORKSPACE_FAILURES[error.code]
            except Exception:
                return "QUALIFICATION_UNAVAILABLE RUNTIME_UNAVAILABLE"
            with self._state:
                current = self._collection
            keep: frozenset[str] = frozenset()
            if current is not None and current.sentinel is not None:
                keep = frozenset({current.sentinel.container_id})
            try:
                collection = self._collector(HeldWorkspace(self._scratch)).collect(
                    retain_sentinel=True, keep=keep
                )
            except QualificationError as error:
                return "QUALIFICATION_UNAVAILABLE " + error.code
            except Exception:
                return "QUALIFICATION_UNAVAILABLE RUNTIME_UNAVAILABLE"
            with self._state:
                self._collection = collection
            if current is not None:
                try:
                    self._retire(current)
                except Exception:
                    # No longer kept, so the next collection's sweep removes it.
                    pass
            return format_decision(self.decide())

    def refresh_due(self) -> bool:
        """Whether the report is missing, refused, or half as old as its validity."""
        with self._state:
            collection = self._collection
        if collection is None or not self.decide().allowed:
            return True
        oldest = min(result.observed_at for result in collection.report.results)
        return self._now().astimezone(UTC) - oldest >= self._max_age / 2

    def decide(self) -> QualificationDecision:
        """Judge the report against the runtime as it is now."""
        with self._state:
            collection = self._collection
        if collection is None or collection.sentinel is None:
            return QualificationDecision((Denial(DenialCode.REPORT_MISSING),))
        try:
            context = self._current_context(collection.sentinel)
        except Exception:
            return QualificationDecision((Denial(DenialCode.CONTEXT_INVALID),))
        return evaluate_qualification(
            context, collection.report, now=self._now(), max_age=self._max_age
        )

    def require(self) -> None:
        """Raise before any Docker call for a Room the report does not qualify."""
        if not self.decide().allowed:
            raise DockerError("PROFILE_UNVERIFIED")

    def close(self) -> None:
        """Wait for a running refresh, destroy the sentinel, release the workspace.

        Safe to repeat; no refresh runs afterwards.
        """
        with self._refreshing:
            self._closed = True
            with self._state:
                collection, self._collection = self._collection, None
            try:
                if collection is not None:
                    self._retire(collection)
            finally:
                self._scratch = None
                self._held.close()

    def _retire(self, collection: QualificationCollection) -> None:
        sentinel = collection.sentinel
        if sentinel is not None:
            self._lifecycle.destroy(
                sentinel.binding,
                sentinel.container_id,
                operation_id=sentinel.operation_id,
            )

    def _current_context(self, sentinel: RetainedSentinel) -> QualificationContext:
        engine = self._docker.engine_identity()
        epoch = sentinel_epoch(
            sentinel.container_id,
            self._docker.inspect_container(sentinel.container_id),
        )
        observed = parse_runtime_identity(
            self._docker.read_runtime_identity(sentinel.container_id)
        )
        image = self._docker.inspect_image(self._profile.image).get("Id")
        if type(image) is not str:
            raise QualificationError("RUNTIME_UNAVAILABLE")
        return QualificationContext(
            runtime_identity(
                engine, observed.boot_id, epoch, observed.io_device, self._profile
            ),
            image,
            profile_fingerprint(self._profile),
        )


class GatedProvisioningRuntime:
    """Ask the gate immediately before a Room sandbox is prepared."""

    def __init__(self, runtime: ProvisioningRuntime, gate: AllocationGate) -> None:
        self._runtime = runtime
        self._gate = gate

    def open(
        self,
        binding: DockerBinding,
        runtime_operation_id: str,
        room_id: str,
        *,
        lifetime: ContainerLifetime,
    ) -> AbstractContextManager[ProvisioningSession]:
        # A refusal raises DockerError, which the orchestrator records as a
        # failed creation before any Docker call is made for this Room.
        self._gate.require()
        return self._runtime.open(
            binding, runtime_operation_id, room_id, lifetime=lifetime
        )
