"""Report-only qualification collection on the trusted local controller.

One collection at a time holds the private workspace next to the operator
database, and it first removes whatever a crashed collection left behind. The
collector creates a sentinel, a probe and a short-lived lifetime sandbox
through the verified diagnostic lifecycle with the exact strict profile and
image, and enters one Room sandbox for the restart scenario. Only the sentinel
differs: its lifetime bound is the report validity instead of the attempt TTL,
because its container ID and start time are the daemon epoch the report is
bound to, and a caller may ask to keep it running after the collection. It runs the fixed
probe in the probe sandbox and judges the twelve container checks, runs the
terminal scenarios against the same sandbox, checks that PID 1 ends the
lifetime sandbox by its deadline, and judges how a restarted control plane
cleans up the abandoned Room sandbox. It keeps no report and gates nothing;
callers decide what to do with the report.
"""

import re
import shutil
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import uuid4

from failroom_sandbox.docker_cli import DockerError, EngineIdentity
from failroom_sandbox.docker_lifecycle import ContainerLifetime, ContainerObservation
from failroom_sandbox.docker_profile import (
    DockerBinding,
    ProfileConfigurationError,
    StrictDockerProfile,
    profile_fingerprint,
)
from failroom_sandbox.fingerprints import configuration_digest
from failroom_sandbox.models import (
    Check,
    CheckResult,
    Outcome,
    QualificationContext,
    QualificationDecision,
    QualificationReport,
    RuntimeIdentity,
)
from failroom_sandbox.qualification_probe import (
    Judgement,
    ProbeOutputError,
    judge_container_checks,
    parse_probe_output,
)
from failroom_state import CleanupRuntime

from .orchestrator import ProvisioningRuntime
from .qualification_restart import RestartCleanupError, RestartScenario
from .qualification_scenarios import (
    TERMINAL_CHECKS,
    TERMINAL_PREFIX,
    TerminalScenarios,
)
from .qualification_workspace import (
    WORKSPACE_FAILURES,
    CollectionWorkspace,
    WorkspaceError,
    workspace_id,
)
from .terminal import TerminalRuntime

Clock = Callable[[], datetime]

# Every collector sandbox's attempt label is this prefix and its workspace's
# ID, so a collection only ever sweeps sandboxes of the workspace it holds.
# Room attempts use UUIDs, so the label never names a learner attempt.
QUALIFICATION_ATTEMPT_PREFIX = "qualification-"
_PROBE_SECONDS = 60
_LIFETIME_SECONDS = 5
_LIFETIME_GRACE_SECONDS = 10
_START_MARGIN_SECONDS = 10
_STARTED_AT = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]{1,9})?Z"
)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


class QualificationError(RuntimeError):
    """A fixed collection failure without runtime details."""

    def __init__(self, code: str) -> None:
        if code not in {
            "CLEANUP_INCOMPLETE",
            "COLLECTION_IN_PROGRESS",
            "INVALID_CONFIGURATION",
            "RUNTIME_UNAVAILABLE",
        }:
            code = "RUNTIME_UNAVAILABLE"
        self.code = code
        super().__init__(code)


@runtime_checkable
class QualificationDocker(Protocol):
    def engine_identity(self) -> EngineIdentity: ...

    def run_qualification_probe(self, container_id: str) -> bytes: ...

    def list_sandbox_processes(self, container_id: str) -> bytes: ...

    def inspect_container(self, selector: str) -> dict[str, object] | None: ...

    def list_containers(self, filters: tuple[str, ...]) -> tuple[str, ...]: ...


@runtime_checkable
class QualificationLifecycle(Protocol):
    def create_diagnostic(
        self,
        profile: StrictDockerProfile,
        binding: DockerBinding,
        operation_id: str,
        *,
        lifetime: ContainerLifetime,
    ) -> ContainerObservation: ...

    def destroy(
        self,
        binding: DockerBinding,
        container_id: str | None,
        *,
        operation_id: str | None = None,
    ) -> str: ...


@dataclass(frozen=True)
class RetainedSentinel:
    """A sentinel kept running after its collection, owned by the caller."""

    binding: DockerBinding
    operation_id: str
    container_id: str


@dataclass(frozen=True)
class QualificationCollection:
    """One report and the fixed reason code behind each non-passing result."""

    report: QualificationReport
    reasons: Mapping[Check, str]
    sentinel: RetainedSentinel | None = None


@dataclass(frozen=True)
class _Started:
    binding: DockerBinding
    operation_id: str
    container_id: str
    deadline: datetime


def _object(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise QualificationError("RUNTIME_UNAVAILABLE")
    return value


def _docker_time(value: object) -> datetime | None:
    if type(value) is not str:
        return None
    match = _STARTED_AT.fullmatch(value)
    if match is None:
        return None
    fraction = (match.group(2) or ".0")[:7]
    return datetime.fromisoformat(match.group(1) + fraction + "+00:00")


def qualification_attempt(workspace: str) -> str:
    """The attempt label of every collector sandbox of one workspace."""
    return QUALIFICATION_ATTEMPT_PREFIX + workspace


def sentinel_epoch(container_id: str, data: object) -> str:
    """The daemon epoch of a running sentinel: its container ID and start time."""
    if type(data) is not dict:
        raise QualificationError("RUNTIME_UNAVAILABLE")
    state = _object(data.get("State"))
    started_at = state.get("StartedAt")
    if (
        state.get("Running") is not True
        or type(started_at) is not str
        or _docker_time(started_at) is None
    ):
        raise QualificationError("RUNTIME_UNAVAILABLE")
    return f"{container_id}@{started_at}"


def runtime_identity(
    engine: EngineIdentity,
    boot_id: str,
    daemon_epoch: str,
    io_device: str | None,
    profile: StrictDockerProfile,
) -> RuntimeIdentity:
    """Bind the engine, boot, daemon epoch and runtime configuration together."""
    return RuntimeIdentity(
        engine.engine_id,
        boot_id,
        daemon_epoch,
        configuration_digest(
            {
                "schema": "failroom.qualification-runtime.v1",
                "engine": dict(engine.configuration),
                "seccomp_digest": profile.seccomp_digest,
                "io_device": io_device,
            }
        ),
    )


def _evidence(context: QualificationContext, judgement: Judgement) -> str:
    runtime = context.runtime
    return configuration_digest(
        {
            "schema": "failroom.qualification-evidence.v1",
            "check": judgement.check.value,
            "outcome": judgement.outcome.value,
            "reason": judgement.reason,
            "facts": dict(judgement.facts),
            "context": {
                "engine_id": runtime.engine_id,
                "host_boot_id": runtime.host_boot_id,
                "daemon_epoch": runtime.daemon_epoch,
                "configuration_digest": runtime.configuration_digest,
                "image_digest": context.image_digest,
                "profile_digest": context.profile_digest,
            },
        }
    )


class QualificationCollector:
    """Collect one report; every sandbox it creates is destroyed before return.

    The one exception is a sentinel the caller asks to retain after a complete
    collection; the caller then owns it and must destroy it.
    """

    def __init__(
        self,
        docker: QualificationDocker,
        lifecycle: QualificationLifecycle,
        profile: StrictDockerProfile,
        *,
        max_age: timedelta,
        now: Clock,
        terminal: TerminalRuntime,
        provisioning: ProvisioningRuntime,
        cleanup: CleanupRuntime,
        workspace: CollectionWorkspace,
        busy_timeout_ms: int,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            not isinstance(docker, QualificationDocker)
            or not isinstance(lifecycle, QualificationLifecycle)
            or type(profile) is not StrictDockerProfile
            or type(max_age) is not timedelta
            or max_age < timedelta(seconds=60)
            or not callable(now)
            or not isinstance(terminal, TerminalRuntime)
            or not callable(getattr(provisioning, "open", None))
            or not callable(getattr(cleanup, "destroy_and_verify_absent", None))
            or not isinstance(workspace, CollectionWorkspace)
            or type(busy_timeout_ms) is not int
            or not 1 <= busy_timeout_ms <= 30_000
            or not callable(monotonic)
            or not callable(sleep)
        ):
            raise QualificationError("INVALID_CONFIGURATION")
        self._docker = docker
        self._lifecycle = lifecycle
        self._profile = profile
        self._max_age = max_age
        self._now = now
        self._monotonic = monotonic
        self._sleep = sleep
        self._workspace = workspace
        self._scenarios = TerminalScenarios(
            docker,
            terminal,
            profile,
            busy_timeout_ms=busy_timeout_ms,
            now=now,
            monotonic=monotonic,
            sleep=sleep,
        )
        self._restart = RestartScenario(
            docker,
            lifecycle,
            provisioning,
            cleanup,
            busy_timeout_ms=busy_timeout_ms,
            now=now,
            monotonic=monotonic,
            sleep=sleep,
        )

    def collect(
        self,
        *,
        retain_sentinel: bool = False,
        keep: frozenset[str] = frozenset(),
    ) -> QualificationCollection:
        """Collect one report; `keep` names sentinels the caller still uses."""
        try:
            with self._workspace.hold() as scratch:
                attempt = qualification_attempt(workspace_id(scratch))
                self._prepare(scratch, attempt, frozenset(keep))
                return self._collect(scratch, attempt, retain_sentinel=retain_sentinel)
        except QualificationError:
            raise
        except WorkspaceError as error:
            raise QualificationError(WORKSPACE_FAILURES[error.code]) from None
        except Exception:
            raise QualificationError("RUNTIME_UNAVAILABLE") from None

    def _prepare(self, scratch: Path, attempt: str, keep: frozenset[str]) -> None:
        """Remove what a collection that is gone left behind.

        Holding the workspace lock proves that no other collection is running,
        so every scratch directory, restart state and collector sandbox found
        now was left by one that crashed, except the sentinels the caller keeps.
        """
        try:
            for entry in scratch.iterdir():
                if (
                    entry.name.startswith(TERMINAL_PREFIX)
                    and not entry.is_symlink()
                    and entry.is_dir()
                ):
                    shutil.rmtree(entry)
            self._restart.recover(scratch)
        except (OSError, RestartCleanupError):
            raise QualificationError("CLEANUP_INCOMPLETE") from None
        self._sweep(attempt, keep)

    def _collect(
        self, scratch: Path, attempt: str, *, retain_sentinel: bool
    ) -> QualificationCollection:
        engine = self._docker.engine_identity()
        max_lifetime = self._profile.absolute_ttl_seconds - _START_MARGIN_SECONDS
        scenarios: dict[Check, Judgement] = {}
        scenario_times: dict[Check, datetime] = {}
        sentinel = self._start_sentinel(attempt)
        retained = False
        try:
            epoch = sentinel_epoch(sentinel.container_id, self._inspect(sentinel))
            # Started first so their deadlines run out while the probe works.
            lifetime_sandbox = self._start(
                attempt, "lifetime", min(_LIFETIME_SECONDS, max_lifetime)
            )
            try:
                restart = self._begin_restart(scratch)
                try:
                    probe = self._start(
                        attempt, "probe", min(_PROBE_SECONDS, max_lifetime)
                    )
                    try:
                        raw = self._docker.run_qualification_probe(probe.container_id)
                        observed_at = self._utc_now()
                        data = self._inspect(probe)
                        scenarios.update(
                            self._terminal_scenarios(probe.container_id, scratch)
                        )
                        scenario_times.update(dict.fromkeys(scenarios, self._utc_now()))
                    finally:
                        self._destroy(probe)
                    scenarios[Check.ABSOLUTE_TTL] = self._lifetime_check(
                        lifetime_sandbox
                    )
                    scenario_times[Check.ABSOLUTE_TTL] = self._utc_now()
                finally:
                    # Also on failure: the restart is what removes the Room sandbox.
                    scenarios[Check.RESTART_CLEANUP] = self._finish_restart(
                        scratch, restart
                    )
                    scenario_times[Check.RESTART_CLEANUP] = self._utc_now()
            finally:
                self._destroy(lifetime_sandbox)
            collection = self._assemble(
                engine, epoch, raw, data, observed_at, scenarios, scenario_times
            )
            if retain_sentinel:
                collection = replace(
                    collection,
                    sentinel=RetainedSentinel(
                        sentinel.binding, sentinel.operation_id, sentinel.container_id
                    ),
                )
                retained = True
            return collection
        finally:
            if not retained:
                self._destroy(sentinel)

    def _assemble(
        self,
        engine: EngineIdentity,
        epoch: str,
        raw: bytes,
        data: dict[str, object],
        observed_at: datetime,
        scenarios: dict[Check, Judgement],
        scenario_times: dict[Check, datetime],
    ) -> QualificationCollection:
        try:
            observation = parse_probe_output(raw)
        except ProbeOutputError:
            raise QualificationError("RUNTIME_UNAVAILABLE") from None
        boot_id = observation.boot_id
        image_digest = data.get("Image")
        if (
            boot_id is None
            or type(image_digest) is not str
            or _SHA256.fullmatch(image_digest) is None
        ):
            raise QualificationError("RUNTIME_UNAVAILABLE")
        context = QualificationContext(
            runtime_identity(
                engine, boot_id, epoch, observation.io_device, self._profile
            ),
            image_digest,
            profile_fingerprint(self._profile),
        )
        judgements = {
            judgement.check: judgement
            for judgement in judge_container_checks(
                observation,
                data,
                self._profile,
                lifetime_seconds=_lifetime(data),
            )
        }
        judgements.update(scenarios)
        for check in Check:
            if check not in judgements:
                judgements[check] = Judgement(
                    check, Outcome.UNVERIFIED, "NOT_COLLECTED", MappingProxyType({})
                )
        results = tuple(
            CheckResult(
                check,
                judgements[check].outcome,
                scenario_times.get(check, observed_at),
                _evidence(context, judgements[check]),
            )
            for check in Check
        )
        return QualificationCollection(
            QualificationReport(context, results),
            MappingProxyType(
                {
                    check: judgement.reason
                    for check, judgement in judgements.items()
                    if judgement.reason
                }
            ),
        )

    def _utc_now(self) -> datetime:
        current = self._now()
        if type(current) is not datetime or current.utcoffset() is None:
            raise QualificationError("RUNTIME_UNAVAILABLE")
        return current.astimezone(UTC)

    def _start_sentinel(self, attempt: str) -> _Started:
        # Only the sentinel lives as long as the report is valid; it keeps every
        # other strict-profile limit and never serves a learner.
        seconds = int(self._max_age.total_seconds())
        profile = replace(
            self._profile, absolute_ttl_seconds=seconds + _START_MARGIN_SECONDS
        )
        return self._start(attempt, "sentinel", seconds, profile=profile)

    def _start(
        self,
        attempt: str,
        role: str,
        seconds: int,
        *,
        profile: StrictDockerProfile | None = None,
    ) -> _Started:
        binding = DockerBinding(attempt, f"{role}-{uuid4().hex}", 1)
        operation_id = uuid4().hex
        deadline = self._utc_now() + timedelta(seconds=seconds + _START_MARGIN_SECONDS)
        observation = self._lifecycle.create_diagnostic(
            profile or self._profile,
            binding,
            operation_id,
            lifetime=ContainerLifetime(deadline, self._now),
        )
        return _Started(binding, operation_id, observation.container_id, deadline)

    def _terminal_scenarios(
        self, container_id: str, scratch: Path
    ) -> dict[Check, Judgement]:
        try:
            return self._scenarios.run(container_id, scratch)
        except Exception:
            return {
                check: Judgement(
                    check,
                    Outcome.UNVERIFIED,
                    "SCENARIO_UNAVAILABLE",
                    MappingProxyType({}),
                )
                for check in TERMINAL_CHECKS
            }

    def _begin_restart(self, scratch: Path) -> Judgement | None:
        try:
            return self._restart.begin(scratch)
        except Exception:
            return Judgement(
                Check.RESTART_CLEANUP,
                Outcome.UNVERIFIED,
                "SCENARIO_UNAVAILABLE",
                MappingProxyType({}),
            )

    def _finish_restart(self, scratch: Path, started: Judgement | None) -> Judgement:
        try:
            return self._restart.finish(scratch, started)
        except (OSError, RestartCleanupError):
            raise QualificationError("CLEANUP_INCOMPLETE") from None

    def _lifetime_check(self, started: _Started) -> Judgement:
        """PID 1 must stop the sandbox on its own no later than its deadline."""
        check = Check.ABSOLUTE_TTL
        try:
            data = self._inspect(started)
            lifetime = _lifetime(data)
            give_up = self._monotonic() + lifetime + _LIFETIME_GRACE_SECONDS
            state = _object(data.get("State"))
            while state.get("Running") is True and self._monotonic() < give_up:
                self._sleep(0.25)
                state = _object(self._inspect(started).get("State"))
        except QualificationError:
            return Judgement(
                check, Outcome.UNVERIFIED, "LIFETIME_UNREADABLE", MappingProxyType({})
            )
        exit_code = state.get("ExitCode")
        finished = _docker_time(state.get("FinishedAt"))
        facts: dict[str, object] = {
            "lifetime_seconds": lifetime,
            "exit_code": exit_code if type(exit_code) is int else None,
        }
        if state.get("Running") is not False:
            outcome, reason = Outcome.FAIL, "LIFETIME_NOT_ENFORCED"
        elif exit_code != 0 or finished is None:
            outcome, reason, facts = Outcome.UNVERIFIED, "UNEXPECTED_EXIT", {}
        elif finished > started.deadline:
            outcome, reason = Outcome.FAIL, "DEADLINE_EXCEEDED"
        else:
            outcome, reason = Outcome.PASS, ""
        return Judgement(check, outcome, reason, MappingProxyType(facts))

    def _inspect(self, started: _Started) -> dict[str, object]:
        data = self._docker.inspect_container(started.container_id)
        if data is None:
            raise QualificationError("RUNTIME_UNAVAILABLE")
        return data

    def _destroy(self, started: _Started) -> None:
        try:
            self._lifecycle.destroy(
                started.binding, started.container_id, operation_id=started.operation_id
            )
        except DockerError:
            raise QualificationError("CLEANUP_INCOMPLETE") from None

    def _sweep(self, attempt: str, keep: frozenset[str]) -> None:
        """Remove every sandbox a crashed collection of this workspace left.

        Only collections holding this workspace's lock create sandboxes with its
        attempt label, and the caller holds that lock, so none of them is in
        use apart from the sentinels it keeps. Sandboxes of other workspaces are
        never touched.
        """
        for container_id in self._docker.list_containers(
            (
                "label=failroom.kind=diagnostic",
                "label=failroom.attempt_id=" + attempt,
            )
        ):
            if container_id in keep:
                continue
            data = self._docker.inspect_container(container_id)
            if data is None:
                continue
            labels = _object(_object(data.get("Config")).get("Labels"))
            sandbox_id = labels.get("failroom.sandbox_id")
            generation = labels.get("failroom.generation")
            operation_id = labels.get("failroom.operation_id")
            try:
                if (
                    type(sandbox_id) is not str
                    or type(generation) is not str
                    or not generation.isdecimal()
                    or type(operation_id) is not str
                ):
                    raise ProfileConfigurationError("INVALID_DOCKER_BINDING")
                binding = DockerBinding(attempt, sandbox_id, int(generation))
                self._lifecycle.destroy(
                    binding, container_id, operation_id=operation_id
                )
            except (DockerError, ProfileConfigurationError):
                raise QualificationError("CLEANUP_INCOMPLETE") from None


def _lifetime(data: dict[str, object]) -> int:
    command = _object(data.get("Config")).get("Cmd")
    if (
        type(command) is not list
        or len(command) != 1
        or type(command[0]) is not str
        or not command[0].isdecimal()
    ):
        raise QualificationError("RUNTIME_UNAVAILABLE")
    return int(command[0])


def format_collection(
    collection: QualificationCollection, decision: QualificationDecision
) -> tuple[str, ...]:
    """Render one report as fixed operator lines without facts or secrets."""
    context = collection.report.context
    runtime = context.runtime
    lines = [
        "QUALIFICATION_CONTEXT"
        f" engine_id={runtime.engine_id}"
        f" host_boot_id={runtime.host_boot_id}"
        f" daemon_epoch={runtime.daemon_epoch}"
        f" configuration_digest={runtime.configuration_digest}"
        f" image_digest={context.image_digest}"
        f" profile_digest={context.profile_digest}"
    ]
    for result in collection.report.results:
        line = (
            f"CHECK {result.check.value} {result.outcome.value}"
            f" {result.observed_at.isoformat()} {result.evidence_digest}"
        )
        reason = collection.reasons.get(result.check)
        lines.append(line + (f" reason={reason}" if reason else ""))
    lines.append(format_decision(decision))
    return tuple(lines)


def format_decision(decision: QualificationDecision) -> str:
    """Render a decision as one fixed operator line."""
    if decision.allowed:
        return "QUALIFICATION_PASSED"
    return "QUALIFICATION_DENIED " + " ".join(
        denial.code.value + ":" + (denial.check.value if denial.check else "-")
        for denial in decision.denials
    )
