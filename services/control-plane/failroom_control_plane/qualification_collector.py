"""Report-only qualification collection on the trusted local controller.

The collector creates a sentinel and a probe sandbox through the verified
diagnostic lifecycle with the exact strict profile and image, runs the fixed
probe in the probe sandbox, and judges the twelve container checks. The six
scenario checks are reported UNVERIFIED until they are collected. It stores
nothing and gates nothing; callers decide what to do with the report.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
    CONTAINER_CHECKS,
    Judgement,
    ProbeOutputError,
    judge_container_checks,
    parse_probe_output,
)

Clock = Callable[[], datetime]

# Every collector-owned sandbox uses this attempt label; Room attempts use
# UUIDs, so the label never names a learner attempt.
QUALIFICATION_ATTEMPT = "qualification"
_PROBE_SECONDS = 60
_START_MARGIN_SECONDS = 10
_STALE_CREATED = timedelta(minutes=10)
_STARTED_AT = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]{1,9})?Z"
)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


class QualificationError(RuntimeError):
    """A fixed collection failure without runtime details."""

    def __init__(self, code: str) -> None:
        if code not in {
            "CLEANUP_INCOMPLETE",
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
class QualificationCollection:
    """One report and the fixed reason code behind each non-passing result."""

    report: QualificationReport
    reasons: Mapping[Check, str]


@dataclass(frozen=True)
class _Started:
    binding: DockerBinding
    operation_id: str
    container_id: str


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
    """Collect one report; every sandbox it creates is destroyed before return."""

    def __init__(
        self,
        docker: QualificationDocker,
        lifecycle: QualificationLifecycle,
        profile: StrictDockerProfile,
        *,
        max_age: timedelta,
        now: Clock,
    ) -> None:
        if (
            not isinstance(docker, QualificationDocker)
            or not isinstance(lifecycle, QualificationLifecycle)
            or type(profile) is not StrictDockerProfile
            or type(max_age) is not timedelta
            or max_age < timedelta(seconds=60)
            or not callable(now)
        ):
            raise QualificationError("INVALID_CONFIGURATION")
        self._docker = docker
        self._lifecycle = lifecycle
        self._profile = profile
        self._max_age = max_age
        self._now = now

    def collect(self) -> QualificationCollection:
        try:
            return self._collect()
        except QualificationError:
            raise
        except Exception:
            raise QualificationError("RUNTIME_UNAVAILABLE") from None

    def _collect(self) -> QualificationCollection:
        self._sweep()
        engine = self._docker.engine_identity()
        max_lifetime = self._profile.absolute_ttl_seconds - _START_MARGIN_SECONDS
        sentinel = self._start(
            "sentinel", min(int(self._max_age.total_seconds()), max_lifetime)
        )
        try:
            epoch = self._daemon_epoch(sentinel)
            probe = self._start("probe", min(_PROBE_SECONDS, max_lifetime))
            try:
                raw = self._docker.run_qualification_probe(probe.container_id)
                observed_at = self._utc_now()
                data = self._inspect(probe)
            finally:
                self._destroy(probe)
        finally:
            self._destroy(sentinel)
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
            RuntimeIdentity(
                engine.engine_id,
                boot_id,
                epoch,
                configuration_digest(
                    {
                        "schema": "failroom.qualification-runtime.v1",
                        "engine": dict(engine.configuration),
                        "seccomp_digest": self._profile.seccomp_digest,
                        "io_device": observation.io_device,
                    }
                ),
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
        for check in Check:
            if check not in CONTAINER_CHECKS:
                judgements[check] = Judgement(
                    check, Outcome.UNVERIFIED, "NOT_COLLECTED", MappingProxyType({})
                )
        results = tuple(
            CheckResult(
                check,
                judgements[check].outcome,
                observed_at,
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

    def _start(self, role: str, seconds: int) -> _Started:
        binding = DockerBinding(QUALIFICATION_ATTEMPT, f"{role}-{uuid4().hex}", 1)
        operation_id = uuid4().hex
        deadline = self._utc_now() + timedelta(seconds=seconds + _START_MARGIN_SECONDS)
        observation = self._lifecycle.create_diagnostic(
            self._profile,
            binding,
            operation_id,
            lifetime=ContainerLifetime(deadline, self._now),
        )
        return _Started(binding, operation_id, observation.container_id)

    def _inspect(self, started: _Started) -> dict[str, object]:
        data = self._docker.inspect_container(started.container_id)
        if data is None:
            raise QualificationError("RUNTIME_UNAVAILABLE")
        return data

    def _daemon_epoch(self, sentinel: _Started) -> str:
        state = _object(self._inspect(sentinel).get("State"))
        started_at = state.get("StartedAt")
        if state.get("Running") is not True or _docker_time(started_at) is None:
            raise QualificationError("RUNTIME_UNAVAILABLE")
        return f"{sentinel.container_id}@{started_at}"

    def _destroy(self, started: _Started) -> None:
        try:
            self._lifecycle.destroy(
                started.binding, started.container_id, operation_id=started.operation_id
            )
        except DockerError:
            raise QualificationError("CLEANUP_INCOMPLETE") from None

    def _sweep(self) -> None:
        """Remove stopped sandboxes a crashed collection left behind.

        Running ones may belong to a concurrent collection; their PID 1 lifetime
        bounds them and a later collection removes them once they stop.
        """
        for container_id in self._docker.list_containers(
            (
                "label=failroom.kind=diagnostic",
                "label=failroom.attempt_id=" + QUALIFICATION_ATTEMPT,
            )
        ):
            data = self._docker.inspect_container(container_id)
            if data is None:
                continue
            status = _object(data.get("State")).get("Status")
            created = _docker_time(data.get("Created"))
            if status not in ("exited", "dead", "created") or (
                status == "created"
                and (created is None or self._utc_now() - created < _STALE_CREATED)
            ):
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
                binding = DockerBinding(
                    QUALIFICATION_ATTEMPT, sandbox_id, int(generation)
                )
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
    if decision.allowed:
        lines.append("QUALIFICATION_PASSED")
    else:
        lines.append(
            "QUALIFICATION_DENIED "
            + " ".join(
                denial.code.value + ":" + (denial.check.value if denial.check else "-")
                for denial in decision.denials
            )
        )
    return tuple(lines)
