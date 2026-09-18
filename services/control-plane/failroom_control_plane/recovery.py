"""Owner-scoped recovery requests backed by trusted runtime observations."""

import hashlib
from dataclasses import dataclass
from typing import NoReturn, Protocol, runtime_checkable

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.docker_profile import DockerBinding
from failroom_sandbox.fingerprints import configuration_digest
from failroom_sandbox.scenario_runtime import ScenarioObservation
from failroom_state import (
    Action,
    Attempt,
    BackendStore,
    Clock,
    ControlPlaneStore,
    Resource,
    ResourceState,
    Role,
    ServiceIdentity,
    StoreError,
    UserIdentity,
)

from .lifecycle import RoomStatus


class RecoveryError(RuntimeError):
    """A fixed recovery result that never exposes Docker runtime details."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code
            in {
                "ATTEMPT_UNAVAILABLE",
                "NOT_AUTHORIZED",
                "INVALID_REQUEST",
                "RECOVERY_NOT_VERIFIED",
                "RECOVERY_UNAVAILABLE",
            }
            else "RECOVERY_UNAVAILABLE"
        )
        super().__init__(self.code)


@runtime_checkable
class RecoveryRuntime(Protocol):
    def verify(
        self,
        binding: DockerBinding,
        runtime_operation_id: str,
        room_id: str,
        container_id: str,
    ) -> ScenarioObservation: ...


def _status(attempt: Attempt) -> RoomStatus:
    return RoomStatus(
        attempt_id=attempt.attempt_id,
        room_id=attempt.room_id,
        state=attempt.state,
        expires_at=attempt.expires_at,
        destroy_intent=attempt.destroy_intent,
    )


def _phase_key(root_key: str, phase: str, resource: Resource, version: int) -> str:
    if (
        type(root_key) is not str
        or type(phase) is not str
        or type(version) is not int
        or not root_key
    ):
        raise RecoveryError("INVALID_REQUEST")
    payload = (
        f"{root_key}:{phase}:{resource.ref.attempt_id}:{resource.ref.sandbox_id}:"
        f"{resource.ref.generation}:{version}"
    )
    try:
        value = payload.encode("ascii")
    except UnicodeEncodeError:
        raise RecoveryError("INVALID_REQUEST") from None
    return "control-plane:" + hashlib.sha256(value).hexdigest()


def _raise_store(error: StoreError) -> NoReturn:
    if error.code in {"NOT_AUTHORIZED", "INVALID_REQUEST"}:
        raise RecoveryError(error.code) from None
    raise RecoveryError("ATTEMPT_UNAVAILABLE") from None


@dataclass(frozen=True)
class _RecoveryContext:
    attempt: Attempt
    resource: Resource
    room_id: str


class RecoveryVerificationService:
    """Advance a Room only when its exact trusted runtime proves recovery."""

    def __init__(
        self,
        backend: BackendStore,
        control: ControlPlaneStore,
        runtime: RecoveryRuntime,
        *,
        backend_identity: ServiceIdentity,
        control_identity: ServiceIdentity,
        now: Clock,
    ) -> None:
        if (
            type(backend) is not BackendStore
            or type(control) is not ControlPlaneStore
            or not isinstance(runtime, RecoveryRuntime)
            or type(backend_identity) is not ServiceIdentity
            or backend_identity.role is not Role.BACKEND
            or not {Action.CREATE, Action.PUBLISH}.issubset(backend_identity.scopes)
            or type(control_identity) is not ServiceIdentity
            or control_identity.role is not Role.CONTROL_PLANE
            or not {Action.INSPECT, Action.TRANSITION}.issubset(
                control_identity.scopes
            )
            or not callable(now)
        ):
            raise RecoveryError("INVALID_REQUEST")
        self._backend = backend
        self._control = control
        self._runtime = runtime
        self._backend_identity = backend_identity
        self._control_identity = control_identity
        self._now = now

    def verify(self, identity: UserIdentity, attempt_id: str, *, key: str) -> RoomStatus:
        try:
            context = self._context(identity, attempt_id)
            attempt, resource = context.attempt, context.resource

            if attempt.state == "RESOLVED" and resource.state == "RESOLVED":
                return _status(attempt)
            if resource.state == ResourceState.READY:
                if attempt.state != "READY":
                    raise RecoveryError("ATTEMPT_UNAVAILABLE")
                running = self._control.transition(
                    self._control_identity,
                    resource.ref,
                    expected_version=resource.version,
                    state=ResourceState.RUNNING,
                    key=_phase_key(key, "running", resource, resource.version),
                    now=self._now,
                )
                resource = self._control.inspect(self._control_identity, resource.ref)
                if resource.version != running.version:
                    raise RecoveryError("ATTEMPT_UNAVAILABLE")

            if resource.state == ResourceState.RUNNING:
                if attempt.state == "READY":
                    running_attempt = self._backend.publish_running(
                        self._backend_identity,
                        resource.ref,
                        expected_version=attempt.version,
                        key=_phase_key(
                            key, "publish-running", resource, attempt.version
                        ),
                        now=self._now,
                    )
                    attempt = self._backend.inspect(identity, attempt_id)
                    if attempt.version != running_attempt.version:
                        raise RecoveryError("ATTEMPT_UNAVAILABLE")
                if attempt.state != "RUNNING":
                    raise RecoveryError("ATTEMPT_UNAVAILABLE")
                observation = self._verify_runtime(context.room_id, resource)
                resolved = self._control.transition(
                    self._control_identity,
                    resource.ref,
                    expected_version=resource.version,
                    state=ResourceState.RESOLVED,
                    key=_phase_key(key, "resolved", resource, resource.version),
                    now=self._now,
                    evidence_digest=_resolution_digest(resource, observation),
                )
                resource = self._control.inspect(self._control_identity, resource.ref)
                if resource.version != resolved.version:
                    raise RecoveryError("ATTEMPT_UNAVAILABLE")

            if resource.state == ResourceState.RESOLVED:
                if attempt.state == "RUNNING":
                    resolved_attempt = self._backend.publish_resolved(
                        self._backend_identity,
                        resource.ref,
                        expected_version=attempt.version,
                        key=_phase_key(
                            key, "publish-resolved", resource, attempt.version
                        ),
                        now=self._now,
                    )
                    attempt = self._backend.inspect(identity, attempt_id)
                    if attempt.version != resolved_attempt.version:
                        raise RecoveryError("ATTEMPT_UNAVAILABLE")
                if attempt.state == "RESOLVED":
                    return _status(attempt)
            raise RecoveryError("ATTEMPT_UNAVAILABLE")
        except RecoveryError:
            raise
        except StoreError as error:
            _raise_store(error)

    def _context(self, identity: UserIdentity, attempt_id: str) -> _RecoveryContext:
        attempt = self._backend.inspect(identity, attempt_id)
        ref = attempt.active_ref
        if ref is None:
            raise RecoveryError("ATTEMPT_UNAVAILABLE")
        room_id = self._backend.room_id_for_binding(self._backend_identity, ref)
        return _RecoveryContext(
            attempt,
            self._control.inspect(self._control_identity, ref),
            room_id,
        )

    def _verify_runtime(
        self, room_id: str, resource: Resource
    ) -> ScenarioObservation:
        if (
            type(resource.runtime_operation_id) is not str
            or type(resource.container_id) is not str
            or resource.evidence_digest is None
        ):
            raise RecoveryError("RECOVERY_NOT_VERIFIED")
        try:
            result = self._runtime.verify(
                DockerBinding(
                    resource.ref.attempt_id,
                    resource.ref.sandbox_id,
                    resource.ref.generation,
                ),
                resource.runtime_operation_id,
                room_id,
                resource.container_id,
            )
        except DockerError as error:
            code = (
                "RECOVERY_UNAVAILABLE"
                if error.code == "RUNTIME_UNAVAILABLE"
                else "RECOVERY_NOT_VERIFIED"
            )
            raise RecoveryError(code) from None
        except Exception:
            raise RecoveryError("RECOVERY_UNAVAILABLE") from None
        if type(result) is not ScenarioObservation:
            raise RecoveryError("RECOVERY_UNAVAILABLE")
        return result


def _resolution_digest(resource: Resource, observation: ScenarioObservation) -> str:
    if resource.evidence_digest is None:
        raise RecoveryError("RECOVERY_NOT_VERIFIED")
    return configuration_digest(
        {
            "schema": "failroom.disk-full-resolved.v1",
            "ready": resource.evidence_digest,
            "recovery": observation.evidence_digest,
        }
    )
