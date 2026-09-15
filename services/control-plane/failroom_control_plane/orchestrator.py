"""Durable state-to-runtime orchestration for trusted control-plane callers."""

import hashlib
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.docker_lifecycle import (
    ContainerObservation,
    CreatedContainer,
)
from failroom_sandbox.docker_profile import DockerBinding
from failroom_state import (
    BackendStore,
    Clock,
    ControlPlaneStore,
    Receipt,
    Resource,
    ResourceRef,
    ResourceState,
    ServiceIdentity,
    StoreError,
)


class LifecycleError(RuntimeError):
    """A fixed orchestration failure safe for service boundaries."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProvisioningRequest:
    receipt: Receipt
    backend_identity: ServiceIdentity
    control_identity: ServiceIdentity
    key: str


class ProvisioningSession(Protocol):
    def create_verified(self) -> CreatedContainer: ...

    def start_verified(self, created: CreatedContainer) -> ContainerObservation: ...


class ProvisioningRuntime(Protocol):
    def open(
        self, binding: DockerBinding, runtime_operation_id: str
    ) -> AbstractContextManager[ProvisioningSession]: ...


def phase_key(root_key: str, phase: str, ref: ResourceRef, version: int) -> str:
    """Derive an idempotent, bounded key for one lifecycle phase."""
    if type(root_key) is not str or type(phase) is not str or type(version) is not int:
        raise LifecycleError("INVALID_REQUEST")
    payload = (
        f"{root_key}:{phase}:{ref.attempt_id}:{ref.sandbox_id}:"
        f"{ref.generation}:{version}"
    )
    try:
        digest = hashlib.sha256(payload.encode("ascii")).hexdigest()
    except (UnicodeEncodeError, AttributeError):
        raise LifecycleError("INVALID_REQUEST") from None
    return "control-plane:" + digest


class LifecycleOrchestrator:
    """Order durable state transitions before every Docker side effect."""

    def __init__(
        self,
        backend: BackendStore,
        control: ControlPlaneStore,
        runtime: ProvisioningRuntime,
    ) -> None:
        self._backend = backend
        self._control = control
        self._runtime = runtime

    def provision(
        self,
        receipt: Receipt,
        *,
        backend_identity: ServiceIdentity,
        control_identity: ServiceIdentity,
        key: str,
        now: Clock,
    ) -> None:
        if type(receipt) is not Receipt or receipt.state not in (
            "PROVISIONING",
            "RESETTING",
        ):
            raise LifecycleError("INVALID_REQUEST")
        try:
            accepted = self._control.accept(
                backend_identity,
                receipt.ref,
                key=phase_key(key, "accept", receipt.ref, receipt.version),
                now=now,
            )
            current = self._control.inspect(control_identity, receipt.ref)
            if current.state == ResourceState.READY:
                self._publish_ready(receipt, backend_identity, key, now)
                return
            self._require_runtime_binding(current)
            if current.state != ResourceState.REQUESTED:
                raise StoreError("INVALID_TRANSITION")

            creating = self._control.transition(
                control_identity,
                receipt.ref,
                expected_version=accepted.version,
                state=ResourceState.CREATING,
                key=phase_key(key, "creating", receipt.ref, accepted.version),
                now=now,
            )
            current = self._control.inspect(control_identity, receipt.ref)
            if current.version != creating.version:
                raise StoreError("STALE_BINDING")
            self._run_runtime(
                current, receipt, backend_identity, control_identity, key, now
            )
        except LifecycleError:
            raise
        except StoreError as error:
            raise LifecycleError(error.code) from None

    def _run_runtime(
        self,
        current: Resource,
        receipt: Receipt,
        backend_identity: ServiceIdentity,
        control_identity: ServiceIdentity,
        key: str,
        now: Clock,
    ) -> None:
        binding = DockerBinding(
            current.ref.attempt_id,
            current.ref.sandbox_id,
            current.ref.generation,
        )
        try:
            with self._runtime.open(
                binding, current.runtime_operation_id or ""
            ) as session:
                try:
                    created = session.create_verified()
                    if type(created) is not CreatedContainer:
                        raise DockerError("INVALID_DOCKER_RESPONSE")
                except DockerError as error:
                    self._fail(
                        current,
                        control_identity,
                        backend_identity,
                        receipt,
                        key,
                        now,
                        error,
                        phase="create",
                    )
                    raise LifecycleError(self._failure_code(error, "create")) from None

                starting = self._control.transition(
                    control_identity,
                    current.ref,
                    expected_version=current.version,
                    state=ResourceState.STARTING,
                    key=phase_key(key, "starting", current.ref, current.version),
                    now=now,
                    container_id=created.container_id,
                )
                current = self._control.inspect(control_identity, current.ref)
                if current.version != starting.version:
                    raise StoreError("STALE_BINDING")
                try:
                    observation = session.start_verified(created)
                    if type(observation) is not ContainerObservation:
                        raise DockerError("INVALID_DOCKER_RESPONSE")
                except DockerError as error:
                    self._fail(
                        current,
                        control_identity,
                        backend_identity,
                        receipt,
                        key,
                        now,
                        error,
                        phase="start",
                    )
                    raise LifecycleError(self._failure_code(error, "start")) from None
        except LifecycleError:
            raise
        except DockerError as error:
            self._fail(
                current,
                control_identity,
                backend_identity,
                receipt,
                key,
                now,
                error,
                phase="create",
            )
            raise LifecycleError(self._failure_code(error, "create")) from None

        ready = self._control.transition(
            control_identity,
            current.ref,
            expected_version=current.version,
            state=ResourceState.READY,
            key=phase_key(key, "ready", current.ref, current.version),
            now=now,
            evidence_digest=observation.evidence_digest,
        )
        current = self._control.inspect(control_identity, current.ref)
        if current.version != ready.version:
            raise StoreError("STALE_BINDING")
        self._publish_ready(receipt, backend_identity, key, now)

    def _publish_ready(
        self,
        receipt: Receipt,
        backend_identity: ServiceIdentity,
        key: str,
        now: Clock,
    ) -> None:
        publish = (
            self._backend.publish_ready
            if receipt.state == "PROVISIONING"
            else self._backend.publish_reset_ready
        )
        publish(
            backend_identity,
            receipt.ref,
            expected_version=receipt.version,
            key=phase_key(key, "publish", receipt.ref, receipt.version),
            now=now,
        )

    @staticmethod
    @staticmethod
    def _require_runtime_binding(resource: Resource) -> None:
        if resource.runtime_operation_id is None:
            raise LifecycleError("LEGACY_RUNTIME_BINDING")

    @staticmethod
    def _failure_code(error: DockerError, phase: str) -> str:
        if error.code == "RUNTIME_UNAVAILABLE":
            return error.code
        return "CREATE_FAILED" if phase == "create" else "START_FAILED"

    def _fail(
        self,
        resource: Resource,
        control_identity: ServiceIdentity,
        backend_identity: ServiceIdentity,
        receipt: Receipt,
        root_key: str,
        now: Clock,
        error: DockerError,
        *,
        phase: str,
    ) -> None:
        self._control.transition(
            control_identity,
            resource.ref,
            expected_version=resource.version,
            state=ResourceState.FAILED,
            key=phase_key(root_key, phase + "-failed", resource.ref, resource.version),
            now=now,
            error_code=self._failure_code(error, phase),
        )
        if receipt.state == "RESETTING":
            self._backend.fail_reset(
                backend_identity,
                receipt.ref,
                expected_version=receipt.version,
                key=phase_key(root_key, "reset-failed", receipt.ref, receipt.version),
                now=now,
            )
