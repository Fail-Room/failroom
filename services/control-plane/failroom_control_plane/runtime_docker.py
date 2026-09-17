"""Trusted adapters between the control plane and the bounded Docker runtime."""

from collections.abc import Iterator
from contextlib import contextmanager

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.docker_lifecycle import (
    ContainerObservation,
    CreatedContainer,
    DockerDiagnosticLifecycle,
    PreparedDockerOperation,
)
from failroom_sandbox.docker_profile import DockerBinding, StrictDockerProfile
from failroom_sandbox.fingerprints import configuration_digest
from failroom_sandbox.scenario import DiskFullScenario
from failroom_sandbox.scenario_runtime import ScenarioObservation
from failroom_state import CleanupTarget, RuntimeCleanupError

from .room_scenarios import RoomScenarioRegistry

__all__ = ("DockerCleanupRuntime", "DockerProvisioningRuntime")


class _DiskFullProvisioningSession:
    """Add the trusted Disk Full bootstrap without widening generic sessions."""

    def __init__(
        self, operation: PreparedDockerOperation, scenario: DiskFullScenario
    ) -> None:
        self._operation = operation
        self._scenario = scenario

    def create_verified(self) -> CreatedContainer:
        return self._operation.create_verified()

    def start_verified(self, created: CreatedContainer) -> ContainerObservation:
        return self._operation.start_verified(created)

    def bootstrap_disk_full(
        self, created: CreatedContainer, started: ContainerObservation
    ) -> ContainerObservation:
        if (
            type(created) is not CreatedContainer
            or type(started) is not ContainerObservation
            or started.container_id != created.container_id
            or started.running is not True
        ):
            raise DockerError("INVALID_DOCKER_REQUEST")
        bootstrap = self._operation.bootstrap_disk_full(created, self._scenario)
        if type(bootstrap) is not ScenarioObservation:
            raise DockerError("INVALID_DOCKER_RESPONSE")
        return ContainerObservation(
            created.container_id,
            True,
            configuration_digest(
                {
                    "schema": "failroom.diagnostic-ready.v1",
                    "running": started.evidence_digest,
                    "disk_full_bootstrap": bootstrap.evidence_digest,
                }
            ),
        )


class DockerProvisioningRuntime:
    """Expose the verified create/start session to the lifecycle orchestrator."""

    def __init__(
        self,
        lifecycle: DockerDiagnosticLifecycle,
        profile: StrictDockerProfile,
    ) -> None:
        self._lifecycle = lifecycle
        self._profile = profile
        self._room_scenarios = RoomScenarioRegistry()

    @contextmanager
    def open(
        self, binding: DockerBinding, runtime_operation_id: str, room_id: str
    ) -> Iterator[PreparedDockerOperation | _DiskFullProvisioningSession]:
        scenario = self._room_scenarios.resolve(
            room_id, workspace_bytes=self._profile.workspace_tmpfs_bytes
        )
        with self._lifecycle.prepare(
            self._profile, binding, runtime_operation_id
        ) as operation:
            if scenario is None:
                yield operation
            else:
                yield _DiskFullProvisioningSession(operation, scenario)


class DockerCleanupRuntime:
    """Convert persisted cleanup targets into safe Docker lifecycle requests."""

    def __init__(self, lifecycle: DockerDiagnosticLifecycle) -> None:
        self._lifecycle = lifecycle

    def destroy_and_verify_absent(self, target: CleanupTarget) -> str:
        try:
            return self._lifecycle.destroy(
                DockerBinding(
                    target.ref.attempt_id,
                    target.ref.sandbox_id,
                    target.ref.generation,
                ),
                target.container_id,
                operation_id=target.runtime_operation_id,
            )
        except DockerError as error:
            code = (
                "RUNTIME_UNAVAILABLE"
                if error.code == "RUNTIME_UNAVAILABLE"
                else "CLEANUP_INCOMPLETE"
            )
            raise RuntimeCleanupError(code) from None
        except Exception:
            raise RuntimeCleanupError("CLEANUP_INCOMPLETE") from None
