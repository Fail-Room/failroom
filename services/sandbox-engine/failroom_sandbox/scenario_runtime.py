"""Trusted fixed-argv bootstrap for the bounded Disk Full scenario."""

from collections.abc import Callable
from dataclasses import dataclass

from .docker_cli import DockerCli, DockerError
from .docker_profile import DockerBinding, StrictDockerProfile
from .fingerprints import configuration_digest
from .scenario import DISK_FULL_FILLER_PATH, DiskFullScenario

__all__ = ("DiskFullBootstrapRuntime", "ScenarioObservation")


@dataclass(frozen=True)
class ScenarioObservation:
    """A digest-only record of a trusted scenario bootstrap."""

    evidence_digest: str


class DiskFullBootstrapRuntime:
    """Observe fixed Disk Full transitions between exact owned-container checks."""

    def __init__(
        self,
        cli: DockerCli,
        profile: StrictDockerProfile,
        binding: DockerBinding,
        operation_id: str,
        inspect_exact: Callable[[str], dict[str, object]],
    ) -> None:
        if (
            type(cli) is not DockerCli
            or type(profile) is not StrictDockerProfile
            or type(binding) is not DockerBinding
            or type(operation_id) is not str
            or not callable(inspect_exact)
        ):
            raise DockerError("INVALID_DOCKER_REQUEST")
        self._cli = cli
        self._profile = profile
        self._binding = binding
        self._operation_id = operation_id
        self._inspect_exact = inspect_exact

    def apply(
        self, container_id: str, scenario: DiskFullScenario
    ) -> ScenarioObservation:
        self._validate_scenario(scenario)
        self._require_running(container_id)
        self._cli.allocate_workspace_file(
            container_id,
            uid=self._profile.uid,
            gid=self._profile.gid,
            size_bytes=scenario.filler_bytes,
            path=scenario.filler_path,
        )
        self._require_running(container_id)
        return ScenarioObservation(
            configuration_digest(
                {
                    "schema": "failroom.disk-full-bootstrap.v1",
                    "binding": {
                        "attempt_id": self._binding.attempt_id,
                        "sandbox_id": self._binding.sandbox_id,
                        "generation": self._binding.generation,
                    },
                    "operation_id": self._operation_id,
                    "container_id": container_id,
                    "filler_path": scenario.filler_path,
                    "filler_bytes": scenario.filler_bytes,
                    "recovery_free_bytes": scenario.recovery_free_bytes,
                }
            )
        )

    def verify_recovery(
        self, container_id: str, scenario: DiskFullScenario
    ) -> ScenarioObservation:
        """Prove recovery from trusted fixed observations, never learner input."""

        self._validate_scenario(scenario)
        self._require_running(container_id)
        filler_absent = self._cli.disk_full_filler_absent(
            container_id,
            uid=self._profile.uid,
            gid=self._profile.gid,
        )
        available_bytes = self._cli.workspace_available_bytes(
            container_id,
            uid=self._profile.uid,
            gid=self._profile.gid,
        )
        self._require_running(container_id)
        if not filler_absent or available_bytes < scenario.recovery_free_bytes:
            raise DockerError("PROFILE_UNVERIFIED")
        return ScenarioObservation(
            configuration_digest(
                {
                    "schema": "failroom.disk-full-recovery.v1",
                    "binding": {
                        "attempt_id": self._binding.attempt_id,
                        "sandbox_id": self._binding.sandbox_id,
                        "generation": self._binding.generation,
                    },
                    "operation_id": self._operation_id,
                    "container_id": container_id,
                    "filler_path": scenario.filler_path,
                    "filler_absent": True,
                    "workspace_available_bytes": available_bytes,
                    "recovery_free_bytes": scenario.recovery_free_bytes,
                }
            )
        )

    def _validate_scenario(self, scenario: DiskFullScenario) -> None:
        if (
            type(scenario) is not DiskFullScenario
            or scenario.filler_path != DISK_FULL_FILLER_PATH
            or type(scenario.filler_bytes) is not int
            or type(scenario.recovery_free_bytes) is not int
            or not 0 < scenario.filler_bytes < self._profile.workspace_tmpfs_bytes
            or not 0
            < scenario.recovery_free_bytes
            < self._profile.workspace_tmpfs_bytes
            or scenario.filler_bytes + scenario.recovery_free_bytes
            < self._profile.workspace_tmpfs_bytes
        ):
            raise DockerError("INVALID_DOCKER_REQUEST")

    def _require_running(self, container_id: str) -> None:
        data = self._inspect_exact(container_id)
        state = data.get("State") if type(data) is dict else None
        if type(state) is not dict or state.get("Running") is not True:
            raise DockerError("PROFILE_UNVERIFIED")
