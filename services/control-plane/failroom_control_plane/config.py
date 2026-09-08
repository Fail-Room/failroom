"""Fail-closed configuration for trusted control-plane composition."""

import math
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from failroom_sandbox.docker_cli import DockerCli, DockerError
from failroom_sandbox.docker_profile import StrictDockerProfile
from failroom_sandbox.seccomp import SeccompError, SeccompPolicyStore


class ConfigurationError(ValueError):
    """A fixed configuration rejection without paths or provider details."""

    def __init__(self, code: str = "INVALID_CONFIGURATION") -> None:
        self.code = "INVALID_CONFIGURATION" if code != "INVALID_CONFIGURATION" else code
        super().__init__(self.code)


@dataclass(frozen=True)
class ControllerConfig:
    """All control-plane composition inputs are explicit and immutable."""

    database_path: Path
    docker_context: str
    docker_timeout_seconds: float
    docker_max_output_bytes: int
    seccomp_store: Path
    seccomp_max_bytes: int
    profile: StrictDockerProfile
    cleanup_retry_delay: timedelta

    def __post_init__(self) -> None:
        if (
            not isinstance(self.database_path, Path)
            or not self.database_path.is_absolute()
            or not isinstance(self.seccomp_store, Path)
            or not self.seccomp_store.is_absolute()
            or type(self.profile) is not StrictDockerProfile
            or type(self.cleanup_retry_delay) is not timedelta
            or self.cleanup_retry_delay <= timedelta(0)
        ):
            raise ConfigurationError()
        if type(self.docker_context) is not str:
            raise ConfigurationError()
        if (
            type(self.docker_timeout_seconds) not in (int, float)
            or not math.isfinite(self.docker_timeout_seconds)
            or not 0 < self.docker_timeout_seconds <= 60
        ):
            raise ConfigurationError()
        if (
            type(self.docker_max_output_bytes) is not int
            or not 0 < self.docker_max_output_bytes <= 1_048_576
        ):
            raise ConfigurationError()
        if type(self.seccomp_max_bytes) is not int or self.seccomp_max_bytes <= 0:
            raise ConfigurationError()

    def docker_cli(self) -> DockerCli:
        """Build the bounded Docker transport without executing a command."""
        try:
            return DockerCli(
                context=self.docker_context,
                timeout=self.docker_timeout_seconds,
                max_output_bytes=self.docker_max_output_bytes,
            )
        except DockerError:
            raise ConfigurationError() from None

    def seccomp_policy_store(self) -> SeccompPolicyStore:
        """Build the Linux-only private seccomp snapshot store."""
        try:
            return SeccompPolicyStore(
                self.seccomp_store,
                max_bytes=self.seccomp_max_bytes,
            )
        except SeccompError:
            raise ConfigurationError() from None
