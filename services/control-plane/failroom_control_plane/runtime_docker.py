"""Trusted adapters between the control plane and the bounded Docker runtime."""

from collections.abc import Iterator
from contextlib import contextmanager

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.docker_lifecycle import (
    DockerDiagnosticLifecycle,
    PreparedDockerOperation,
)
from failroom_sandbox.docker_profile import DockerBinding, StrictDockerProfile
from failroom_state import CleanupTarget, RuntimeCleanupError

__all__ = ("DockerCleanupRuntime", "DockerProvisioningRuntime")


class DockerProvisioningRuntime:
    """Expose the verified create/start session to the lifecycle orchestrator."""

    def __init__(
        self, lifecycle: DockerDiagnosticLifecycle, profile: StrictDockerProfile
    ) -> None:
        self._lifecycle = lifecycle
        self._profile = profile

    @contextmanager
    def open(
        self, binding: DockerBinding, runtime_operation_id: str
    ) -> Iterator[PreparedDockerOperation]:
        with self._lifecycle.prepare(
            self._profile, binding, runtime_operation_id
        ) as operation:
            yield operation


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
