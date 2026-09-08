import unittest
from contextlib import contextmanager
from unittest.mock import Mock

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.docker_profile import DockerBinding
from failroom_state import CleanupTarget, ResourceRef, RuntimeCleanupError

from failroom_control_plane.runtime_docker import (
    DockerCleanupRuntime,
    DockerProvisioningRuntime,
)


class DockerRuntimeAdapterTests(unittest.TestCase):
    def binding(self) -> DockerBinding:
        return DockerBinding("attempt-123", "sandbox-456", 1)

    def target(
        self,
        *,
        container_id: str | None = "c" * 64,
        runtime_operation_id: str | None = "a" * 32,
    ) -> CleanupTarget:
        return CleanupTarget(
            ResourceRef("attempt-123", "sandbox-456", 1),
            container_id,
            runtime_operation_id,
            "cleanup-operation",
        )

    def test_provisioning_adapter_holds_prepared_operation(self) -> None:
        lifecycle = Mock()
        profile = object()
        operation = object()

        @contextmanager
        def prepare(*args: object):
            lifecycle.prepare_calls = args
            yield operation

        lifecycle.prepare.side_effect = prepare
        adapter = DockerProvisioningRuntime(lifecycle, profile)

        with adapter.open(self.binding(), "runtime-operation") as actual:
            self.assertIs(actual, operation)

        lifecycle.prepare.assert_called_once_with(
            profile, self.binding(), "runtime-operation"
        )

    def test_cleanup_adapter_uses_original_runtime_id_not_cleanup_operation_id(
        self,
    ) -> None:
        lifecycle = Mock()
        lifecycle.destroy.return_value = "sha256:" + "b" * 64
        cleanup = DockerCleanupRuntime(lifecycle)

        evidence = cleanup.destroy_and_verify_absent(self.target())

        self.assertRegex(evidence, r"^sha256:[0-9a-f]{64}$")
        lifecycle.destroy.assert_called_once_with(
            self.binding(),
            "c" * 64,
            operation_id="a" * 32,
        )

    def test_legacy_cleanup_never_substitutes_cleanup_operation_id(self) -> None:
        lifecycle = Mock()
        lifecycle.destroy.return_value = "sha256:" + "b" * 64
        cleanup = DockerCleanupRuntime(lifecycle)

        cleanup.destroy_and_verify_absent(
            self.target(container_id=None, runtime_operation_id=None)
        )

        lifecycle.destroy.assert_called_once_with(
            self.binding(), None, operation_id=None
        )

    def test_runtime_unavailable_is_mapped_without_raw_error(self) -> None:
        lifecycle = Mock()
        lifecycle.destroy.side_effect = DockerError("RUNTIME_UNAVAILABLE")
        cleanup = DockerCleanupRuntime(lifecycle)

        with self.assertRaises(RuntimeCleanupError) as raised:
            cleanup.destroy_and_verify_absent(self.target())

        self.assertEqual(raised.exception.code, "RUNTIME_UNAVAILABLE")
        self.assertEqual(str(raised.exception), "RUNTIME_UNAVAILABLE")

    def test_profile_and_ownership_errors_map_to_cleanup_incomplete(self) -> None:
        for code in (
            "PROFILE_UNVERIFIED",
            "OWNERSHIP_MISMATCH",
            "INVALID_DOCKER_REQUEST",
        ):
            with self.subTest(code=code):
                lifecycle = Mock()
                lifecycle.destroy.side_effect = DockerError(code)
                cleanup = DockerCleanupRuntime(lifecycle)

                with self.assertRaises(RuntimeCleanupError) as raised:
                    cleanup.destroy_and_verify_absent(self.target())

                self.assertEqual(raised.exception.code, "CLEANUP_INCOMPLETE")
                self.assertNotIn(code, str(raised.exception))

    def test_unknown_errors_map_to_cleanup_incomplete(self) -> None:
        lifecycle = Mock()
        lifecycle.destroy.side_effect = RuntimeError("secret daemon output")
        cleanup = DockerCleanupRuntime(lifecycle)

        with self.assertRaises(RuntimeCleanupError) as raised:
            cleanup.destroy_and_verify_absent(self.target())

        self.assertEqual(raised.exception.code, "CLEANUP_INCOMPLETE")
        self.assertNotIn("secret daemon output", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
