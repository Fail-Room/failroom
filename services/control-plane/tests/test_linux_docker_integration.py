"""Opt-in proof of the durable control-plane Docker lifecycle on Linux."""

import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from failroom_sandbox.docker_cli import DockerCli
from failroom_sandbox.docker_lifecycle import DockerDiagnosticLifecycle
from failroom_sandbox.docker_profile import DockerBinding, StrictDockerProfile
from failroom_sandbox.seccomp import SeccompPolicyStore
from failroom_state import (
    Action,
    BackendStore,
    CleanupTarget,
    ControlPlaneStore,
    Database,
    DockerCleanupWorker,
    ResourceState,
    Role,
    ServiceIdentity,
    UserIdentity,
)

from failroom_control_plane import (
    DockerCleanupRuntime,
    DockerProvisioningRuntime,
    LifecycleOrchestrator,
)

_REQUIRED = (
    "FAILROOM_DOCKER_CONTEXT",
    "FAILROOM_DOCKER_IMAGE",
    "FAILROOM_DOCKER_UID",
    "FAILROOM_DOCKER_GID",
    "FAILROOM_SECCOMP_PATH",
    "FAILROOM_SECCOMP_DIGEST",
    "FAILROOM_SECCOMP_STORE",
    "FAILROOM_SECCOMP_MAX_BYTES",
    "FAILROOM_DOCKER_TIMEOUT_SECONDS",
    "FAILROOM_DOCKER_MAX_OUTPUT_BYTES",
    "FAILROOM_CPU_LIMIT",
    "FAILROOM_MEMORY_BYTES",
    "FAILROOM_MEMORY_SWAP_BYTES",
    "FAILROOM_PIDS_LIMIT",
    "FAILROOM_WORKSPACE_TMPFS_BYTES",
    "FAILROOM_TEMP_TMPFS_BYTES",
    "FAILROOM_SHM_BYTES",
    "FAILROOM_FD_LIMIT",
    "FAILROOM_IO_DEVICE",
    "FAILROOM_IO_READ_BPS",
    "FAILROOM_IO_WRITE_BPS",
    "FAILROOM_TERMINAL_OUTPUT_BYTES",
    "FAILROOM_CONNECTION_LIMIT",
    "FAILROOM_SESSION_LIMIT",
    "FAILROOM_ABSOLUTE_TTL_SECONDS",
    "FAILROOM_DATABASE_DIR",
    "FAILROOM_DATABASE_BUSY_TIMEOUT_MS",
)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise unittest.SkipTest("UNVERIFIED: missing explicit operator input")
    return value


def _database_directory() -> Path:
    path = Path(_required("FAILROOM_DATABASE_DIR"))
    if not path.is_absolute() or not path.is_dir():
        raise unittest.SkipTest(
            "UNVERIFIED: FAILROOM_DATABASE_DIR must be an existing absolute directory"
        )
    return path


def _profile_from_environment() -> StrictDockerProfile:
    return StrictDockerProfile(
        image=_required("FAILROOM_DOCKER_IMAGE"),
        uid=int(_required("FAILROOM_DOCKER_UID")),
        gid=int(_required("FAILROOM_DOCKER_GID")),
        seccomp_path=_required("FAILROOM_SECCOMP_PATH"),
        seccomp_digest=_required("FAILROOM_SECCOMP_DIGEST"),
        cpu_limit=Decimal(_required("FAILROOM_CPU_LIMIT")),
        memory_limit_bytes=int(_required("FAILROOM_MEMORY_BYTES")),
        memory_swap_limit_bytes=int(_required("FAILROOM_MEMORY_SWAP_BYTES")),
        pids_limit=int(_required("FAILROOM_PIDS_LIMIT")),
        workspace_tmpfs_bytes=int(_required("FAILROOM_WORKSPACE_TMPFS_BYTES")),
        temp_tmpfs_bytes=int(_required("FAILROOM_TEMP_TMPFS_BYTES")),
        shm_size_bytes=int(_required("FAILROOM_SHM_BYTES")),
        fd_limit=int(_required("FAILROOM_FD_LIMIT")),
        io_device_path=_required("FAILROOM_IO_DEVICE"),
        io_read_bps=int(_required("FAILROOM_IO_READ_BPS")),
        io_write_bps=int(_required("FAILROOM_IO_WRITE_BPS")),
        terminal_output_limit_bytes=int(_required("FAILROOM_TERMINAL_OUTPUT_BYTES")),
        connection_limit=int(_required("FAILROOM_CONNECTION_LIMIT")),
        session_limit=int(_required("FAILROOM_SESSION_LIMIT")),
        absolute_ttl_seconds=int(_required("FAILROOM_ABSOLUTE_TTL_SECONDS")),
    )


def build_runtime_from_required_environment() -> tuple[
    DockerProvisioningRuntime, DockerCleanupRuntime
]:
    profile = _profile_from_environment()
    lifecycle = DockerDiagnosticLifecycle(
        DockerCli(
            context=_required("FAILROOM_DOCKER_CONTEXT"),
            timeout=float(_required("FAILROOM_DOCKER_TIMEOUT_SECONDS")),
            max_output_bytes=int(_required("FAILROOM_DOCKER_MAX_OUTPUT_BYTES")),
        ),
        SeccompPolicyStore(
            Path(_required("FAILROOM_SECCOMP_STORE")),
            max_bytes=int(_required("FAILROOM_SECCOMP_MAX_BYTES")),
        ),
    )
    return DockerProvisioningRuntime(lifecycle, profile), DockerCleanupRuntime(
        lifecycle
    )


def _assert_hardening(
    test_case: unittest.TestCase,
    data: dict[str, object],
    profile: StrictDockerProfile,
) -> None:
    config = data["Config"]
    host = data["HostConfig"]
    mounts = data["Mounts"]
    test_case.assertEqual(config["User"], f"{profile.uid}:{profile.gid}")
    test_case.assertEqual(host["NetworkMode"], "none")
    test_case.assertIsNone(host["Binds"])
    test_case.assertIsNone(host.get("Mounts"))
    test_case.assertIsNone(host["VolumesFrom"])
    test_case.assertEqual(host["Devices"], [])
    test_case.assertIsNone(host["DeviceRequests"])
    test_case.assertEqual(
        host["Tmpfs"],
        {
            "/workspace": f"rw,size={profile.workspace_tmpfs_bytes},nosuid,nodev,noexec",
            "/tmp": f"rw,size={profile.temp_tmpfs_bytes},nosuid,nodev,noexec",
        },
    )
    expected_mounts = [
        {"Type": "tmpfs", "Destination": "/workspace", "Source": ""},
        {"Type": "tmpfs", "Destination": "/tmp", "Source": ""},
    ]
    if mounts:
        test_case.assertEqual(mounts, expected_mounts)
    else:
        test_case.assertEqual(mounts, [])
    test_case.assertNotIn("docker.sock", repr(data))


def _exact_label_filters(binding: DockerBinding) -> tuple[str, ...]:
    return (
        "label=failroom.kind=diagnostic",
        "label=failroom.attempt_id=" + binding.attempt_id,
        "label=failroom.sandbox_id=" + binding.sandbox_id,
        "label=failroom.generation=" + str(binding.generation),
    )


@unittest.skipUnless(
    os.environ.get("FAILROOM_DOCKER_INTEGRATION") == "1",
    "UNVERIFIED: opt-in required",
)
@unittest.skipUnless(
    sys.platform == "linux", "UNVERIFIED: trusted Linux controller required"
)
class LinuxControlPlaneIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = _profile_from_environment()
        self.database_root = _database_directory()
        self.database_temp = tempfile.TemporaryDirectory(dir=self.database_root)
        self.addCleanup(self.database_temp.cleanup)
        self.database_path = Path(self.database_temp.name) / "state.sqlite3"
        self.database = Database(
            self.database_path,
            busy_timeout_ms=int(_required("FAILROOM_DATABASE_BUSY_TIMEOUT_MS")),
        )
        self.database.initialize()
        self.backend = BackendStore(self.database)
        self.control = ControlPlaneStore(self.database)
        self.now = datetime(2026, 9, 8, tzinfo=UTC)
        self.deadline = self.now + timedelta(minutes=5)
        suffix = uuid4().hex
        self.user = UserIdentity(
            "linux-integration-" + suffix, frozenset({"disk-full"})
        )
        self.backend_identity = ServiceIdentity(
            "linux-backend-" + suffix,
            Role.BACKEND,
            frozenset({Action.CREATE, Action.PUBLISH}),
        )
        self.control_identity = ServiceIdentity(
            "linux-control-" + suffix,
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.TRANSITION, Action.RECONCILE}),
        )
        self.cleanup_backend_identity = ServiceIdentity(
            "linux-cleanup-backend-" + suffix,
            Role.BACKEND,
            frozenset({Action.RECONCILE, Action.PUBLISH}),
        )
        self.provisioning, self.cleanup = build_runtime_from_required_environment()
        self.orchestrator = LifecycleOrchestrator(
            self.backend, self.control, self.provisioning
        )
        self.worker = DockerCleanupWorker(
            self.control,
            self.backend,
            self.cleanup,
            retry_delay=timedelta(seconds=10),
        )
        self.inspect_cli = DockerCli(
            context=_required("FAILROOM_DOCKER_CONTEXT"),
            timeout=float(_required("FAILROOM_DOCKER_TIMEOUT_SECONDS")),
            max_output_bytes=int(_required("FAILROOM_DOCKER_MAX_OUTPUT_BYTES")),
        )

    def test_create_start_leave_cleanup_and_absence_evidence(self) -> None:
        receipt = None
        try:
            receipt = self.backend.create(
                self.user,
                "disk-full",
                key=uuid4().hex,
                expires_at=self.deadline,
                now=lambda: self.now,
            )
            self.orchestrator.provision(
                receipt,
                backend_identity=self.backend_identity,
                control_identity=self.control_identity,
                key=uuid4().hex,
                now=lambda: self.now,
            )
            resource = self.control.inspect(self.control_identity, receipt.ref)
            self.assertEqual(resource.state, ResourceState.READY)
            self.assertIsNotNone(resource.container_id)
            data = self.inspect_cli.inspect_container(resource.container_id)
            self.assertIsNotNone(data)
            _assert_hardening(self, data, self.profile)

            self.backend.leave(
                self.user,
                receipt.ref,
                key=uuid4().hex,
                now=lambda: self.now,
            )
            result = self.worker.run_once(
                self.control_identity,
                self.cleanup_backend_identity,
                now=lambda: self.now,
                limit=1,
            )
            self.assertEqual(result.destroyed, 1)
            self.assertEqual(result.finalized, 1)
            destroyed = self.control.inspect(self.control_identity, receipt.ref)
            self.assertEqual(destroyed.state, ResourceState.DESTROYED)
            self.assertRegex(
                destroyed.cleanup_evidence_digest or "",
                r"^sha256:[0-9a-f]{64}$",
            )
            binding = DockerBinding(
                receipt.ref.attempt_id,
                receipt.ref.sandbox_id,
                receipt.ref.generation,
            )
            self.assertEqual(
                self.inspect_cli.list_containers(_exact_label_filters(binding)), ()
            )
        finally:
            if receipt is not None:
                resource = self.control.inspect(self.control_identity, receipt.ref)
                target = CleanupTarget(
                    receipt.ref,
                    resource.container_id,
                    resource.runtime_operation_id,
                    "linux-integration-finally",
                )
                self.cleanup.destroy_and_verify_absent(target)


if __name__ == "__main__":
    unittest.main()
