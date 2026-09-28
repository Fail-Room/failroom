"""Opt-in proof that the Disk Full Room consumes and restores tmpfs space."""

import os
import re
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from failroom_sandbox.docker_cli import DockerCli
from failroom_sandbox.docker_lifecycle import DockerDiagnosticLifecycle
from failroom_sandbox.docker_profile import DockerBinding
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
from test_linux_docker_integration import (
    _database_directory,
    _exact_label_filters,
    _profile_from_environment,
    _required,
)

from failroom_control_plane import (
    DockerRecoveryRuntime,
    LifecycleOrchestrator,
    RecoveryVerificationService,
)
from failroom_control_plane.room_scenarios import RoomScenarioRegistry
from failroom_control_plane.runtime_docker import (
    DockerCleanupRuntime,
    DockerProvisioningRuntime,
)


@unittest.skipUnless(
    os.environ.get("FAILROOM_DOCKER_INTEGRATION") == "1",
    "UNVERIFIED: opt-in required",
)
@unittest.skipUnless(
    sys.platform == "linux", "UNVERIFIED: trusted Linux controller required"
)
class LinuxDiskFullIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        base_profile = _profile_from_environment()
        self.cli = DockerCli(
            context=_required("FAILROOM_DOCKER_CONTEXT"),
            timeout=float(_required("FAILROOM_DOCKER_TIMEOUT_SECONDS")),
            max_output_bytes=int(_required("FAILROOM_DOCKER_MAX_OUTPUT_BYTES")),
        )
        self.target_tag = "failroom-disk-full-test-" + uuid4().hex
        self.profile = replace(base_profile, image=self._build_target_image())
        self.lifecycle = DockerDiagnosticLifecycle(
            self.cli,
            SeccompPolicyStore(
                Path(_required("FAILROOM_SECCOMP_STORE")),
                max_bytes=int(_required("FAILROOM_SECCOMP_MAX_BYTES")),
            ),
        )
        self.database_temp = tempfile.TemporaryDirectory(dir=_database_directory())
        self.addCleanup(self.database_temp.cleanup)
        self.database = Database(
            Path(self.database_temp.name) / "state.sqlite3",
            busy_timeout_ms=int(_required("FAILROOM_DATABASE_BUSY_TIMEOUT_MS")),
        )
        self.database.initialize()
        self.backend = BackendStore(self.database)
        self.control = ControlPlaneStore(self.database)
        self.now = datetime(2026, 9, 17, tzinfo=UTC)
        self.deadline = self.now + timedelta(minutes=5)
        suffix = uuid4().hex
        self.user = UserIdentity("disk-full-" + suffix, frozenset({"disk-full"}))
        self.backend_identity = ServiceIdentity(
            "disk-full-backend-" + suffix,
            Role.BACKEND,
            frozenset({Action.CREATE, Action.PUBLISH}),
        )
        self.control_identity = ServiceIdentity(
            "disk-full-control-" + suffix,
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.TRANSITION, Action.RECONCILE}),
        )
        self.cleanup_backend_identity = ServiceIdentity(
            "disk-full-cleanup-" + suffix,
            Role.BACKEND,
            frozenset({Action.RECONCILE, Action.PUBLISH}),
        )
        self.provisioning = DockerProvisioningRuntime(self.lifecycle, self.profile)
        self.cleanup = DockerCleanupRuntime(self.lifecycle)
        self.orchestrator = LifecycleOrchestrator(
            self.backend, self.control, self.provisioning
        )
        self.worker = DockerCleanupWorker(
            self.control,
            self.backend,
            self.cleanup,
            retry_delay=timedelta(seconds=10),
        )

    def _build_target_image(self) -> str:
        image_directory = (
            Path(__file__).resolve().parents[3] / "scenarios" / "disk-full" / "image"
        )
        self.addCleanup(self._remove_target_tag)
        result = subprocess.run(
            (
                "docker",
                "--context",
                _required("FAILROOM_DOCKER_CONTEXT"),
                "build",
                "--pull=false",
                "--quiet",
                "--tag",
                self.target_tag,
                str(image_directory),
            ),
            check=False,
            capture_output=True,
            timeout=float(_required("FAILROOM_DOCKER_TIMEOUT_SECONDS")),
        )
        image_id = result.stdout.decode("ascii", errors="ignore").strip()
        if result.returncode != 0 or re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None:
            self.fail("TARGET_IMAGE_BUILD_FAILED")
        return image_id

    def _remove_target_tag(self) -> None:
        result = subprocess.run(
            (
                "docker",
                "--context",
                _required("FAILROOM_DOCKER_CONTEXT"),
                "image",
                "rm",
                self.target_tag,
            ),
            check=False,
            capture_output=True,
            timeout=float(_required("FAILROOM_DOCKER_TIMEOUT_SECONDS")),
        )
        if result.returncode != 0:
            self.fail("TARGET_IMAGE_CLEANUP_FAILED")

    def test_disk_full_filler_reduces_and_restores_workspace_capacity(self) -> None:
        receipt = None
        try:
            scenario = RoomScenarioRegistry().resolve(
                "disk-full", workspace_bytes=self.profile.workspace_tmpfs_bytes
            )
            self.assertIsNotNone(scenario)
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
            container_id = resource.container_id or ""
            available = self.cli.workspace_available_bytes(
                container_id, uid=self.profile.uid, gid=self.profile.gid
            )
            self.assertEqual(
                self.cli.disk_full_filler_size(
                    container_id, uid=self.profile.uid, gid=self.profile.gid
                ),
                scenario.filler_bytes,
            )
            self.assertLess(available, scenario.recovery_free_bytes)

            self.cli.remove_disk_full_filler(
                container_id, uid=self.profile.uid, gid=self.profile.gid
            )
            recovered = self.cli.workspace_available_bytes(
                container_id, uid=self.profile.uid, gid=self.profile.gid
            )
            self.assertGreaterEqual(recovered, scenario.recovery_free_bytes)
            self.assertLessEqual(recovered, self.profile.workspace_tmpfs_bytes)

            status = RecoveryVerificationService(
                self.backend,
                self.control,
                DockerRecoveryRuntime(self.lifecycle, self.profile),
                backend_identity=self.backend_identity,
                control_identity=self.control_identity,
                now=lambda: self.now,
            ).verify(self.user, receipt.attempt_id, key=uuid4().hex)
            self.assertEqual(status.state, "RESOLVED")
            self.assertEqual(
                self.control.inspect(self.control_identity, receipt.ref).state,
                ResourceState.RESOLVED,
            )

            self.backend.leave(
                self.user, receipt.ref, key=uuid4().hex, now=lambda: self.now
            )
            result = self.worker.run_once(
                self.control_identity,
                self.cleanup_backend_identity,
                now=lambda: self.now,
                limit=1,
            )
            self.assertEqual(result.destroyed, 1)
            binding = DockerBinding(
                receipt.ref.attempt_id,
                receipt.ref.sandbox_id,
                receipt.ref.generation,
            )
            self.assertEqual(self.cli.list_containers(_exact_label_filters(binding)), ())
        finally:
            if receipt is not None:
                resource = self.control.inspect(self.control_identity, receipt.ref)
                self.cleanup.destroy_and_verify_absent(
                    CleanupTarget(
                        receipt.ref,
                        resource.container_id,
                        resource.runtime_operation_id,
                        "disk-full-integration-finally",
                    )
                )


if __name__ == "__main__":
    unittest.main()
