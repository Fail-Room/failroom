"""Opt-in proof for a trusted Linux control-plane host.

This test never supplies profile defaults. It is skipped unless an operator
explicitly provides every input and enables it. Windows intentionally skips:
the production SeccompPolicyStore rejects that platform before Docker create.
"""

import os
import sys
import unittest
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from failroom_sandbox.docker_cli import DockerCli
from failroom_sandbox.docker_lifecycle import DockerDiagnosticLifecycle
from failroom_sandbox.docker_profile import DockerBinding, StrictDockerProfile
from failroom_sandbox.seccomp import SeccompPolicyStore

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
    "FAILROOM_TARGET_SUPERVISOR_TMPFS_BYTES",
    "FAILROOM_SHM_BYTES",
    "FAILROOM_FD_LIMIT",
    "FAILROOM_IO_DEVICE",
    "FAILROOM_IO_READ_BPS",
    "FAILROOM_IO_WRITE_BPS",
    "FAILROOM_TERMINAL_OUTPUT_BYTES",
    "FAILROOM_CONNECTION_LIMIT",
    "FAILROOM_SESSION_LIMIT",
    "FAILROOM_ABSOLUTE_TTL_SECONDS",
)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise unittest.SkipTest("UNVERIFIED: missing explicit operator profile input")
    return value


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
        target_supervisor_tmpfs_bytes=int(
            _required("FAILROOM_TARGET_SUPERVISOR_TMPFS_BYTES")
        ),
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


def _assert_hardening(
    test_case: unittest.TestCase, data: dict[str, object], profile: StrictDockerProfile
) -> None:
    config = data["Config"]
    host = data["HostConfig"]
    mounts = data["Mounts"]
    test_case.assertEqual(config["User"], f"{profile.uid}:{profile.gid}")
    test_case.assertEqual(host["NetworkMode"], "none")
    test_case.assertIsNone(host["Binds"])
    test_case.assertIsNone(host["Mounts"])
    test_case.assertIsNone(host["VolumesFrom"])
    test_case.assertEqual(host["Devices"], [])
    test_case.assertIsNone(host["DeviceRequests"])
    test_case.assertEqual(
        host["Tmpfs"],
        {
            "/workspace": f"rw,size={profile.workspace_tmpfs_bytes},nosuid,nodev,noexec",
            "/tmp": f"rw,size={profile.temp_tmpfs_bytes},nosuid,nodev,noexec",
            "/run/failroom-target": (
                "rw,size="
                + str(profile.target_supervisor_tmpfs_bytes)
                + ",mode=0700,nosuid,nodev,noexec"
            ),
        },
    )
    test_case.assertEqual(
        mounts,
        [
            {"Type": "tmpfs", "Destination": "/workspace", "Source": ""},
            {"Type": "tmpfs", "Destination": "/tmp", "Source": ""},
            {"Type": "tmpfs", "Destination": "/run/failroom-target", "Source": ""},
        ],
    )
    test_case.assertNotIn("docker.sock", repr(data))


@unittest.skipUnless(
    os.environ.get("FAILROOM_DOCKER_INTEGRATION") == "1",
    "UNVERIFIED: set FAILROOM_DOCKER_INTEGRATION=1 on a trusted Linux controller",
)
@unittest.skipUnless(
    sys.platform == "linux", "UNVERIFIED: secure policy pinning requires Linux"
)
class DockerDiagnosticIntegrationTests(unittest.TestCase):
    def test_owned_diagnostic_resource_is_verified_absent_after_destroy(self):
        profile = _profile_from_environment()
        context = _required("FAILROOM_DOCKER_CONTEXT")
        store = SeccompPolicyStore(
            Path(_required("FAILROOM_SECCOMP_STORE")),
            max_bytes=int(_required("FAILROOM_SECCOMP_MAX_BYTES")),
        )
        cli = DockerCli(
            context=context,
            timeout=float(_required("FAILROOM_DOCKER_TIMEOUT_SECONDS")),
            max_output_bytes=int(_required("FAILROOM_DOCKER_MAX_OUTPUT_BYTES")),
        )
        lifecycle = DockerDiagnosticLifecycle(
            cli,
            store,
        )
        binding = DockerBinding(uuid4().hex, uuid4().hex, 1)
        operation_id = uuid4().hex
        container_id = None
        try:
            observation = lifecycle.create_diagnostic(profile, binding, operation_id)
            container_id = observation.container_id
            self.assertTrue(observation.running)
            data = cli.inspect_container(container_id)
            self.assertIsNotNone(data)
            _assert_hardening(self, data, profile)
            evidence = lifecycle.destroy(
                binding,
                container_id,
                operation_id=operation_id,
            )
            self.assertRegex(evidence, r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(
                cli.list_containers(
                    (
                        "label=failroom.kind=diagnostic",
                        "label=failroom.attempt_id=" + binding.attempt_id,
                        "label=failroom.sandbox_id=" + binding.sandbox_id,
                        "label=failroom.generation=1",
                    )
                ),
                (),
            )
        finally:
            # The lifecycle is idempotent; rerun cleanup after assertion failures.
            lifecycle.destroy(
                binding,
                container_id,
                operation_id=operation_id,
            )


if __name__ == "__main__":
    unittest.main()
