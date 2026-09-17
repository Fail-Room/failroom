import unittest
from decimal import Decimal

from failroom_sandbox.docker_cli import DockerCli, DockerError, ProcessResult
from failroom_sandbox.docker_profile import DockerBinding, StrictDockerProfile
from failroom_sandbox.scenario import DiskFullScenario
from failroom_sandbox.scenario_runtime import DiskFullBootstrapRuntime

CID = "a" * 64
BINDING = DockerBinding("attempt-123", "sandbox-456", 1)
SCENARIO = DiskFullScenario(
    filler_path="/workspace/.failroom-disk-full",
    filler_bytes=60_000_000,
    recovery_free_bytes=8_000_000,
)


def profile() -> StrictDockerProfile:
    return StrictDockerProfile(
        image="example@sha256:" + "b" * 64,
        uid=1000,
        gid=1000,
        seccomp_path="/trusted/policy.json",
        seccomp_digest="sha256:" + "c" * 64,
        cpu_limit=Decimal("1"),
        memory_limit_bytes=134_217_728,
        memory_swap_limit_bytes=134_217_728,
        pids_limit=64,
        workspace_tmpfs_bytes=67_108_864,
        temp_tmpfs_bytes=16_777_216,
        shm_size_bytes=16_777_216,
        fd_limit=256,
        io_device_path="/dev/loop0",
        io_read_bps=1_048_576,
        io_write_bps=1_048_576,
        terminal_output_limit_bytes=1_048_576,
        connection_limit=1,
        session_limit=1,
        absolute_ttl_seconds=300,
    )


class DiskFullBootstrapRuntimeTests(unittest.TestCase):
    def test_rechecks_the_exact_running_binding_around_fixed_allocation(self):
        events: list[str] = []

        def runner(argv, **kwargs):
            events.append("allocate")
            return ProcessResult(0, b"", b"")

        def inspect(container_id: str) -> dict[str, object]:
            self.assertEqual(container_id, CID)
            events.append("inspect")
            return {"State": {"Running": True}}

        runtime = DiskFullBootstrapRuntime(
            DockerCli(
                context="desktop-linux",
                timeout=5,
                max_output_bytes=1024,
                runner=runner,
            ),
            profile(),
            BINDING,
            "operation-789",
            inspect,
        )

        observation = runtime.apply(CID, SCENARIO)

        self.assertEqual(events, ["inspect", "allocate", "inspect"])
        self.assertRegex(observation.evidence_digest, r"^sha256:[a-f0-9]{64}$")

    def test_rejects_a_foreign_binding_before_any_allocation(self):
        calls: list[tuple[str, ...]] = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, b"", b"")

        runtime = DiskFullBootstrapRuntime(
            DockerCli(
                context="desktop-linux",
                timeout=5,
                max_output_bytes=1024,
                runner=runner,
            ),
            profile(),
            BINDING,
            "operation-789",
            lambda container_id: (_ for _ in ()).throw(DockerError("OWNERSHIP_MISMATCH")),
        )

        with self.assertRaisesRegex(DockerError, "^OWNERSHIP_MISMATCH$"):
            runtime.apply(CID, SCENARIO)

        self.assertEqual(calls, [])

    def test_rejects_a_non_running_container_after_allocation(self):
        checks = 0

        def inspect(container_id: str) -> dict[str, object]:
            nonlocal checks
            checks += 1
            return {"State": {"Running": checks == 1}}

        runtime = DiskFullBootstrapRuntime(
            DockerCli(
                context="desktop-linux",
                timeout=5,
                max_output_bytes=1024,
                runner=lambda *args, **kwargs: ProcessResult(0, b"", b""),
            ),
            profile(),
            BINDING,
            "operation-789",
            inspect,
        )

        with self.assertRaisesRegex(DockerError, "^PROFILE_UNVERIFIED$"):
            runtime.apply(CID, SCENARIO)


if __name__ == "__main__":
    unittest.main()
