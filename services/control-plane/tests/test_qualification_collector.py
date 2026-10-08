import copy
import math
import re
import unittest
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import MappingProxyType

from failroom_sandbox.docker_cli import DockerError, EngineIdentity
from failroom_sandbox.docker_lifecycle import ContainerObservation
from failroom_sandbox.docker_profile import StrictDockerProfile, profile_fingerprint
from failroom_sandbox.models import (
    Check,
    DenialCode,
    Outcome,
    QualificationDecision,
)
from failroom_sandbox.qualification import evaluate_qualification
from failroom_sandbox.qualification_probe import CONTAINER_CHECKS

from failroom_control_plane.qualification_collector import (
    QUALIFICATION_ATTEMPT,
    QualificationCollector,
    QualificationError,
    format_collection,
)

NOW = datetime(2026, 10, 8, 10, 14, tzinfo=UTC)
STARTED_AT = "2026-10-08T10:14:00.951523267Z"
BOOT_ID = "39838d7c-98d9-4c41-9181-b3baadabb0c6"
IMAGE_ID = "sha256:" + "d" * 64
SCENARIO_CHECKS = tuple(check for check in Check if check not in CONTAINER_CHECKS)


def profile(**changes) -> StrictDockerProfile:
    values = {
        "image": "registry.example.com/failroom/diagnostic@sha256:" + "a" * 64,
        "uid": 10001,
        "gid": 10001,
        "seccomp_path": "/etc/failroom/seccomp.json",
        "seccomp_digest": "sha256:" + "b" * 64,
        "cpu_limit": Decimal("0.5"),
        "memory_limit_bytes": 134_217_728,
        "memory_swap_limit_bytes": 134_217_728,
        "pids_limit": 64,
        "workspace_tmpfs_bytes": 67_108_864,
        "temp_tmpfs_bytes": 16_777_216,
        "target_supervisor_tmpfs_bytes": 1_048_576,
        "shm_size_bytes": 16_777_216,
        "fd_limit": 256,
        "io_device_path": "/dev/loop0",
        "io_read_bps": 1_048_576,
        "io_write_bps": 1_048_576,
        "terminal_output_limit_bytes": 1_048_576,
        "connection_limit": 1,
        "session_limit": 1,
        "absolute_ttl_seconds": 300,
    }
    values.update(changes)
    return StrictDockerProfile(**values)


def probe_output(lifetime: int, *, boot_id=BOOT_ID, io_device="7:0") -> bytes:
    lines = [
        "probe=1",
        "uid=10001",
        "gid=10001",
        "groups=10001",
        *(
            f"status_{name}=0000000000000000"
            for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        ),
        "status_NoNewPrivs=1",
        "status_Seccomp=2",
        "status_Seccomp_filters=2",
        "boot_id=" + boot_id,
        f"process=1 0 /sbin/docker-init -- /bin/sleep {lifetime}",
        f"process=7 1 /bin/sleep {lifetime}",
        "process=8 0 /bin/sh -c LC_ALL=C PATH=/usr/bin:/bin",
        "mount=/ overlay ro,relatime root",
        "mount=/proc proc rw,nosuid,nodev,noexec,relatime root",
        "mount=/dev tmpfs rw,nosuid root",
        "mount=/sys sysfs ro,nosuid,nodev,noexec,relatime root",
        "mount=/dev/shm tmpfs rw,nosuid,nodev,noexec,relatime root",
        "mount=/usr/sbin/docker-init overlay ro,relatime other",
        "mount=/tmp tmpfs rw,nosuid,nodev,noexec,relatime root",
        "mount=/workspace tmpfs rw,nosuid,nodev,noexec,relatime root",
        "mount=/run/failroom-target tmpfs rw,nosuid,nodev,noexec,relatime root",
        "mount=/etc/hosts ext4 ro,relatime other",
        "net_iface=lo",
        "default_route=0",
        "tcp_connect=1",
        "socket_files=0",
        "cgroup_cpu.max=50000 100000",
        "cgroup_memory.max=134217728",
        "cgroup_memory.swap.max=0",
        "cgroup_pids.max=64",
        f"io_max={io_device} rbps=1048576 wbps=1048576 riops=max wiops=max",
        "fd_soft=256",
        "fd_hard=256",
        "fs_size=/workspace 67108864",
        "fs_size=/tmp 16777216",
        "fs_size=/run/failroom-target 1048576",
        "fs_size=/dev/shm 16777216",
        "workspace_overfill=1 1",
        "end=1",
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


def container(binding, operation_id, lifetime, *, status="running", created=None):
    return {
        "Image": IMAGE_ID,
        "Created": created or STARTED_AT,
        "State": {
            "Status": status,
            "Running": status == "running",
            "StartedAt": STARTED_AT,
        },
        "Config": {
            "User": "10001:10001",
            "Cmd": [str(lifetime)],
            "Labels": {
                "failroom.kind": "diagnostic",
                "failroom.attempt_id": binding.attempt_id,
                "failroom.sandbox_id": binding.sandbox_id,
                "failroom.generation": str(binding.generation),
                "failroom.operation_id": operation_id,
            },
        },
        "HostConfig": {
            "Privileged": False,
            "SecurityOpt": ["no-new-privileges", "seccomp=/trusted/policy.json"],
            "PidMode": "",
            "IpcMode": "private",
            "NetworkMode": "none",
            "UTSMode": "",
            "UsernsMode": "",
            "CgroupnsMode": "private",
            "Binds": None,
            "VolumesFrom": None,
            "Devices": [],
            "DeviceRequests": None,
            "CapAdd": None,
        },
    }


class FakeDocker:
    def __init__(self) -> None:
        self.containers: dict[str, dict] = {}
        self.listed: tuple[str, ...] = ()
        self.probe_output = probe_output(60)
        self.probe_error: Exception | None = None
        self.engine = EngineIdentity(
            "engine-1",
            MappingProxyType({"ServerVersion": "29.4.2", "Runtimes": ["runc"]}),
        )
        self.filters: list[tuple[str, ...]] = []

    def engine_identity(self) -> EngineIdentity:
        return self.engine

    def run_qualification_probe(self, container_id: str) -> bytes:
        if self.probe_error is not None:
            raise self.probe_error
        return self.probe_output

    def inspect_container(self, selector: str):
        return copy.deepcopy(self.containers.get(selector))

    def list_containers(self, filters):
        self.filters.append(filters)
        return self.listed


class FakeLifecycle:
    def __init__(self, docker: FakeDocker) -> None:
        self.docker = docker
        self.created: list = []
        self.destroyed: list = []
        self.destroy_error: Exception | None = None
        self.sentinel_status = "running"

    def create_diagnostic(self, profile, binding, operation_id, *, lifetime):
        remaining = (lifetime.deadline - lifetime.now()).total_seconds()
        seconds = min(math.floor(remaining) - 10, profile.absolute_ttl_seconds - 10)
        container_id = f"{len(self.docker.containers) + 1:064x}"
        status = (
            self.sentinel_status
            if binding.sandbox_id.startswith("sentinel-")
            else "running"
        )
        self.docker.containers[container_id] = container(
            binding, operation_id, seconds, status=status
        )
        self.created.append((binding, operation_id, lifetime, container_id))
        return ContainerObservation(container_id, True, "sha256:" + "e" * 64)

    def destroy(self, binding, container_id, *, operation_id=None):
        if self.destroy_error is not None:
            raise self.destroy_error
        self.destroyed.append((binding, container_id, operation_id))
        self.docker.containers.pop(container_id, None)
        return "sha256:" + "f" * 64


class QualificationCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.docker = FakeDocker()
        self.lifecycle = FakeLifecycle(self.docker)
        self.profile = profile()

    def collector(self, *, max_age=timedelta(hours=1)) -> QualificationCollector:
        return QualificationCollector(
            self.docker, self.lifecycle, self.profile, max_age=max_age, now=lambda: NOW
        )

    def test_collects_container_checks_and_reports_scenarios_unverified(self) -> None:
        collection = self.collector().collect()
        report = collection.report

        self.assertEqual(tuple(result.check for result in report.results), tuple(Check))
        for result in report.results:
            with self.subTest(check=result.check):
                expected = (
                    Outcome.PASS
                    if result.check in CONTAINER_CHECKS
                    else Outcome.UNVERIFIED
                )
                self.assertIs(result.outcome, expected)
                self.assertEqual(result.observed_at, NOW)
                self.assertRegex(result.evidence_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            dict(collection.reasons),
            {check: "NOT_COLLECTED" for check in SCENARIO_CHECKS},
        )
        decision = evaluate_qualification(
            report.context, report, now=NOW, max_age=timedelta(hours=1)
        )
        self.assertEqual(
            {(denial.code, denial.check) for denial in decision.denials},
            {(DenialCode.CHECK_UNVERIFIED, check) for check in SCENARIO_CHECKS},
        )

    def test_report_is_bound_to_runtime_image_and_profile(self) -> None:
        context = self.collector().collect().report.context
        sentinel_id = self.lifecycle.created[0][3]

        self.assertEqual(context.runtime.engine_id, "engine-1")
        self.assertEqual(context.runtime.host_boot_id, BOOT_ID)
        self.assertEqual(context.runtime.daemon_epoch, f"{sentinel_id}@{STARTED_AT}")
        self.assertRegex(context.runtime.configuration_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(context.image_digest, IMAGE_ID)
        self.assertEqual(context.profile_digest, profile_fingerprint(self.profile))

    def test_configuration_digest_follows_engine_and_io_device(self) -> None:
        baseline = self.collector().collect().report.context.runtime
        self.docker.probe_output = probe_output(60, io_device="8:48")
        moved = self.collector().collect().report.context.runtime
        self.docker.probe_output = probe_output(60)
        self.docker.engine = EngineIdentity(
            "engine-1",
            MappingProxyType({"ServerVersion": "29.5.0", "Runtimes": ["runc"]}),
        )
        upgraded = self.collector().collect().report.context.runtime

        self.assertNotEqual(baseline.configuration_digest, moved.configuration_digest)
        self.assertNotEqual(
            baseline.configuration_digest, upgraded.configuration_digest
        )

    def test_creates_and_destroys_only_collector_owned_sandboxes(self) -> None:
        self.collector().collect()

        (sentinel, sentinel_op, sentinel_life, sentinel_id), probe = (
            self.lifecycle.created
        )
        probe_binding, probe_op, probe_life, probe_id = probe
        for binding, role in ((sentinel, "sentinel"), (probe_binding, "probe")):
            self.assertEqual(binding.attempt_id, QUALIFICATION_ATTEMPT)
            self.assertRegex(binding.sandbox_id, rf"^{role}-[0-9a-f]{{32}}$")
            self.assertEqual(binding.generation, 1)
        self.assertEqual(sentinel_life.deadline - NOW, timedelta(seconds=300))
        self.assertEqual(probe_life.deadline - NOW, timedelta(seconds=70))
        self.assertEqual(
            self.lifecycle.destroyed,
            [(probe_binding, probe_id, probe_op), (sentinel, sentinel_id, sentinel_op)],
        )
        self.assertEqual(self.docker.containers, {})

    def test_sentinel_lifetime_is_the_report_validity_within_the_profile(self) -> None:
        self.collector(max_age=timedelta(seconds=120)).collect()

        self.assertEqual(
            self.lifecycle.created[0][2].deadline - NOW, timedelta(seconds=130)
        )

    def test_failed_or_unreadable_probe_is_no_report_and_cleans_up(self) -> None:
        cases = {
            "probe failure": ("probe_error", DockerError("RUNTIME_UNAVAILABLE")),
            "malformed output": ("probe_output", b"probe=1\nend=1\n"),
            "invalid boot id": ("probe_output", probe_output(60, boot_id="unknown")),
        }
        for name, (attribute, value) in cases.items():
            with self.subTest(case=name):
                self.setUp()
                setattr(self.docker, attribute, value)
                with self.assertRaises(QualificationError) as raised:
                    self.collector().collect()
                self.assertEqual(raised.exception.code, "RUNTIME_UNAVAILABLE")
                self.assertEqual(len(self.lifecycle.destroyed), 2)
                self.assertEqual(self.docker.containers, {})

    def test_stopped_sentinel_has_no_daemon_epoch(self) -> None:
        self.lifecycle.sentinel_status = "exited"

        with self.assertRaises(QualificationError) as raised:
            self.collector().collect()

        self.assertEqual(raised.exception.code, "RUNTIME_UNAVAILABLE")
        self.assertEqual(len(self.lifecycle.created), 1)
        self.assertEqual(len(self.lifecycle.destroyed), 1)

    def test_cleanup_failure_is_reported_as_incomplete(self) -> None:
        self.lifecycle.destroy_error = DockerError("CLEANUP_INCOMPLETE")

        with self.assertRaises(QualificationError) as raised:
            self.collector().collect()

        self.assertEqual(raised.exception.code, "CLEANUP_INCOMPLETE")

    def test_sweep_removes_stopped_leftovers_and_keeps_running_ones(self) -> None:
        from failroom_sandbox.docker_profile import DockerBinding

        def leftover(name, status, created=None):
            binding = DockerBinding(QUALIFICATION_ATTEMPT, name, 1)
            cid = f"{len(self.docker.containers) + 100:064x}"
            self.docker.containers[cid] = container(
                binding, "op-" + name, 5, status=status, created=created
            )
            return cid, binding

        exited = leftover("probe-exited", "exited")
        dead = leftover("probe-dead", "dead")
        running = leftover("probe-running", "running")
        fresh = leftover("probe-fresh", "created", "2026-10-08T10:10:00Z")
        stale = leftover("probe-stale", "created", "2026-10-08T10:00:00.5Z")
        self.docker.listed = tuple(
            cid for cid, _ in (exited, dead, running, fresh, stale)
        )

        self.collector().collect()

        swept = [entry for entry in self.lifecycle.destroyed[:3]]
        self.assertEqual(
            swept,
            [
                (binding, cid, "op-" + binding.sandbox_id)
                for cid, binding in (exited, dead, stale)
            ],
        )
        self.assertIn(running[0], self.docker.containers)
        self.assertIn(fresh[0], self.docker.containers)
        self.assertEqual(
            self.docker.filters[0],
            (
                "label=failroom.kind=diagnostic",
                "label=failroom.attempt_id=" + QUALIFICATION_ATTEMPT,
            ),
        )

    def test_sweep_refuses_leftovers_without_exact_labels(self) -> None:
        from failroom_sandbox.docker_profile import DockerBinding

        binding = DockerBinding(QUALIFICATION_ATTEMPT, "probe-broken", 1)
        data = container(binding, "op", 5, status="exited")
        data["Config"]["Labels"]["failroom.generation"] = "one"
        self.docker.containers["a" * 64] = data
        self.docker.listed = ("a" * 64,)

        with self.assertRaises(QualificationError) as raised:
            self.collector().collect()

        self.assertEqual(raised.exception.code, "CLEANUP_INCOMPLETE")
        self.assertEqual(self.lifecycle.created, [])

    def test_invalid_configuration_is_rejected(self) -> None:
        cases = (
            (object(), self.lifecycle, self.profile, timedelta(hours=1), lambda: NOW),
            (self.docker, object(), self.profile, timedelta(hours=1), lambda: NOW),
            (self.docker, self.lifecycle, object(), timedelta(hours=1), lambda: NOW),
            (
                self.docker,
                self.lifecycle,
                self.profile,
                timedelta(seconds=59),
                lambda: NOW,
            ),
            (self.docker, self.lifecycle, self.profile, 3600, lambda: NOW),
            (self.docker, self.lifecycle, self.profile, timedelta(hours=1), None),
        )
        for docker, lifecycle, chosen, max_age, now in cases:
            with (
                self.subTest(max_age=max_age),
                self.assertRaises(QualificationError) as raised,
            ):
                QualificationCollector(
                    docker, lifecycle, chosen, max_age=max_age, now=now
                )
            self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")

    def test_operator_lines_carry_digests_and_reasons_only(self) -> None:
        collection = self.collector().collect()
        report = collection.report
        denied = evaluate_qualification(
            report.context, report, now=NOW, max_age=timedelta(hours=1)
        )

        lines = format_collection(collection, denied)
        passed = format_collection(collection, QualificationDecision(()))

        self.assertEqual(len(lines), 20)
        self.assertRegex(
            lines[0],
            r"^QUALIFICATION_CONTEXT engine_id=engine-1 host_boot_id=\S+ "
            r"daemon_epoch=\S+ configuration_digest=sha256:[0-9a-f]{64} "
            r"image_digest=sha256:[0-9a-f]{64} profile_digest=sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(
            lines[1],
            "CHECK unprivileged_identity PASS 2026-10-08T10:14:00+00:00 "
            + report.results[0].evidence_digest,
        )
        self.assertTrue(lines[13].endswith(" reason=NOT_COLLECTED"))
        self.assertEqual(
            lines[-1],
            "QUALIFICATION_DENIED "
            + " ".join(f"CHECK_UNVERIFIED:{check.value}" for check in SCENARIO_CHECKS),
        )
        self.assertEqual(passed[-1], "QUALIFICATION_PASSED")
        self.assertIsNone(re.search(r"[\x00-\x1f]", "".join(lines)))


if __name__ == "__main__":
    unittest.main()
