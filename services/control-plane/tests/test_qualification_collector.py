import copy
import math
import re
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
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
from failroom_sandbox.pty import PtyError
from failroom_sandbox.qualification import evaluate_qualification

from failroom_control_plane.qualification_collector import (
    QUALIFICATION_ATTEMPT,
    QualificationCollector,
    QualificationError,
    format_collection,
)
from failroom_control_plane.qualification_scenarios import TERMINAL_CHECKS

NOW = datetime(2026, 10, 8, 10, 14, tzinfo=UTC)
STARTED_AT = "2026-10-08T10:14:00.951523267Z"
BOOT_ID = "39838d7c-98d9-4c41-9181-b3baadabb0c6"
IMAGE_ID = "sha256:" + "d" * 64
UNCOLLECTED = (Check.RESTART_CLEANUP,)


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
        "terminal_output_limit_bytes": 4096,
        "connection_limit": 2,
        "session_limit": 2,
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


def docker_time(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def container(binding, operation_id, lifetime, *, status="running", created=None):
    return {
        "Image": IMAGE_ID,
        "Created": created or STARTED_AT,
        "State": {
            "Status": status,
            "Running": status == "running",
            "StartedAt": STARTED_AT,
            "FinishedAt": "0001-01-01T00:00:00Z",
            "ExitCode": 0,
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


class Clock:
    """Monotonic time that moves only when the code under test sleeps."""

    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class ProcessTable:
    """The process list of one fake sandbox, keyed by shell session."""

    def __init__(self) -> None:
        self.sessions: dict[int, list[tuple[int, str]]] = {}
        self.keep_after_close = False
        self.malformed = False

    def list_sandbox_processes(self, container_id: str) -> bytes:
        if self.malformed:
            return b"process=one\nend=1\n"
        lines = ["process=1 S 1", "process=7 S 1"]
        for shell, members in self.sessions.items():
            lines += [f"process={pid} {state} {shell}" for pid, state in members]
        return ("\n".join(lines) + "\nend=1\n").encode("ascii")


class FakeSession:
    """Mimic the Docker PTY session's cumulative output accounting."""

    def __init__(self, runtime: "FakeTerminalRuntime") -> None:
        self.runtime = runtime
        self.pending = b""
        self.output = 0
        self.shell: int | None = None
        self.closed = False

    def write(self, data: bytes) -> None:
        size = re.search(rb"head -c ([0-9]+)", data)
        if size and self.runtime.produce_output:
            self.pending += b"x" * int(size.group(1))
        if b"FAILROOM_SHELL" in data:
            self.shell = self.runtime.next_shell
            self.runtime.next_shell += 10
            if self.runtime.report_shell:
                self.pending += b"\x1b[32mFAILROOM_SHELL=%d\x1b[0m\r\n" % self.shell
            members = [(self.shell + index, "S") for index in range(3)]
            self.runtime.processes.sessions[self.shell] = members[
                : self.runtime.members
            ]

    def read(self, maximum: int) -> bytes:
        limit = self.runtime.limit
        if self.runtime.enforce_output and self.output >= limit:
            self.close()
            raise PtyError("OUTPUT_LIMIT")
        allowed = limit - self.output if self.runtime.enforce_output else maximum
        data = self.pending[: min(maximum, allowed)]
        self.pending = self.pending[len(data) :]
        self.output += len(data)
        return data

    def resize(self, rows: int, columns: int) -> None:
        return None

    def signal(self, value: int) -> None:
        return None

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.shell is not None and not self.runtime.processes.keep_after_close:
            self.runtime.processes.sessions.pop(self.shell, None)


class FakeTerminalRuntime:
    def __init__(self, processes: ProcessTable, limit: int) -> None:
        self.processes = processes
        self.limit = limit
        self.produce_output = True
        self.enforce_output = True
        self.report_shell = True
        self.members = 3
        self.next_shell = 42
        self.open_error: Exception | None = None
        self.opened: list[tuple[str, tuple[str, ...]]] = []

    def open(self, container_id: str, *, command: tuple[str, ...]) -> FakeSession:
        if self.open_error is not None:
            raise self.open_error
        self.opened.append((container_id, command))
        return FakeSession(self)


class FakeDocker:
    def __init__(self, processes: ProcessTable) -> None:
        self.containers: dict[str, dict] = {}
        self.listed: tuple[str, ...] = ()
        self.probe_output = probe_output(60)
        self.probe_error: Exception | None = None
        self.processes = processes
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

    def list_sandbox_processes(self, container_id: str) -> bytes:
        return self.processes.list_sandbox_processes(container_id)

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
        # How the short-lived lifetime sandbox ends: (running, exit code, seconds).
        self.lifetime_end: tuple[bool, int, float] = (False, 0, 4.2)

    def create_diagnostic(self, profile, binding, operation_id, *, lifetime):
        remaining = (lifetime.deadline - lifetime.now()).total_seconds()
        seconds = min(math.floor(remaining) - 10, profile.absolute_ttl_seconds - 10)
        container_id = f"{len(self.docker.containers) + 1:064x}"
        data = container(binding, operation_id, seconds)
        if binding.sandbox_id.startswith("sentinel-"):
            data["State"]["Status"] = self.sentinel_status
            data["State"]["Running"] = self.sentinel_status == "running"
        if binding.sandbox_id.startswith("lifetime-"):
            running, exit_code, ended = self.lifetime_end
            data["State"].update(
                Status="running" if running else "exited",
                Running=running,
                ExitCode=exit_code,
                FinishedAt=docker_time(NOW + timedelta(seconds=ended)),
            )
        self.docker.containers[container_id] = data
        self.created.append((binding, operation_id, lifetime, container_id))
        return ContainerObservation(container_id, True, "sha256:" + "e" * 64)

    def destroy(self, binding, container_id, *, operation_id=None):
        if self.destroy_error is not None:
            raise self.destroy_error
        self.destroyed.append((binding, container_id, operation_id))
        self.docker.containers.pop(container_id, None)
        return "sha256:" + "f" * 64


class Harness:
    """One collector with fakes, a scratch directory and a manual clock."""

    def __init__(self, test: unittest.TestCase) -> None:
        scratch = tempfile.TemporaryDirectory()
        test.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name)
        self.profile = profile()
        self.processes = ProcessTable()
        self.terminal = FakeTerminalRuntime(
            self.processes, self.profile.terminal_output_limit_bytes
        )
        self.docker = FakeDocker(self.processes)
        self.lifecycle = FakeLifecycle(self.docker)
        self.clock = Clock()

    def collector(self, *, max_age=timedelta(hours=1), scratch=None):
        return QualificationCollector(
            self.docker,
            self.lifecycle,
            self.profile,
            max_age=max_age,
            now=lambda: NOW,
            terminal=self.terminal,
            scratch=scratch or self.scratch,
            busy_timeout_ms=5000,
            monotonic=self.clock.monotonic,
            sleep=self.clock.sleep,
        )


class QualificationCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(self)
        self.docker = self.harness.docker
        self.lifecycle = self.harness.lifecycle
        self.profile = self.harness.profile

    def collector(self, **kwargs) -> QualificationCollector:
        return self.harness.collector(**kwargs)

    def test_collects_everything_but_restart_cleanup(self) -> None:
        collection = self.collector().collect()
        report = collection.report

        self.assertEqual(tuple(result.check for result in report.results), tuple(Check))
        for result in report.results:
            with self.subTest(check=result.check):
                expected = (
                    Outcome.UNVERIFIED if result.check in UNCOLLECTED else Outcome.PASS
                )
                self.assertIs(result.outcome, expected)
                self.assertEqual(result.observed_at, NOW)
                self.assertRegex(result.evidence_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            dict(collection.reasons), {check: "NOT_COLLECTED" for check in UNCOLLECTED}
        )
        decision = evaluate_qualification(
            report.context, report, now=NOW, max_age=timedelta(hours=1)
        )
        self.assertEqual(
            {(denial.code, denial.check) for denial in decision.denials},
            {(DenialCode.CHECK_UNVERIFIED, check) for check in UNCOLLECTED},
        )
        self.assertEqual(list(self.harness.scratch.iterdir()), [])

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

        created = self.lifecycle.created
        roles = ("sentinel", "lifetime", "probe")
        for (binding, _, _, _), role in zip(created, roles, strict=True):
            self.assertEqual(binding.attempt_id, QUALIFICATION_ATTEMPT)
            self.assertRegex(binding.sandbox_id, rf"^{role}-[0-9a-f]{{32}}$")
            self.assertEqual(binding.generation, 1)
        self.assertEqual(
            [life.deadline - NOW for _, _, life, _ in created],
            [timedelta(seconds=300), timedelta(seconds=15), timedelta(seconds=70)],
        )
        self.assertEqual(
            self.lifecycle.destroyed,
            [
                (binding, container_id, operation)
                for binding, operation, _, container_id in reversed(created)
            ],
        )
        self.assertEqual(self.docker.containers, {})
        probe_id = created[2][3]
        self.assertTrue(self.harness.terminal.opened)
        self.assertTrue(
            all(
                opened == (probe_id, ("/bin/bash",))
                for opened in self.harness.terminal.opened
            )
        )

    def test_sentinel_lifetime_is_the_report_validity_within_the_profile(self) -> None:
        self.collector(max_age=timedelta(seconds=120)).collect()

        self.assertEqual(
            self.lifecycle.created[0][2].deadline - NOW, timedelta(seconds=130)
        )

    def test_lifetime_scenario_requires_pid1_to_end_by_the_deadline(self) -> None:
        cases = (
            ((True, 0, 0.0), Outcome.FAIL, "LIFETIME_NOT_ENFORCED"),
            ((False, 137, 4.2), Outcome.UNVERIFIED, "UNEXPECTED_EXIT"),
            ((False, 0, 15.5), Outcome.FAIL, "DEADLINE_EXCEEDED"),
            ((False, 0, 14.9), Outcome.PASS, ""),
        )
        for end, outcome, reason in cases:
            with self.subTest(end=end):
                self.setUp()
                self.lifecycle.lifetime_end = end
                collection = self.collector().collect()
                result = collection.report.results[
                    tuple(Check).index(Check.ABSOLUTE_TTL)
                ]
                self.assertIs(result.outcome, outcome)
                self.assertEqual(collection.reasons.get(Check.ABSOLUTE_TTL, ""), reason)

    def test_terminal_scenario_failure_is_unverified_not_fatal(self) -> None:
        missing = self.harness.scratch / "missing"

        collection = self.collector(scratch=missing).collect()

        for check in TERMINAL_CHECKS:
            with self.subTest(check=check):
                result = collection.report.results[tuple(Check).index(check)]
                self.assertIs(result.outcome, Outcome.UNVERIFIED)
                self.assertEqual(collection.reasons[check], "SCENARIO_UNAVAILABLE")
        self.assertEqual(len(self.lifecycle.destroyed), 3)

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
                self.assertEqual(len(self.lifecycle.destroyed), 3)
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

        self.assertEqual(
            self.lifecycle.destroyed[:3],
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
        harness = self.harness
        valid = {
            "max_age": timedelta(hours=1),
            "now": lambda: NOW,
            "terminal": harness.terminal,
            "scratch": harness.scratch,
            "busy_timeout_ms": 5000,
        }
        cases = (
            ((object(), self.lifecycle, self.profile), {}),
            ((self.docker, object(), self.profile), {}),
            ((self.docker, self.lifecycle, object()), {}),
            (
                (self.docker, self.lifecycle, self.profile),
                {"max_age": timedelta(seconds=59)},
            ),
            ((self.docker, self.lifecycle, self.profile), {"max_age": 3600}),
            ((self.docker, self.lifecycle, self.profile), {"now": None}),
            ((self.docker, self.lifecycle, self.profile), {"terminal": object()}),
            (
                (self.docker, self.lifecycle, self.profile),
                {"scratch": Path("relative")},
            ),
            ((self.docker, self.lifecycle, self.profile), {"scratch": "/tmp"}),
            ((self.docker, self.lifecycle, self.profile), {"busy_timeout_ms": 0}),
            ((self.docker, self.lifecycle, self.profile), {"sleep": None}),
        )
        for arguments, changes in cases:
            with (
                self.subTest(changes=changes),
                self.assertRaises(QualificationError) as raised,
            ):
                QualificationCollector(*arguments, **{**valid, **changes})
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
        self.assertTrue(lines[18].startswith("CHECK restart_cleanup UNVERIFIED "))
        self.assertTrue(lines[18].endswith(" reason=NOT_COLLECTED"))
        self.assertEqual(
            lines[-1], "QUALIFICATION_DENIED CHECK_UNVERIFIED:restart_cleanup"
        )
        self.assertEqual(passed[-1], "QUALIFICATION_PASSED")
        self.assertIsNone(re.search(r"[\x00-\x1f]", "".join(lines)))


if __name__ == "__main__":
    unittest.main()
