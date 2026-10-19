import copy
import math
import re
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from unittest import mock

from failroom_sandbox.docker_cli import ContainerExit, DockerError, EngineIdentity
from failroom_sandbox.docker_lifecycle import ContainerObservation, CreatedContainer
from failroom_sandbox.docker_profile import (
    DockerBinding,
    StrictDockerProfile,
    profile_fingerprint,
)
from failroom_sandbox.models import (
    Check,
    Outcome,
    QualificationDecision,
)
from failroom_sandbox.pty import PtyError
from failroom_sandbox.qualification import evaluate_qualification
from failroom_state import RuntimeCleanupError

from failroom_control_plane.qualification_collector import (
    QUALIFICATION_ATTEMPT_PREFIX,
    QualificationCollector,
    QualificationError,
    format_collection,
)
from failroom_control_plane.qualification_restart import (
    RESTART_DIRECTORY,
    RestartScenario,
)
from failroom_control_plane.qualification_scenarios import (
    TERMINAL_CHECKS,
    TerminalScenarios,
)
from failroom_control_plane.qualification_workspace import (
    ID_NAME,
    WorkspaceError,
    workspace_id,
)

NOW = datetime(2026, 10, 8, 10, 14, tzinfo=UTC)
STARTED_AT = "2026-10-08T10:14:00.951523267Z"
BOOT_ID = "39838d7c-98d9-4c41-9181-b3baadabb0c6"
IMAGE_ID = "sha256:" + "d" * 64
CONTAINER_CHECKS = tuple(Check)[:12]


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


def binding_labels(binding: DockerBinding) -> dict[str, str]:
    return {
        "failroom.kind": "diagnostic",
        "failroom.attempt_id": binding.attempt_id,
        "failroom.sandbox_id": binding.sandbox_id,
        "failroom.generation": str(binding.generation),
    }


class Clock:
    """Time that moves only when the code under test sleeps."""

    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def now(self) -> datetime:
        return NOW + timedelta(seconds=self.value)

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
        self.next_id = 1
        self.probe_output = probe_output(60)
        self.probe_error: Exception | None = None
        self.list_error: Exception | None = None
        self.processes = processes
        self.engine = EngineIdentity(
            "engine-1",
            MappingProxyType({"ServerVersion": "29.4.2", "Runtimes": ["runc"]}),
        )
        self.filters: list[tuple[str, ...]] = []
        # What the runtime reports now, for the allocation gate's checks.
        self.image_id = IMAGE_ID
        self.boot_id = BOOT_ID
        self.io_device = "7:0"
        # When each sandbox's PID 1 exits: (clock seconds, exit code, removed).
        self.clock: Clock | None = None
        self.endings: dict[str, tuple[float, int, bool]] = {}
        self.exits: dict[str, ContainerExit] = {}
        self.record_exits = True
        self.exit_error: Exception | None = None
        self.on_exit_read = None

    def end_later(
        self, container_id: str, seconds: float, exit_code: int, *, removed: bool
    ) -> None:
        """PID 1 exits that long from now; Docker then removes the sandbox, or not."""
        start = self.clock.value if self.clock is not None else 0.0
        self.endings[container_id] = (start + seconds, exit_code, removed)

    def settle(self) -> None:
        """End every sandbox whose PID 1 is due, as Docker would."""
        if self.clock is None:
            return
        for cid, (due, exit_code, removed) in list(self.endings.items()):
            if self.clock.value < due:
                continue
            del self.endings[cid]
            if cid not in self.containers:
                continue
            finished = NOW + timedelta(seconds=due)
            if self.record_exits:
                self.exits[cid] = ContainerExit(exit_code, finished)
            if removed:
                del self.containers[cid]
            else:
                self.containers[cid]["State"].update(
                    Status="exited",
                    Running=False,
                    ExitCode=exit_code,
                    FinishedAt=docker_time(finished),
                )

    def container_exit(self, container_id: str, *, since, until):
        if self.on_exit_read is not None:
            self.on_exit_read()
        if self.exit_error is not None:
            raise self.exit_error
        self.settle()
        return self.exits.get(container_id)

    def allocate(self) -> str:
        self.next_id += 1
        return f"{self.next_id:064x}"

    def matching(self, labels: dict[str, str]) -> tuple[str, ...]:
        return tuple(
            cid
            for cid, data in self.containers.items()
            if all(
                data["Config"]["Labels"].get(key) == value
                for key, value in labels.items()
            )
        )

    def engine_identity(self) -> EngineIdentity:
        return self.engine

    def run_qualification_probe(self, container_id: str) -> bytes:
        if self.probe_error is not None:
            raise self.probe_error
        return self.probe_output

    def list_sandbox_processes(self, container_id: str) -> bytes:
        return self.processes.list_sandbox_processes(container_id)

    def read_runtime_identity(self, container_id: str) -> bytes:
        if container_id not in self.containers:
            raise DockerError("RUNTIME_UNAVAILABLE")
        return (
            f"boot_id={self.boot_id}\nio_max={self.io_device} rbps=1048576"
            " wbps=1048576 riops=max wiops=max\nend=1\n"
        ).encode("ascii")

    def inspect_image(self, image: str) -> dict:
        return {"Id": self.image_id}

    def inspect_container(self, selector: str):
        self.settle()
        return copy.deepcopy(self.containers.get(selector))

    def list_containers(self, filters):
        self.filters.append(filters)
        if self.list_error is not None:
            raise self.list_error
        return self.matching(
            dict(item.removeprefix("label=").split("=", 1) for item in filters)
        )


class FakeLifecycle:
    def __init__(self, docker: FakeDocker) -> None:
        self.docker = docker
        self.created: list = []
        self.profiles: list = []
        self.destroyed: list = []
        self.destroy_error: Exception | None = None
        # Refuse to destroy Room sandboxes, as when Docker cannot remove them.
        self.refuse_rooms = False
        self.sentinel_status = "running"
        # How the short-lived lifetime sandbox ends: (running, exit code, seconds).
        self.lifetime_end: tuple[bool, int, float] = (False, 0, 4.2)
        # Whether Docker removes it once PID 1 exits, as the strict profile asks.
        self.lifetime_removed = True

    def create_diagnostic(self, profile, binding, operation_id, *, lifetime):
        remaining = (lifetime.deadline - lifetime.now()).total_seconds()
        seconds = min(math.floor(remaining) - 10, profile.absolute_ttl_seconds - 10)
        container_id = self.docker.allocate()
        data = container(binding, operation_id, seconds)
        if binding.sandbox_id.startswith("sentinel-"):
            data["State"]["Status"] = self.sentinel_status
            data["State"]["Running"] = self.sentinel_status == "running"
        self.docker.containers[container_id] = data
        if binding.sandbox_id.startswith("lifetime-"):
            running, exit_code, ended = self.lifetime_end
            if not running:
                self.docker.end_later(
                    container_id, ended, exit_code, removed=self.lifetime_removed
                )
        self.created.append((binding, operation_id, lifetime, container_id))
        self.profiles.append(profile)
        return ContainerObservation(container_id, True, "sha256:" + "e" * 64)

    def destroy(self, binding, container_id, *, operation_id=None):
        if self.destroy_error is not None:
            raise self.destroy_error
        if self.refuse_rooms and not binding.attempt_id.startswith(
            QUALIFICATION_ATTEMPT_PREFIX
        ):
            raise DockerError("CLEANUP_INCOMPLETE")
        self.destroyed.append((binding, container_id, operation_id))
        for cid in (
            (container_id,)
            if container_id
            else self.docker.matching(binding_labels(binding))
        ):
            self.docker.containers.pop(cid, None)
        return "sha256:" + "f" * 64


class FakeRoomSession:
    def __init__(self, rooms: "FakeRooms", binding, operation_id, lifetime) -> None:
        self.rooms = rooms
        self.binding = binding
        self.operation_id = operation_id
        self.lifetime = lifetime

    def create_verified(self) -> CreatedContainer:
        if self.rooms.create_error is not None:
            raise self.rooms.create_error
        remaining = (self.lifetime.deadline - self.lifetime.now()).total_seconds()
        container_id = self.rooms.docker.allocate()
        self.rooms.docker.containers[container_id] = container(
            self.binding, self.operation_id, math.floor(remaining) - 10
        )
        return CreatedContainer(container_id, False)

    def start_verified(self, created: CreatedContainer) -> ContainerObservation:
        if self.rooms.start_error is not None:
            raise self.rooms.start_error
        return ContainerObservation(created.container_id, True, "sha256:" + "c" * 64)


class FakeRooms:
    """Provision Room sandboxes into the fake Docker inventory."""

    def __init__(self, docker: FakeDocker) -> None:
        self.docker = docker
        self.opened: list = []
        self.create_error: Exception | None = None
        self.start_error: Exception | None = None

    @contextmanager
    def open(self, binding, runtime_operation_id, room_id, *, lifetime):
        self.opened.append((binding, runtime_operation_id, room_id, lifetime))
        yield FakeRoomSession(self, binding, runtime_operation_id, lifetime)


class FakeCleanup:
    """Remove Room sandboxes as the Docker cleanup runtime does, or not."""

    def __init__(self, docker: FakeDocker) -> None:
        self.docker = docker
        self.targets: list = []
        self.remove = True
        self.error: Exception | None = None

    def destroy_and_verify_absent(self, target) -> str:
        self.targets.append(target)
        if self.remove:
            binding = DockerBinding(
                target.ref.attempt_id, target.ref.sandbox_id, target.ref.generation
            )
            for cid in self.docker.matching(binding_labels(binding)):
                del self.docker.containers[cid]
        if self.error is not None:
            raise self.error
        return "sha256:" + "9" * 64


class FakeWorkspace:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.error: Exception | None = None
        self.holds = 0
        self.releases = 0

    @contextmanager
    def hold(self):
        if self.error is not None:
            raise self.error
        self.holds += 1
        try:
            yield self.path
        finally:
            self.releases += 1


class Harness:
    """One collector with fakes, a scratch workspace and a manual clock."""

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
        self.rooms = FakeRooms(self.docker)
        self.cleanup = FakeCleanup(self.docker)
        self.workspace = FakeWorkspace(self.scratch)
        self.clock = Clock()
        self.docker.clock = self.clock

    def collector(self, *, max_age=timedelta(hours=1), workspace=None):
        return QualificationCollector(
            self.docker,
            self.lifecycle,
            self.profile,
            max_age=max_age,
            now=self.clock.now,
            terminal=self.terminal,
            provisioning=self.rooms,
            cleanup=self.cleanup,
            workspace=workspace or self.workspace,
            busy_timeout_ms=5000,
            monotonic=self.clock.monotonic,
            sleep=self.clock.sleep,
        )

    def restart(self) -> RestartScenario:
        return RestartScenario(
            self.docker,
            self.lifecycle,
            self.rooms,
            self.cleanup,
            busy_timeout_ms=5000,
            now=self.clock.now,
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

    def result(self, collection, check):
        return collection.report.results[tuple(Check).index(check)]

    def attempt(self) -> str:
        """This workspace's attempt label; reading it creates the ID once."""
        return QUALIFICATION_ATTEMPT_PREFIX + workspace_id(self.harness.scratch)

    def scratch_entries(self) -> list[str]:
        return sorted(entry.name for entry in self.harness.scratch.iterdir())

    def test_collects_every_check(self) -> None:
        collection = self.collector().collect()
        report = collection.report

        self.assertEqual(tuple(result.check for result in report.results), tuple(Check))
        for result in report.results:
            with self.subTest(check=result.check):
                self.assertIs(result.outcome, Outcome.PASS)
                self.assertRegex(result.evidence_digest, r"^sha256:[0-9a-f]{64}$")
                if result.check in CONTAINER_CHECKS:
                    self.assertEqual(result.observed_at, NOW)
                else:
                    self.assertGreaterEqual(result.observed_at, NOW)
        self.assertEqual(dict(collection.reasons), {})
        decision = evaluate_qualification(
            report.context,
            report,
            now=self.harness.clock.now(),
            max_age=timedelta(hours=1),
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(self.harness.workspace.holds, 1)
        # Only the workspace ID stays.
        self.assertEqual(self.scratch_entries(), [ID_NAME])

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
            self.assertEqual(binding.attempt_id, self.attempt())
            self.assertRegex(binding.sandbox_id, rf"^{role}-[0-9a-f]{{32}}$")
            self.assertEqual(binding.generation, 1)
        self.assertEqual(
            [life.deadline - NOW for _, _, life, _ in created],
            [timedelta(seconds=3610), timedelta(seconds=15), timedelta(seconds=70)],
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

    def test_restart_scenario_enters_a_room_that_the_restart_removes(self) -> None:
        collection = self.collector().collect()

        ((binding, operation, room, lifetime),) = self.harness.rooms.opened
        self.assertEqual(room, "disk-full")
        self.assertFalse(binding.attempt_id.startswith(QUALIFICATION_ATTEMPT_PREFIX))
        self.assertEqual(lifetime.deadline - NOW, timedelta(seconds=20))
        (target,) = self.harness.cleanup.targets
        self.assertEqual(
            (target.ref.attempt_id, target.ref.sandbox_id, target.runtime_operation_id),
            (binding.attempt_id, binding.sandbox_id, operation),
        )
        # The restart waited for the attempt deadline before cleaning up.
        self.assertGreaterEqual(self.harness.clock.value, 20)
        self.assertEqual(self.docker.containers, {})
        self.assertIs(
            self.result(collection, Check.RESTART_CLEANUP).outcome, Outcome.PASS
        )

    def test_only_the_sentinel_lives_as_long_as_the_report_is_valid(self) -> None:
        for max_age, lifetime in ((120, 120), (3600, 3600)):
            with self.subTest(max_age=max_age):
                self.setUp()
                self.collector(max_age=timedelta(seconds=max_age)).collect()

                sentinel, *others = self.lifecycle.profiles
                # Beyond the attempt TTL of 300 seconds, as the epoch must last.
                self.assertEqual(
                    sentinel,
                    profile(absolute_ttl_seconds=lifetime + 10),
                )
                self.assertEqual(
                    self.lifecycle.created[0][2].deadline - NOW,
                    timedelta(seconds=lifetime + 10),
                )
                self.assertEqual(others, [self.profile, self.profile])

    def test_retained_sentinel_outlives_a_complete_collection(self) -> None:
        collection = self.collector().collect(retain_sentinel=True)

        binding, operation_id, _, container_id = self.lifecycle.created[0]
        self.assertEqual(
            (
                collection.sentinel.binding,
                collection.sentinel.operation_id,
                collection.sentinel.container_id,
            ),
            (binding, operation_id, container_id),
        )
        self.assertEqual(list(self.docker.containers), [container_id])
        self.assertNotIn(container_id, [cid for _, cid, _ in self.lifecycle.destroyed])
        self.assertIsNone(self.collector().collect().sentinel)

    def test_retained_sentinel_is_destroyed_when_the_collection_fails(self) -> None:
        self.docker.probe_output = b"probe=1\nend=1\n"

        with self.assertRaises(QualificationError):
            self.collector().collect(retain_sentinel=True)

        self.assertEqual(self.docker.containers, {})
        self.assertEqual(len(self.lifecycle.destroyed), 3)

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
                result = self.result(collection, Check.ABSOLUTE_TTL)
                self.assertIs(result.outcome, outcome)
                self.assertEqual(collection.reasons.get(Check.ABSOLUTE_TTL, ""), reason)

    def test_lifetime_scenario_requires_docker_to_remove_the_sandbox(self) -> None:
        self.lifecycle.lifetime_removed = False

        collection = self.collector().collect()

        result = self.result(collection, Check.ABSOLUTE_TTL)
        self.assertIs(result.outcome, Outcome.FAIL)
        self.assertEqual(collection.reasons[Check.ABSOLUTE_TTL], "SANDBOX_NOT_REMOVED")
        self.assertEqual(self.docker.containers, {})

    def test_lifetime_exit_that_docker_cannot_show_is_unverified(self) -> None:
        for name in ("no event", "events unavailable"):
            with self.subTest(case=name):
                self.setUp()
                if name == "no event":
                    self.docker.record_exits = False
                else:
                    self.docker.exit_error = DockerError("RUNTIME_UNAVAILABLE")

                collection = self.collector().collect()

                result = self.result(collection, Check.ABSOLUTE_TTL)
                self.assertIs(result.outcome, Outcome.UNVERIFIED)
                self.assertEqual(
                    collection.reasons[Check.ABSOLUTE_TTL], "LIFETIME_UNREADABLE"
                )

    def test_lifetime_exit_is_read_before_the_terminal_scenarios(self) -> None:
        # Docker keeps only its latest events, and the scenarios add many.
        opened_when_read: list[int] = []
        self.docker.on_exit_read = lambda: opened_when_read.append(
            len(self.harness.terminal.opened)
        )

        collection = self.collector().collect()

        self.assertEqual(opened_when_read, [0])
        self.assertTrue(self.harness.terminal.opened)
        self.assertIs(self.result(collection, Check.ABSOLUTE_TTL).outcome, Outcome.PASS)

    def test_terminal_scenario_failure_is_unverified_not_fatal(self) -> None:
        with mock.patch.object(
            TerminalScenarios, "run", side_effect=RuntimeError("provider detail")
        ):
            collection = self.collector().collect()

        for check in TERMINAL_CHECKS:
            with self.subTest(check=check):
                self.assertIs(
                    self.result(collection, check).outcome, Outcome.UNVERIFIED
                )
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
                self.assertEqual(self.scratch_entries(), [ID_NAME])

    def test_stopped_sentinel_has_no_daemon_epoch(self) -> None:
        self.lifecycle.sentinel_status = "exited"

        with self.assertRaises(QualificationError) as raised:
            self.collector().collect()

        self.assertEqual(raised.exception.code, "RUNTIME_UNAVAILABLE")
        self.assertEqual(len(self.lifecycle.created), 1)
        self.assertEqual(len(self.lifecycle.destroyed), 1)
        self.assertEqual(self.harness.rooms.opened, [])

    def test_cleanup_failure_is_reported_as_incomplete(self) -> None:
        self.lifecycle.destroy_error = DockerError("CLEANUP_INCOMPLETE")

        with self.assertRaises(QualificationError) as raised:
            self.collector().collect()

        self.assertEqual(raised.exception.code, "CLEANUP_INCOMPLETE")

    def test_restart_sandbox_that_cannot_be_removed_fails_the_collection(self) -> None:
        self.harness.cleanup.remove = False
        self.harness.cleanup.error = RuntimeCleanupError("CLEANUP_INCOMPLETE")
        self.lifecycle.refuse_rooms = True

        with self.assertRaises(QualificationError) as raised:
            self.collector().collect()

        self.assertEqual(raised.exception.code, "CLEANUP_INCOMPLETE")
        # The state stays for the next collection to recover.
        self.assertTrue((self.harness.scratch / RESTART_DIRECTORY).is_dir())
        self.assertEqual(len(self.docker.containers), 1)
        # Every collector sandbox is still destroyed.
        self.assertEqual(len(self.lifecycle.destroyed), 3)

    def test_workspace_failures_stop_before_any_docker_call(self) -> None:
        cases = {
            "COLLECTION_IN_PROGRESS": "COLLECTION_IN_PROGRESS",
            "WORKSPACE_UNSAFE": "INVALID_CONFIGURATION",
            "WORKSPACE_UNAVAILABLE": "RUNTIME_UNAVAILABLE",
        }
        for workspace_code, code in cases.items():
            with self.subTest(code=workspace_code):
                self.setUp()
                self.harness.workspace.error = WorkspaceError(workspace_code)
                with self.assertRaises(QualificationError) as raised:
                    self.collector().collect()
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(self.docker.filters, [])
                self.assertEqual(self.lifecycle.created, [])

    def test_what_a_crashed_collection_left_is_removed_first(self) -> None:
        scratch = self.harness.scratch
        (scratch / "terminal-stale").mkdir()
        (scratch / "terminal-stale" / "terminal.sqlite3").write_bytes(b"stale")
        (scratch / "collector.lock").write_bytes(b"")
        self.assertIsNone(self.harness.restart().begin(scratch))
        (leftover,) = self.docker.containers

        collection = self.collector().collect()

        self.assertNotIn(leftover, self.docker.containers)
        # The leftover is cleaned up first, before this collection's own Room.
        self.assertEqual(
            self.harness.cleanup.targets[0].ref.attempt_id,
            self.harness.rooms.opened[0][0].attempt_id,
        )
        self.assertEqual(len(self.harness.rooms.opened), 2)
        self.assertEqual(self.scratch_entries(), ["collector.lock", ID_NAME])
        self.assertTrue(
            all(result.outcome is Outcome.PASS for result in collection.report.results)
        )

    def test_sweep_removes_every_leftover_collector_sandbox(self) -> None:
        def leftover(name, status, created=None):
            binding = DockerBinding(self.attempt(), name, 1)
            cid = self.docker.allocate()
            self.docker.containers[cid] = container(
                binding, "op-" + name, 5, status=status, created=created
            )
            return cid, binding

        leftovers = (
            leftover("probe-exited", "exited"),
            leftover("probe-dead", "dead"),
            leftover("probe-running", "running"),
            leftover("probe-created", "created", "2026-10-08T10:13:59Z"),
        )

        self.collector().collect()

        self.assertEqual(
            self.lifecycle.destroyed[: len(leftovers)],
            [(binding, cid, "op-" + binding.sandbox_id) for cid, binding in leftovers],
        )
        self.assertEqual(
            self.docker.filters[0],
            (
                "label=failroom.kind=diagnostic",
                "label=failroom.attempt_id=" + self.attempt(),
            ),
        )
        self.assertEqual(self.docker.containers, {})

    def test_sweep_keeps_the_sentinels_the_caller_still_uses(self) -> None:
        sandboxes = {}
        for name in ("sentinel-kept", "sentinel-stale"):
            cid = self.docker.allocate()
            self.docker.containers[cid] = container(
                DockerBinding(self.attempt(), name, 1), "op-" + name, 300
            )
            sandboxes[name] = cid

        self.collector().collect(keep=frozenset({sandboxes["sentinel-kept"]}))

        self.assertIn(sandboxes["sentinel-kept"], self.docker.containers)
        self.assertNotIn(sandboxes["sentinel-stale"], self.docker.containers)

    def test_sweep_leaves_other_workspaces_sandboxes_alone(self) -> None:
        others = {}
        # Another workspace's running collection, and the label older
        # collections used before their workspace had an ID.
        for attempt in (QUALIFICATION_ATTEMPT_PREFIX + "f" * 32, "qualification"):
            cid = self.docker.allocate()
            others[cid] = container(
                DockerBinding(attempt, "sentinel-" + "a" * 32, 1), "op", 300
            )
        self.docker.containers.update(copy.deepcopy(others))

        self.collector().collect()

        self.assertEqual(self.docker.containers, others)
        self.assertNotIn(
            True,
            [cid in others for _, cid, _ in self.lifecycle.destroyed],
        )

    def test_unreadable_workspace_id_stops_before_any_docker_call(self) -> None:
        (self.harness.scratch / ID_NAME).write_bytes(b"not-an-id\n")

        with self.assertRaises(QualificationError) as raised:
            self.collector().collect()

        self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")
        self.assertEqual(self.docker.filters, [])

    def test_sweep_refuses_leftovers_without_exact_labels(self) -> None:
        binding = DockerBinding(self.attempt(), "probe-broken", 1)
        data = container(binding, "op", 5, status="exited")
        data["Config"]["Labels"]["failroom.generation"] = "one"
        self.docker.containers["a" * 64] = data

        with self.assertRaises(QualificationError) as raised:
            self.collector().collect()

        self.assertEqual(raised.exception.code, "CLEANUP_INCOMPLETE")
        self.assertEqual(self.lifecycle.created, [])

    def test_invalid_configuration_is_rejected(self) -> None:
        harness = self.harness
        valid = {
            "max_age": timedelta(hours=1),
            "now": harness.clock.now,
            "terminal": harness.terminal,
            "provisioning": harness.rooms,
            "cleanup": harness.cleanup,
            "workspace": harness.workspace,
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
            ((self.docker, self.lifecycle, self.profile), {"provisioning": object()}),
            ((self.docker, self.lifecycle, self.profile), {"cleanup": object()}),
            ((self.docker, self.lifecycle, self.profile), {"workspace": object()}),
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
        self.lifecycle.lifetime_end = (False, 0, 15.5)
        collection = self.collector().collect()
        report = collection.report
        denied = evaluate_qualification(
            report.context,
            report,
            now=self.harness.clock.now(),
            max_age=timedelta(hours=1),
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
        self.assertTrue(lines[16].startswith("CHECK absolute_ttl FAIL "))
        self.assertTrue(lines[16].endswith(" reason=DEADLINE_EXCEEDED"))
        self.assertRegex(
            lines[18], r"^CHECK restart_cleanup PASS \S+ sha256:[0-9a-f]{64}$"
        )
        self.assertEqual(lines[-1], "QUALIFICATION_DENIED CHECK_FAILED:absolute_ttl")
        self.assertEqual(passed[-1], "QUALIFICATION_PASSED")
        self.assertIsNone(re.search(r"[\x00-\x1f]", "".join(lines)))


if __name__ == "__main__":
    unittest.main()
