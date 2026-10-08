"""Fixed in-sandbox qualification probe and trusted judgement of its output.

The probe runs inside a verified diagnostic sandbox as its configured user
through one fixed Docker exec command. It reads kernel-reported facts and makes
one bounded write that must hit the workspace tmpfs limit. It relies on the
reviewed image's ``/bin/sh``, coreutils, ``sed``, ``awk``, ``find``,
``timeout`` and ``bash``. The trusted control plane parses the bounded output
strictly and judges it against the exact profile and the host-side inspect
document: contradicting facts FAIL, facts that cannot be read are UNVERIFIED.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .docker_profile import StrictDockerProfile, _cpu_nanocpus
from .models import Check, Outcome

PROBE_SCRIPT = r"""LC_ALL=C
PATH=/usr/bin:/bin
export LC_ALL PATH
field() { sed -n "s/^$1:[[:space:]]*//p" /proc/self/status; }
size_of() {
  set -- $(stat -f -c '%b %S' "$1" 2>/dev/null)
  if [ "$#" -eq 2 ]; then echo $(($1 * $2)); else echo unavailable; fi
}
echo "probe=1"
echo "uid=$(id -u)"
echo "gid=$(id -g)"
echo "groups=$(id -G)"
for name in CapInh CapPrm CapEff CapBnd CapAmb NoNewPrivs Seccomp Seccomp_filters; do
  echo "status_$name=$(field "$name")"
done
echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
for stat in /proc/[0-9]*/stat; do
  read -r line 2>/dev/null <"$stat" || continue
  pid=${line%% *}
  rest=${line##*") "}
  set -- $rest
  command=$(tr '\000\n' '  ' <"/proc/$pid/cmdline" 2>/dev/null | cut -d ' ' -f 1-4)
  printf 'process=%s %s %s\n' "$pid" "$2" "$command"
done
while read -r id parent dev root point opts rest; do
  fs=${rest#*- }
  fs=${fs%% *}
  case $root in /null) origin=null ;; /) origin=root ;; *) origin=other ;; esac
  printf 'mount=%s %s %s %s\n' "$point" "$fs" "$opts" "$origin"
done </proc/self/mountinfo
for iface in /sys/class/net/*; do echo "net_iface=${iface##*/}"; done
echo "default_route=$(awk 'NR > 1 && $2 == "00000000" {n++} END {print n + 0}' \
  /proc/net/route 2>/dev/null)"
timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/80' 2>/dev/null
echo "tcp_connect=$?"
for path in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock \
  /var/run/containerd/containerd.sock /run/podman/podman.sock \
  /var/run/podman/podman.sock /run/crio/crio.sock /var/run/crio/crio.sock \
  /run/buildkit/buildkitd.sock /var/run/cri-dockerd.sock; do
  if [ -e "$path" ]; then echo "runtime_socket=$path"; fi
done
sockets=$(find / \( -path /proc -o -path /sys \) -prune -o -type s -print 2>/dev/null)
echo "socket_files=$(printf '%s' "$sockets" | grep -c .)"
for file in cpu.max memory.max memory.swap.max pids.max; do
  echo "cgroup_$file=$(cat "/sys/fs/cgroup/$file" 2>/dev/null)"
done
{ cat /sys/fs/cgroup/io.max 2>/dev/null || true; } | while read -r line; do
  echo "io_max=$line"
done
echo "fd_soft=$(ulimit -Sn)"
echo "fd_hard=$(ulimit -Hn)"
for point in /workspace /tmp /run/failroom-target /dev/shm; do
  echo "fs_size=$point $(size_of "$point")"
done
workspace=$(size_of /workspace)
case $workspace in
  unavailable) echo "workspace_overfill=unavailable" ;;
  *)
    error=$(head -c $((workspace + 1048576)) /dev/zero 2>&1 \
      >/workspace/.failroom-qualification-fill)
    status=$?
    rm -f /workspace/.failroom-qualification-fill
    case $error in *"No space left on device"*) enospc=1 ;; *) enospc=0 ;; esac
    echo "workspace_overfill=$status $enospc"
    ;;
esac
echo "end=1"
"""

CONTAINER_CHECKS = (
    Check.UNPRIVILEGED_IDENTITY,
    Check.SYSCALL_RESTRICTIONS,
    Check.FILESYSTEM_ISOLATION,
    Check.PROCESS_ISOLATION,
    Check.HOST_ACCESS_ABSENCE,
    Check.NETWORK_ISOLATION,
    Check.CPU_LIMIT,
    Check.MEMORY_AND_SWAP_LIMIT,
    Check.PID_LIMIT,
    Check.STORAGE_LIMIT,
    Check.IO_LIMIT,
    Check.FILE_DESCRIPTOR_LIMIT,
)

_SINGLE_KEYS = frozenset(
    {
        "probe",
        "uid",
        "gid",
        "groups",
        "status_CapInh",
        "status_CapPrm",
        "status_CapEff",
        "status_CapBnd",
        "status_CapAmb",
        "status_NoNewPrivs",
        "status_Seccomp",
        "status_Seccomp_filters",
        "boot_id",
        "default_route",
        "tcp_connect",
        "socket_files",
        "cgroup_cpu.max",
        "cgroup_memory.max",
        "cgroup_memory.swap.max",
        "cgroup_pids.max",
        "fd_soft",
        "fd_hard",
        "workspace_overfill",
        "end",
    }
)
_MULTIPLE_KEYS = frozenset(
    {"process", "mount", "net_iface", "runtime_socket", "io_max", "fs_size"}
)
_LINE = re.compile(r"([A-Za-z_.]{1,32})=([ -~]{0,512})")
_MAX_LINES = 512
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_IO_MAX = re.compile(
    r"([0-9]{1,10}:[0-9]{1,10}) rbps=([0-9]{1,19}|max) wbps=([0-9]{1,19}|max)"
    r" riops=([0-9]{1,19}|max) wiops=([0-9]{1,19}|max)"
)
_CAPABILITIES = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
_SCRATCH_MOUNTS = frozenset({"/workspace", "/tmp", "/run/failroom-target"})
_DOCKER_FILES = frozenset({"/etc/hostname", "/etc/hosts", "/etc/resolv.conf"})
_INIT_MOUNTS = frozenset({"/sbin/docker-init", "/usr/sbin/docker-init"})
# Docker's default masked and read-only proc/sys paths; masks exist only for
# paths the host kernel provides.
_MASKED_PATHS = frozenset(
    {
        "/proc/asound",
        "/proc/acpi",
        "/proc/interrupts",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/sys/firmware",
        "/sys/devices/virtual/powercap",
    }
)
_READONLY_PATHS = frozenset(
    {"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}
)
_FIXED_MOUNTS = {
    "/proc": ("proc", frozenset({"nosuid", "nodev", "noexec"})),
    "/dev": ("tmpfs", frozenset({"nosuid"})),
    "/dev/pts": ("devpts", frozenset({"nosuid", "noexec"})),
    "/dev/mqueue": ("mqueue", frozenset({"nosuid", "nodev", "noexec"})),
    "/dev/shm": ("tmpfs", frozenset({"nosuid", "nodev", "noexec"})),
    "/sys": ("sysfs", frozenset({"ro"})),
    "/sys/fs/cgroup": ("cgroup2", frozenset({"ro"})),
}
_REQUIRED_MOUNTS = frozenset({"/", "/proc", "/dev", "/sys", "/dev/shm"})
_RUNTIME_PAGE_SLACK = 65_536


class ProbeOutputError(ValueError):
    """The probe output did not match the fixed format."""

    def __init__(self) -> None:
        super().__init__("INVALID_PROBE_OUTPUT")


@dataclass(frozen=True)
class ProbeObservation:
    """Strictly parsed probe facts; values are unverified until judged."""

    single: Mapping[str, str]
    multiple: Mapping[str, tuple[str, ...]]

    @property
    def boot_id(self) -> str | None:
        value = self.single["boot_id"]
        return value if _BOOT_ID.fullmatch(value) else None

    @property
    def io_device(self) -> str | None:
        lines = self.multiple["io_max"]
        if len(lines) != 1:
            return None
        match = _IO_MAX.fullmatch(lines[0])
        return match.group(1) if match else None


@dataclass(frozen=True)
class Judgement:
    """One check outcome with a fixed reason code and JSON-ready facts."""

    check: Check
    outcome: Outcome
    reason: str
    facts: Mapping[str, object]


def parse_probe_output(stdout: bytes) -> ProbeObservation:
    """Accept only the fixed key set, each single key once, ending with end=1."""
    try:
        text = stdout.decode("ascii")
    except UnicodeError:
        raise ProbeOutputError() from None
    if not text.endswith("\n"):
        raise ProbeOutputError()
    lines = text[:-1].split("\n")
    if len(lines) > _MAX_LINES or lines[0] != "probe=1" or lines[-1] != "end=1":
        raise ProbeOutputError()
    single: dict[str, str] = {}
    multiple: dict[str, list[str]] = {key: [] for key in _MULTIPLE_KEYS}
    for line in lines:
        match = _LINE.fullmatch(line)
        if match is None:
            raise ProbeOutputError()
        key, value = match.groups()
        if key in _MULTIPLE_KEYS:
            multiple[key].append(value)
        elif key in _SINGLE_KEYS and key not in single:
            single[key] = value
        else:
            raise ProbeOutputError()
    if set(single) != _SINGLE_KEYS:
        raise ProbeOutputError()
    return ProbeObservation(
        MappingProxyType(single),
        MappingProxyType({key: tuple(values) for key, values in multiple.items()}),
    )


class _Unverified(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


_Evaluation = tuple[list[str], dict[str, object]]


def _number(value: str, reason: str) -> int:
    if re.fullmatch(r"[0-9]{1,19}", value) is None:
        raise _Unverified(reason)
    return int(value)


def _host(inspect: Mapping[str, object]) -> Mapping[str, object]:
    host = inspect.get("HostConfig")
    if type(host) is not dict:
        raise _Unverified("INSPECT_UNREADABLE")
    return host


def _empty(value: object) -> bool:
    return value is None or value == [] or value == {}


def _judge(check: Check, evaluate: Callable[[], _Evaluation]) -> Judgement:
    try:
        failures, facts = evaluate()
    except _Unverified as error:
        return Judgement(check, Outcome.UNVERIFIED, error.reason, MappingProxyType({}))
    if failures:
        return Judgement(check, Outcome.FAIL, failures[0], MappingProxyType(facts))
    return Judgement(check, Outcome.PASS, "", MappingProxyType(facts))


def _identity(
    observation: ProbeObservation,
    inspect: Mapping[str, object],
    profile: StrictDockerProfile,
) -> _Evaluation:
    single = observation.single
    uid = _number(single["uid"], "IDENTITY_UNREADABLE")
    gid = _number(single["gid"], "IDENTITY_UNREADABLE")
    groups = single["groups"].split()
    capabilities = {name: single["status_" + name] for name in _CAPABILITIES}
    no_new_privileges = single["status_NoNewPrivs"]
    if any(re.fullmatch(r"[0-9a-f]{16}", v) is None for v in capabilities.values()):
        raise _Unverified("CAPABILITIES_UNREADABLE")
    if no_new_privileges not in ("0", "1"):
        raise _Unverified("NO_NEW_PRIVILEGES_UNREADABLE")
    config = inspect.get("Config")
    configured_user = config.get("User") if type(config) is dict else None
    failures = []
    if uid == 0 or gid == 0:
        failures.append("ROOT_IDENTITY")
    if (uid, gid) != (profile.uid, profile.gid):
        failures.append("IDENTITY_MISMATCH")
    if groups != [str(profile.gid)]:
        failures.append("SUPPLEMENTARY_GROUPS")
    if any(int(value, 16) for value in capabilities.values()):
        failures.append("CAPABILITIES_PRESENT")
    if no_new_privileges != "1":
        failures.append("NEW_PRIVILEGES_ALLOWED")
    if configured_user != f"{profile.uid}:{profile.gid}":
        failures.append("CONFIGURED_USER_MISMATCH")
    return failures, {
        "uid": uid,
        "gid": gid,
        "groups": groups,
        "capabilities": capabilities,
        "no_new_privileges": no_new_privileges,
    }


def _syscalls(
    observation: ProbeObservation,
    inspect: Mapping[str, object],
    profile: StrictDockerProfile,
) -> _Evaluation:
    mode = observation.single["status_Seccomp"]
    filters = observation.single["status_Seccomp_filters"]
    if mode not in ("0", "1", "2"):
        raise _Unverified("SECCOMP_UNREADABLE")
    options = _host(inspect).get("SecurityOpt")
    if type(options) is not list or any(type(item) is not str for item in options):
        raise _Unverified("INSPECT_UNREADABLE")
    failures = []
    if mode != "2":
        failures.append("SECCOMP_NOT_FILTERING")
    if filters and _number(filters, "SECCOMP_UNREADABLE") < 1:
        failures.append("SECCOMP_FILTER_ABSENT")
    if "no-new-privileges" not in options:
        failures.append("NO_NEW_PRIVILEGES_UNSET")
    if sum(1 for item in options if item.startswith("seccomp=")) != 1:
        failures.append("SECCOMP_PROFILE_UNSET")
    return failures, {
        "mode": mode,
        "filters": filters,
        "policy_digest": profile.seccomp_digest,
    }


def _mounts(
    observation: ProbeObservation,
) -> list[tuple[str, str, frozenset[str], str]]:
    entries = []
    for line in observation.multiple["mount"]:
        parts = line.split(" ")
        if len(parts) != 4 or parts[3] not in ("root", "null", "other"):
            raise _Unverified("MOUNTS_UNREADABLE")
        point, fstype, options, origin = parts
        entries.append((point, fstype, frozenset(options.split(",")), origin))
    if not entries:
        raise _Unverified("MOUNTS_UNREADABLE")
    return entries


def _mount_allowed(
    point: str, fstype: str, options: frozenset[str], origin: str
) -> bool:
    if point == "/":
        return "ro" in options
    if point in _SCRATCH_MOUNTS:
        return (
            fstype == "tmpfs"
            and origin == "root"
            and {"rw", "nosuid", "nodev", "noexec"} <= options
        )
    if point in _FIXED_MOUNTS:
        expected_type, expected_options = _FIXED_MOUNTS[point]
        return fstype == expected_type and expected_options <= options
    if point in _DOCKER_FILES or point in _INIT_MOUNTS:
        return "ro" in options and origin == "other"
    if point in _READONLY_PATHS:
        return fstype == "proc" and "ro" in options
    if point in _MASKED_PATHS:
        return origin == "null" or (fstype == "tmpfs" and "ro" in options)
    return False


def _filesystem(observation: ProbeObservation) -> _Evaluation:
    entries = _mounts(observation)
    points = [entry[0] for entry in entries]
    failures = []
    unexpected = sorted(
        point
        for point, fstype, options, origin in entries
        if not _mount_allowed(point, fstype, options, origin)
    )
    if unexpected:
        failures.append("UNEXPECTED_MOUNT")
    if len(set(points)) != len(points):
        failures.append("DUPLICATE_MOUNT")
    required = _REQUIRED_MOUNTS | _SCRATCH_MOUNTS
    if not required <= set(points) or not _INIT_MOUNTS & set(points):
        failures.append("MOUNT_MISSING")
    return failures, {"mounts": sorted(points), "unexpected": unexpected}


def _entered_from_outside(
    pid: int, parents: dict[int, int], workload: set[int]
) -> bool:
    """Whether a process descends from one docker exec entered (parent 0)."""
    seen: set[int] = set()
    while pid not in seen:
        seen.add(pid)
        parent = parents[pid]
        if parent == 0:
            return True
        if parent in workload or parent not in parents:
            return False
        pid = parent
    return False


def _processes(
    observation: ProbeObservation,
    inspect: Mapping[str, object],
    lifetime_seconds: int,
) -> _Evaluation:
    parents: dict[int, int] = {}
    commands: dict[int, list[str]] = {}
    for line in observation.multiple["process"]:
        parts = line.split()
        if len(parts) < 2:
            raise _Unverified("PROCESSES_UNREADABLE")
        pid = _number(parts[0], "PROCESSES_UNREADABLE")
        if pid in parents:
            raise _Unverified("PROCESSES_UNREADABLE")
        parents[pid] = _number(parts[1], "PROCESSES_UNREADABLE")
        commands[pid] = parts[2:]
    lifetime = str(lifetime_seconds)
    init_children = [pid for pid, parent in parents.items() if parent == 1]
    failures = []
    if commands.get(1) != ["/sbin/docker-init", "--", "/bin/sleep", lifetime]:
        failures.append("PID1_UNEXPECTED")
    if len(init_children) != 1 or commands[init_children[0]] != [
        "/bin/sleep",
        lifetime,
    ]:
        failures.append("WORKLOAD_UNEXPECTED")
    # Everything else must descend from a process entered from outside the
    # namespace (parent 0), which is how docker exec appears inside it.
    workload = {1, *init_children}
    if any(
        not _entered_from_outside(pid, parents, workload)
        for pid in parents
        if pid not in workload
    ):
        failures.append("FOREIGN_PROCESS")
    if _host(inspect).get("PidMode") != "":
        failures.append("PID_NAMESPACE_SHARED")
    return failures, {
        "pid1": commands.get(1, []),
        "processes": len(parents),
    }


def _host_access(
    observation: ProbeObservation, inspect: Mapping[str, object]
) -> _Evaluation:
    host = _host(inspect)
    sockets = list(observation.multiple["runtime_socket"])
    socket_files = _number(observation.single["socket_files"], "SOCKETS_UNREADABLE")
    failures = []
    if sockets:
        failures.append("RUNTIME_SOCKET_PRESENT")
    if socket_files:
        failures.append("SOCKET_FILE_PRESENT")
    if host.get("Privileged") is not False:
        failures.append("PRIVILEGED")
    if not all(
        _empty(host.get(key))
        for key in ("Binds", "Mounts", "VolumesFrom", "Devices", "DeviceRequests")
    ):
        failures.append("HOST_RESOURCE_ATTACHED")
    if not _empty(host.get("CapAdd")):
        failures.append("CAPABILITY_ADDED")
    namespaces = {
        "NetworkMode": "none",
        "PidMode": "",
        "IpcMode": "private",
        "UTSMode": "",
        "UsernsMode": "",
        "CgroupnsMode": "private",
    }
    if any(host.get(key) != value for key, value in namespaces.items()):
        failures.append("HOST_NAMESPACE_SHARED")
    return failures, {"runtime_sockets": sockets, "socket_files": socket_files}


def _network(
    observation: ProbeObservation, inspect: Mapping[str, object]
) -> _Evaluation:
    interfaces = sorted(observation.multiple["net_iface"])
    routes = _number(observation.single["default_route"], "NETWORK_UNREADABLE")
    connect = _number(observation.single["tcp_connect"], "NETWORK_UNREADABLE")
    if connect in (126, 127):
        raise _Unverified("NETWORK_PROBE_UNAVAILABLE")
    failures = []
    if interfaces != ["lo"]:
        failures.append("INTERFACE_PRESENT")
    if routes:
        failures.append("DEFAULT_ROUTE_PRESENT")
    if connect != 1:
        failures.append("CONNECTION_NOT_REFUSED")
    if _host(inspect).get("NetworkMode") != "none":
        failures.append("NETWORK_MODE")
    return failures, {
        "interfaces": interfaces,
        "default_routes": routes,
        "connect_status": connect,
    }


def _cpu(observation: ProbeObservation, profile: StrictDockerProfile) -> _Evaluation:
    value = observation.single["cgroup_cpu.max"]
    parts = value.split(" ")
    if len(parts) != 2:
        raise _Unverified("CGROUP_UNREADABLE")
    quota = None if parts[0] == "max" else _number(parts[0], "CGROUP_UNREADABLE")
    period = _number(parts[1], "CGROUP_UNREADABLE")
    nanocpus = _cpu_nanocpus(profile.cpu_limit)
    if nanocpus is None or period == 0:
        raise _Unverified("CGROUP_UNREADABLE")
    failures = []
    if quota is None or quota * 1_000_000_000 != nanocpus * period:
        failures.append("CPU_LIMIT_MISMATCH")
    return failures, {"cpu_max": value, "nanocpus": nanocpus}


def _limit(observation: ProbeObservation, key: str, expected: int) -> tuple[bool, str]:
    value = observation.single[key]
    if value == "max":
        return False, value
    return _number(value, "CGROUP_UNREADABLE") == expected, value


def _memory(observation: ProbeObservation, profile: StrictDockerProfile) -> _Evaluation:
    memory_ok, memory = _limit(
        observation, "cgroup_memory.max", profile.memory_limit_bytes
    )
    swap_ok, swap = _limit(
        observation,
        "cgroup_memory.swap.max",
        profile.memory_swap_limit_bytes - profile.memory_limit_bytes,
    )
    failures = []
    if not memory_ok:
        failures.append("MEMORY_LIMIT_MISMATCH")
    if not swap_ok:
        failures.append("SWAP_LIMIT_MISMATCH")
    return failures, {"memory_max": memory, "swap_max": swap}


def _pids(observation: ProbeObservation, profile: StrictDockerProfile) -> _Evaluation:
    ok, value = _limit(observation, "cgroup_pids.max", profile.pids_limit)
    return ([] if ok else ["PID_LIMIT_MISMATCH"]), {"pids_max": value}


def _storage(
    observation: ProbeObservation, profile: StrictDockerProfile
) -> _Evaluation:
    expected = {
        "/workspace": profile.workspace_tmpfs_bytes,
        "/tmp": profile.temp_tmpfs_bytes,
        "/run/failroom-target": profile.target_supervisor_tmpfs_bytes,
        "/dev/shm": profile.shm_size_bytes,
    }
    sizes: dict[str, int] = {}
    for line in observation.multiple["fs_size"]:
        parts = line.split(" ")
        if len(parts) != 2 or parts[0] not in expected or parts[0] in sizes:
            raise _Unverified("STORAGE_UNREADABLE")
        sizes[parts[0]] = _number(parts[1], "STORAGE_UNREADABLE")
    if set(sizes) != set(expected):
        raise _Unverified("STORAGE_UNREADABLE")
    overfill = observation.single["workspace_overfill"].split(" ")
    if len(overfill) != 2 or overfill[1] not in ("0", "1"):
        raise _Unverified("STORAGE_UNREADABLE")
    status = _number(overfill[0], "STORAGE_UNREADABLE")
    failures = []
    # tmpfs rounds its size up to whole pages.
    if any(
        not expected[point] <= size < expected[point] + _RUNTIME_PAGE_SLACK
        for point, size in sizes.items()
    ):
        failures.append("TMPFS_SIZE_MISMATCH")
    if status == 0 or overfill[1] != "1":
        failures.append("WORKSPACE_NOT_BOUNDED")
    return failures, {
        "sizes": sizes,
        "overfill_status": status,
        "overfill_no_space": overfill[1] == "1",
    }


def _io(observation: ProbeObservation, profile: StrictDockerProfile) -> _Evaluation:
    lines = observation.multiple["io_max"]
    if len(lines) > 1:
        return ["IO_LIMIT_MISMATCH"], {"io_max": list(lines)}
    match = _IO_MAX.fullmatch(lines[0]) if lines else None
    if match is None:
        return ["IO_LIMIT_MISMATCH"], {"io_max": list(lines)}
    device, read, write = match.group(1), match.group(2), match.group(3)
    failures = []
    if (read, write) != (str(profile.io_read_bps), str(profile.io_write_bps)):
        failures.append("IO_LIMIT_MISMATCH")
    return failures, {"device": device, "read_bps": read, "write_bps": write}


def _descriptors(
    observation: ProbeObservation, profile: StrictDockerProfile
) -> _Evaluation:
    soft = _number(observation.single["fd_soft"], "DESCRIPTORS_UNREADABLE")
    hard = _number(observation.single["fd_hard"], "DESCRIPTORS_UNREADABLE")
    failures = []
    if (soft, hard) != (profile.fd_limit, profile.fd_limit):
        failures.append("DESCRIPTOR_LIMIT_MISMATCH")
    return failures, {"soft": soft, "hard": hard}


def judge_container_checks(
    observation: ProbeObservation,
    inspect: Mapping[str, object],
    profile: StrictDockerProfile,
    *,
    lifetime_seconds: int,
) -> tuple[Judgement, ...]:
    """Judge the twelve container checks from one probe and its inspect data."""
    evaluations: dict[Check, Callable[[], _Evaluation]] = {
        Check.UNPRIVILEGED_IDENTITY: lambda: _identity(observation, inspect, profile),
        Check.SYSCALL_RESTRICTIONS: lambda: _syscalls(observation, inspect, profile),
        Check.FILESYSTEM_ISOLATION: lambda: _filesystem(observation),
        Check.PROCESS_ISOLATION: lambda: _processes(
            observation, inspect, lifetime_seconds
        ),
        Check.HOST_ACCESS_ABSENCE: lambda: _host_access(observation, inspect),
        Check.NETWORK_ISOLATION: lambda: _network(observation, inspect),
        Check.CPU_LIMIT: lambda: _cpu(observation, profile),
        Check.MEMORY_AND_SWAP_LIMIT: lambda: _memory(observation, profile),
        Check.PID_LIMIT: lambda: _pids(observation, profile),
        Check.STORAGE_LIMIT: lambda: _storage(observation, profile),
        Check.IO_LIMIT: lambda: _io(observation, profile),
        Check.FILE_DESCRIPTOR_LIMIT: lambda: _descriptors(observation, profile),
    }
    return tuple(_judge(check, evaluations[check]) for check in CONTAINER_CHECKS)
