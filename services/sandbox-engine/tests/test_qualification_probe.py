import copy
import subprocess
import sys
import unittest

import test_docker_profile

from failroom_sandbox.models import Check, Outcome
from failroom_sandbox.qualification_probe import (
    CONTAINER_CHECKS,
    PROBE_SCRIPT,
    ProbeOutputError,
    judge_container_checks,
    parse_probe_output,
)

LIFETIME = 290
BOOT_ID = "39838d7c-98d9-4c41-9181-b3baadabb0c6"


def probe_lines(lifetime=LIFETIME):
    """The output a matching sandbox produced, adapted to the test profile."""
    return [
        "probe=1",
        "uid=10001",
        "gid=10001",
        "groups=10001",
        "status_CapInh=0000000000000000",
        "status_CapPrm=0000000000000000",
        "status_CapEff=0000000000000000",
        "status_CapBnd=0000000000000000",
        "status_CapAmb=0000000000000000",
        "status_NoNewPrivs=1",
        "status_Seccomp=2",
        "status_Seccomp_filters=2",
        "boot_id=" + BOOT_ID,
        f"process=1 0 /sbin/docker-init -- /bin/sleep {lifetime}",
        f"process=7 1 /bin/sleep {lifetime} ",
        "process=8 0 /bin/sh -c LC_ALL=C PATH=/usr/bin:/bin",
        "mount=/ overlay ro,relatime root",
        "mount=/proc proc rw,nosuid,nodev,noexec,relatime root",
        "mount=/dev tmpfs rw,nosuid root",
        "mount=/dev/pts devpts rw,nosuid,noexec,relatime root",
        "mount=/sys sysfs ro,nosuid,nodev,noexec,relatime root",
        "mount=/sys/fs/cgroup cgroup2 ro,nosuid,nodev,noexec,relatime root",
        "mount=/dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime root",
        "mount=/dev/shm tmpfs rw,nosuid,nodev,noexec,relatime root",
        "mount=/usr/sbin/docker-init overlay ro,relatime other",
        "mount=/tmp tmpfs rw,nosuid,nodev,noexec,relatime root",
        "mount=/workspace tmpfs rw,nosuid,nodev,noexec,relatime root",
        "mount=/run/failroom-target tmpfs rw,nosuid,nodev,noexec,relatime root",
        "mount=/etc/resolv.conf ext4 ro,relatime other",
        "mount=/etc/hostname ext4 ro,relatime other",
        "mount=/etc/hosts ext4 ro,relatime other",
        "mount=/proc/bus proc ro,nosuid,nodev,noexec,relatime other",
        "mount=/proc/fs proc ro,nosuid,nodev,noexec,relatime other",
        "mount=/proc/irq proc ro,nosuid,nodev,noexec,relatime other",
        "mount=/proc/sys proc ro,nosuid,nodev,noexec,relatime other",
        "mount=/proc/sysrq-trigger proc ro,nosuid,nodev,noexec,relatime other",
        "mount=/proc/acpi tmpfs ro,relatime root",
        "mount=/proc/interrupts tmpfs rw,nosuid null",
        "mount=/proc/kcore tmpfs rw,nosuid null",
        "mount=/proc/keys tmpfs rw,nosuid null",
        "mount=/proc/scsi tmpfs ro,relatime root",
        "mount=/proc/timer_list tmpfs rw,nosuid null",
        "mount=/sys/firmware tmpfs ro,relatime root",
        "net_iface=lo",
        "default_route=0",
        "tcp_connect=1",
        "socket_files=0",
        "cgroup_cpu.max=50000 100000",
        "cgroup_memory.max=134217728",
        "cgroup_memory.swap.max=0",
        "cgroup_pids.max=64",
        "io_max=7:0 rbps=1048576 wbps=1048576 riops=max wiops=max",
        "fd_soft=256",
        "fd_hard=256",
        "fs_size=/workspace 67108864",
        "fs_size=/tmp 16777216",
        "fs_size=/run/failroom-target 1048576",
        "fs_size=/dev/shm 16777216",
        "workspace_overfill=1 1",
        "end=1",
    ]


def inspect_data(lifetime=LIFETIME):
    return {
        "Image": "sha256:" + "d" * 64,
        "Config": {"User": "10001:10001", "Cmd": [str(lifetime)]},
        "HostConfig": {
            "Privileged": False,
            "SecurityOpt": [
                "no-new-privileges",
                "seccomp=/trusted/policies/verified.json",
            ],
            "PidMode": "",
            "IpcMode": "private",
            "NetworkMode": "none",
            "UTSMode": "",
            "UsernsMode": "",
            "CgroupnsMode": "private",
            "Binds": None,
            "Mounts": None,
            "VolumesFrom": None,
            "Devices": [],
            "DeviceRequests": None,
            "CapAdd": None,
        },
    }


def encode(lines):
    return ("\n".join(lines) + "\n").encode("ascii")


def replaced(lines, key, *values):
    """Replace every line of one key with the given values (none removes it)."""
    index = next(i for i, line in enumerate(lines) if line.startswith(key + "="))
    kept = [line for line in lines if not line.startswith(key + "=")]
    return kept[:index] + [key + "=" + value for value in values] + kept[index:]


class ProbeParsingTests(unittest.TestCase):
    def test_parses_the_fixed_output_and_exposes_context_facts(self):
        observation = parse_probe_output(encode(probe_lines()))

        self.assertEqual(observation.single["uid"], "10001")
        self.assertEqual(len(observation.multiple["mount"]), 27)
        self.assertEqual(observation.boot_id, BOOT_ID)
        self.assertEqual(observation.io_device, "7:0")

    def test_context_facts_are_absent_unless_well_formed(self):
        observation = parse_probe_output(
            encode(replaced(replaced(probe_lines(), "boot_id", "x"), "io_max"))
        )

        self.assertIsNone(observation.boot_id)
        self.assertIsNone(observation.io_device)

    def test_rejects_output_outside_the_fixed_format(self):
        lines = probe_lines()
        cases = {
            "non-ascii": encode(lines).replace(b"uid=10001", "uid=é".encode()),
            "no trailing newline": encode(lines)[:-1],
            "truncated": encode(lines[:-1]),
            "wrong first line": encode(["probe=2", *lines[1:]]),
            "unknown key": encode([*lines[:-1], "extra=1", "end=1"]),
            "duplicate key": encode([*lines[:-1], "uid=0", "end=1"]),
            "missing key": encode(
                [line for line in lines if not line.startswith("gid=")]
            ),
            "no separator": encode([*lines[:-1], "mount", "end=1"]),
            "control character": encode(lines).replace(b"uid=10001", b"uid=1\t1"),
            "carriage return": encode(lines).replace(b"\n", b"\r\n"),
            "too long": encode([*lines[:-1], "mount=" + "a" * 513, "end=1"]),
            "too many lines": encode([*lines[:-1], *["net_iface=lo"] * 500, "end=1"]),
        }
        for name, data in cases.items():
            with self.subTest(case=name), self.assertRaises(ProbeOutputError):
                parse_probe_output(data)

    def test_probe_script_is_fixed_ascii_without_carriage_returns(self):
        PROBE_SCRIPT.encode("ascii")
        self.assertNotIn("\r", PROBE_SCRIPT)
        self.assertTrue(PROBE_SCRIPT.startswith("LC_ALL=C\nPATH=/usr/bin:/bin\n"))
        self.assertTrue(PROBE_SCRIPT.endswith('echo "end=1"\n'))

    @unittest.skipUnless(sys.platform == "linux", "POSIX shell required")
    def test_probe_script_is_valid_posix_shell(self):
        subprocess.run(("sh", "-n", "-c", PROBE_SCRIPT), check=True, timeout=10)


class ContainerJudgementTests(unittest.TestCase):
    def setUp(self):
        self.profile = test_docker_profile.DockerProfileTests()._profile()

    def judge(self, lines=None, inspect=None, lifetime=LIFETIME):
        observation = parse_probe_output(encode(lines or probe_lines()))
        judgements = judge_container_checks(
            observation,
            inspect or inspect_data(),
            self.profile,
            lifetime_seconds=lifetime,
        )
        self.assertEqual(tuple(j.check for j in judgements), CONTAINER_CHECKS)
        return {judgement.check: judgement for judgement in judgements}

    def assert_outcome(self, judgements, check, outcome, reason):
        self.assertEqual(
            (judgements[check].outcome, judgements[check].reason), (outcome, reason)
        )
        for other, judgement in judgements.items():
            if other is not check:
                self.assertIs(judgement.outcome, Outcome.PASS, other)

    def test_matching_probe_passes_every_container_check(self):
        judgements = self.judge()

        for check, judgement in judgements.items():
            with self.subTest(check=check):
                self.assertIs(judgement.outcome, Outcome.PASS)
                self.assertEqual(judgement.reason, "")
        self.assertEqual(
            judgements[Check.STORAGE_LIMIT].facts["sizes"]["/workspace"], 67108864
        )

    def test_contradicting_facts_fail_the_owning_check(self):
        lines = probe_lines()
        cases = (
            (Check.UNPRIVILEGED_IDENTITY, "ROOT_IDENTITY", replaced(lines, "uid", "0")),
            (
                Check.UNPRIVILEGED_IDENTITY,
                "IDENTITY_MISMATCH",
                replaced(lines, "gid", "1"),
            ),
            (
                Check.UNPRIVILEGED_IDENTITY,
                "SUPPLEMENTARY_GROUPS",
                replaced(lines, "groups", "10001 999"),
            ),
            (
                Check.UNPRIVILEGED_IDENTITY,
                "CAPABILITIES_PRESENT",
                replaced(lines, "status_CapBnd", "00000000a80425fb"),
            ),
            (
                Check.UNPRIVILEGED_IDENTITY,
                "NEW_PRIVILEGES_ALLOWED",
                replaced(lines, "status_NoNewPrivs", "0"),
            ),
            (
                Check.SYSCALL_RESTRICTIONS,
                "SECCOMP_NOT_FILTERING",
                replaced(lines, "status_Seccomp", "0"),
            ),
            (
                Check.SYSCALL_RESTRICTIONS,
                "SECCOMP_FILTER_ABSENT",
                replaced(lines, "status_Seccomp_filters", "0"),
            ),
            (
                Check.FILESYSTEM_ISOLATION,
                "UNEXPECTED_MOUNT",
                [
                    line.replace("mount=/ overlay ro,", "mount=/ overlay rw,")
                    for line in lines
                ],
            ),
            (
                Check.FILESYSTEM_ISOLATION,
                "UNEXPECTED_MOUNT",
                [*lines[:-1], "mount=/data ext4 rw,relatime other", "end=1"],
            ),
            (
                Check.FILESYSTEM_ISOLATION,
                "UNEXPECTED_MOUNT",
                [
                    line.replace("/proc/sys proc ro,", "/proc/sys proc rw,")
                    for line in lines
                ],
            ),
            (
                Check.FILESYSTEM_ISOLATION,
                "MOUNT_MISSING",
                [line for line in lines if not line.startswith("mount=/workspace ")],
            ),
            (
                Check.FILESYSTEM_ISOLATION,
                "DUPLICATE_MOUNT",
                [*lines[:-1], "mount=/tmp tmpfs rw,nosuid,nodev,noexec root", "end=1"],
            ),
            (
                Check.PROCESS_ISOLATION,
                "PID1_UNEXPECTED",
                [
                    line.replace(
                        "process=1 0 /sbin/docker-init", "process=1 0 /sbin/init"
                    )
                    for line in lines
                ],
            ),
            (
                Check.PROCESS_ISOLATION,
                "WORKLOAD_UNEXPECTED",
                [*lines[:-1], "process=9 1 /usr/sbin/sshd", "end=1"],
            ),
            (
                Check.PROCESS_ISOLATION,
                "FOREIGN_PROCESS",
                [*lines[:-1], "process=9 7 /bin/sh", "end=1"],
            ),
            (
                Check.PROCESS_ISOLATION,
                "FOREIGN_PROCESS",
                [*lines[:-1], "process=9 44 /bin/sh", "end=1"],
            ),
            (
                Check.HOST_ACCESS_ABSENCE,
                "RUNTIME_SOCKET_PRESENT",
                [*lines[:-1], "runtime_socket=/var/run/docker.sock", "end=1"],
            ),
            (
                Check.HOST_ACCESS_ABSENCE,
                "SOCKET_FILE_PRESENT",
                replaced(lines, "socket_files", "1"),
            ),
            (
                Check.NETWORK_ISOLATION,
                "INTERFACE_PRESENT",
                [*lines[:-1], "net_iface=eth0", "end=1"],
            ),
            (
                Check.NETWORK_ISOLATION,
                "DEFAULT_ROUTE_PRESENT",
                replaced(lines, "default_route", "1"),
            ),
            (
                Check.NETWORK_ISOLATION,
                "CONNECTION_NOT_REFUSED",
                replaced(lines, "tcp_connect", "0"),
            ),
            (
                Check.NETWORK_ISOLATION,
                "CONNECTION_NOT_REFUSED",
                replaced(lines, "tcp_connect", "124"),
            ),
            (
                Check.CPU_LIMIT,
                "CPU_LIMIT_MISMATCH",
                replaced(lines, "cgroup_cpu.max", "max 100000"),
            ),
            (
                Check.CPU_LIMIT,
                "CPU_LIMIT_MISMATCH",
                replaced(lines, "cgroup_cpu.max", "100000 100000"),
            ),
            (
                Check.MEMORY_AND_SWAP_LIMIT,
                "MEMORY_LIMIT_MISMATCH",
                replaced(lines, "cgroup_memory.max", "max"),
            ),
            (
                Check.MEMORY_AND_SWAP_LIMIT,
                "SWAP_LIMIT_MISMATCH",
                replaced(lines, "cgroup_memory.swap.max", "4096"),
            ),
            (
                Check.PID_LIMIT,
                "PID_LIMIT_MISMATCH",
                replaced(lines, "cgroup_pids.max", "max"),
            ),
            (
                Check.STORAGE_LIMIT,
                "TMPFS_SIZE_MISMATCH",
                [
                    line.replace("fs_size=/tmp 16777216", "fs_size=/tmp 33554432")
                    for line in lines
                ],
            ),
            (
                Check.STORAGE_LIMIT,
                "WORKSPACE_NOT_BOUNDED",
                replaced(lines, "workspace_overfill", "0 0"),
            ),
            (
                Check.STORAGE_LIMIT,
                "WORKSPACE_NOT_BOUNDED",
                replaced(lines, "workspace_overfill", "1 0"),
            ),
            (Check.IO_LIMIT, "IO_LIMIT_MISMATCH", replaced(lines, "io_max")),
            (
                Check.IO_LIMIT,
                "IO_LIMIT_MISMATCH",
                replaced(
                    lines, "io_max", "7:0 rbps=max wbps=1048576 riops=max wiops=max"
                ),
            ),
            (
                Check.FILE_DESCRIPTOR_LIMIT,
                "DESCRIPTOR_LIMIT_MISMATCH",
                replaced(lines, "fd_soft", "1024"),
            ),
        )
        for check, reason, mutated in cases:
            with self.subTest(check=check, reason=reason):
                self.assert_outcome(self.judge(mutated), check, Outcome.FAIL, reason)

    def test_host_inspect_contradictions_fail_the_owning_check(self):
        def changed(**host):
            data = copy.deepcopy(inspect_data())
            data["HostConfig"].update(host)
            return data

        cases = (
            (Check.PROCESS_ISOLATION, "PID_NAMESPACE_SHARED", changed(PidMode="host")),
            (Check.HOST_ACCESS_ABSENCE, "PRIVILEGED", changed(Privileged=True)),
            (
                Check.HOST_ACCESS_ABSENCE,
                "HOST_RESOURCE_ATTACHED",
                changed(Binds=["/:/host"]),
            ),
            (
                Check.HOST_ACCESS_ABSENCE,
                "CAPABILITY_ADDED",
                changed(CapAdd=["NET_RAW"]),
            ),
            (
                Check.HOST_ACCESS_ABSENCE,
                "HOST_NAMESPACE_SHARED",
                changed(UTSMode="host"),
            ),
            (
                Check.SYSCALL_RESTRICTIONS,
                "SECCOMP_PROFILE_UNSET",
                changed(SecurityOpt=["no-new-privileges"]),
            ),
        )
        for check, reason, data in cases:
            with self.subTest(check=check, reason=reason):
                judgements = self.judge(inspect=data)
                self.assertEqual(
                    (judgements[check].outcome, judgements[check].reason),
                    (Outcome.FAIL, reason),
                )
        network = self.judge(inspect=changed(NetworkMode="bridge"))
        self.assertEqual(network[Check.NETWORK_ISOLATION].reason, "NETWORK_MODE")
        user = copy.deepcopy(inspect_data())
        user["Config"]["User"] = "0:0"
        self.assertEqual(
            self.judge(inspect=user)[Check.UNPRIVILEGED_IDENTITY].reason,
            "CONFIGURED_USER_MISMATCH",
        )

    def test_unreadable_facts_are_unverified(self):
        lines = probe_lines()
        cases = (
            (
                Check.UNPRIVILEGED_IDENTITY,
                "IDENTITY_UNREADABLE",
                replaced(lines, "uid", ""),
            ),
            (
                Check.UNPRIVILEGED_IDENTITY,
                "CAPABILITIES_UNREADABLE",
                replaced(lines, "status_CapEff", ""),
            ),
            (
                Check.SYSCALL_RESTRICTIONS,
                "SECCOMP_UNREADABLE",
                replaced(lines, "status_Seccomp", ""),
            ),
            (
                Check.FILESYSTEM_ISOLATION,
                "MOUNTS_UNREADABLE",
                [*lines[:-1], "mount=/broken", "end=1"],
            ),
            (
                Check.PROCESS_ISOLATION,
                "PROCESSES_UNREADABLE",
                [*lines[:-1], "process=x 0 /bin/sh", "end=1"],
            ),
            (
                Check.HOST_ACCESS_ABSENCE,
                "SOCKETS_UNREADABLE",
                replaced(lines, "socket_files", ""),
            ),
            (
                Check.NETWORK_ISOLATION,
                "NETWORK_PROBE_UNAVAILABLE",
                replaced(lines, "tcp_connect", "127"),
            ),
            (
                Check.CPU_LIMIT,
                "CGROUP_UNREADABLE",
                replaced(lines, "cgroup_cpu.max", ""),
            ),
            (
                Check.MEMORY_AND_SWAP_LIMIT,
                "CGROUP_UNREADABLE",
                replaced(lines, "cgroup_memory.max", ""),
            ),
            (
                Check.PID_LIMIT,
                "CGROUP_UNREADABLE",
                replaced(lines, "cgroup_pids.max", ""),
            ),
            (
                Check.STORAGE_LIMIT,
                "STORAGE_UNREADABLE",
                replaced(lines, "workspace_overfill", "unavailable"),
            ),
            (
                Check.STORAGE_LIMIT,
                "STORAGE_UNREADABLE",
                [line for line in lines if not line.startswith("fs_size=/tmp ")],
            ),
            (
                Check.FILE_DESCRIPTOR_LIMIT,
                "DESCRIPTORS_UNREADABLE",
                replaced(lines, "fd_hard", "unlimited"),
            ),
        )
        for check, reason, mutated in cases:
            with self.subTest(check=check, reason=reason):
                judgement = self.judge(mutated)[check]
                self.assertEqual(
                    (judgement.outcome, judgement.reason), (Outcome.UNVERIFIED, reason)
                )
                self.assertEqual(dict(judgement.facts), {})

    def test_docker_masks_are_allowed_only_as_masks(self):
        lines = probe_lines()
        allowed = [
            *lines[:-1],
            "mount=/proc/latency_stats tmpfs rw,nosuid null",
            "end=1",
        ]
        writable_mask = [
            *lines[:-1],
            "mount=/proc/asound tmpfs rw,relatime root",
            "end=1",
        ]
        writable_hosts = [
            line.replace("/etc/hosts ext4 ro,", "/etc/hosts ext4 rw,") for line in lines
        ]

        self.assertIs(
            self.judge(allowed)[Check.FILESYSTEM_ISOLATION].outcome, Outcome.PASS
        )
        for mutated in (writable_mask, writable_hosts):
            with self.subTest(mutated=mutated[-2]):
                judgement = self.judge(mutated)[Check.FILESYSTEM_ISOLATION]
                self.assertEqual(judgement.reason, "UNEXPECTED_MOUNT")

    def test_workload_must_match_the_verified_lifetime(self):
        judgement = self.judge(lifetime=LIFETIME - 1)[Check.PROCESS_ISOLATION]

        self.assertEqual(
            (judgement.outcome, judgement.reason), (Outcome.FAIL, "PID1_UNEXPECTED")
        )


if __name__ == "__main__":
    unittest.main()
