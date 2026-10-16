import json
import subprocess
import sys
import unittest
from datetime import UTC, datetime

from failroom_sandbox.docker_cli import (
    ContainerExit,
    DockerCli,
    DockerError,
    ProcessResult,
    _run_process,
)
from failroom_sandbox.qualification_probe import (
    IDENTITY_SCRIPT,
    PROBE_SCRIPT,
    PROCESS_SCRIPT,
)


class DockerCliTests(unittest.TestCase):
    def test_allocates_a_bounded_workspace_file_with_fixed_argv(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return ProcessResult(0, b"", b"")

        cli = DockerCli(
            context="desktop-linux", timeout=5, max_output_bytes=1024, runner=runner
        )
        cli.allocate_workspace_file(
            "a" * 64,
            uid=1000,
            gid=1000,
            size_bytes=60_000_000,
            path="/workspace/.failroom-disk-full",
        )

        self.assertEqual(
            calls[0][0],
            (
                "docker",
                "--context",
                "desktop-linux",
                "container",
                "exec",
                "--user",
                "1000:1000",
                "a" * 64,
                "/usr/bin/fallocate",
                "-l",
                "60000000",
                "/workspace/.failroom-disk-full",
            ),
        )

    def test_rejects_unbounded_workspace_allocation_arguments(self):
        cli = DockerCli(
            context="desktop-linux",
            timeout=5,
            max_output_bytes=1024,
            runner=lambda *args, **kwargs: ProcessResult(0, b"", b""),
        )
        for kwargs in (
            {"uid": 0, "gid": 1000, "size_bytes": 1, "path": "/workspace/a"},
            {"uid": 1000, "gid": 1000, "size_bytes": 0, "path": "/workspace/a"},
            {"uid": 1000, "gid": 1000, "size_bytes": 1, "path": "/tmp/a"},
            {
                "uid": 1000,
                "gid": 1000,
                "size_bytes": 1,
                "path": "/workspace/../tmp/a",
            },
        ):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(DockerError, "^INVALID_DOCKER_REQUEST$"),
            ):
                cli.allocate_workspace_file("a" * 64, **kwargs)

    def test_observes_and_removes_only_the_fixed_disk_full_filler(self):
        calls = []
        results = iter(
            (
                ProcessResult(0, b"Avail\n7108864\n", b""),
                ProcessResult(0, b"60000000\n", b""),
                ProcessResult(0, b"", b""),
            )
        )

        def runner(argv, **kwargs):
            calls.append(argv)
            return next(results)

        cli = DockerCli(
            context="desktop-linux", timeout=5, max_output_bytes=1024, runner=runner
        )
        self.assertEqual(
            cli.workspace_available_bytes("a" * 64, uid=1000, gid=1000), 7_108_864
        )
        self.assertEqual(
            cli.disk_full_filler_size("a" * 64, uid=1000, gid=1000), 60_000_000
        )
        cli.remove_disk_full_filler("a" * 64, uid=1000, gid=1000)

        self.assertEqual(
            calls,
            [
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "container",
                    "exec",
                    "--user",
                    "1000:1000",
                    "a" * 64,
                    "/usr/bin/df",
                    "--output=avail",
                    "-B1",
                    "/workspace",
                ),
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "container",
                    "exec",
                    "--user",
                    "1000:1000",
                    "a" * 64,
                    "/usr/bin/stat",
                    "--format=%s",
                    "--",
                    "/workspace/.failroom-disk-full",
                ),
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "container",
                    "exec",
                    "--user",
                    "1000:1000",
                    "a" * 64,
                    "/usr/bin/rm",
                    "--",
                    "/workspace/.failroom-disk-full",
                ),
            ],
        )

    def test_checks_only_the_fixed_disk_full_filler_for_absence(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, b"", b"")

        cli = DockerCli(
            context="desktop-linux", timeout=5, max_output_bytes=1024, runner=runner
        )

        self.assertTrue(cli.disk_full_filler_absent("a" * 64, uid=1000, gid=1000))
        self.assertEqual(
            calls,
            [
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "container",
                    "exec",
                    "--user",
                    "1000:1000",
                    "a" * 64,
                    "/usr/bin/test",
                    "!",
                    "-e",
                    "/workspace/.failroom-disk-full",
                )
            ],
        )

        present = DockerCli(
            context="desktop-linux",
            timeout=5,
            max_output_bytes=1024,
            runner=lambda *args, **kwargs: ProcessResult(1, b"", b""),
        )
        self.assertFalse(present.disk_full_filler_absent("a" * 64, uid=1000, gid=1000))

        unavailable = DockerCli(
            context="desktop-linux",
            timeout=5,
            max_output_bytes=1024,
            runner=lambda *args, **kwargs: ProcessResult(2, b"", b""),
        )
        with self.assertRaisesRegex(DockerError, "^RUNTIME_UNAVAILABLE$"):
            unavailable.disk_full_filler_absent("a" * 64, uid=1000, gid=1000)

    def test_uses_fixed_target_service_exec_argv(self):
        calls = []
        results = iter(
            (
                ProcessResult(1, b"", b""),
                ProcessResult(0, b"", b""),
                ProcessResult(0, b"", b""),
            )
        )
        cli = DockerCli(
            context="desktop-linux",
            timeout=5,
            max_output_bytes=1024,
            runner=lambda argv, **kwargs: (calls.append(argv), next(results))[1],
        )

        self.assertTrue(cli.disk_full_target_initialization_failed("a" * 64))
        cli.start_disk_full_target("a" * 64)
        self.assertTrue(cli.disk_full_target_healthy("a" * 64))

        self.assertEqual(
            calls[0][-2:], ("/usr/local/bin/failroom-disk-target", "initialize")
        )
        self.assertEqual(calls[0][5:7], ("--user", "0:0"))
        self.assertEqual(calls[1][4:8], ("exec", "--detach", "--user", "0:0"))
        self.assertEqual(
            calls[2][-2:], ("/usr/local/bin/failroom-disk-target", "status")
        )
        self.assertEqual(calls[2][5:7], ("--user", "0:0"))

    def test_process_timeout_and_output_limit_are_enforced(self):
        for code, timeout, limit in (
            ("import time; time.sleep(10)", 0.1, 1024),
            ("print('x' * 100000)", 3, 1024),
        ):
            with self.subTest(code=code), self.assertRaises(DockerError):
                _run_process(
                    (sys.executable, "-c", code),
                    timeout=timeout,
                    max_output_bytes=limit,
                )

    def test_process_returns_bounded_stdout_and_stderr(self):
        result = _run_process(
            (
                sys.executable,
                "-c",
                "import sys; print('ok'); print('error', file=sys.stderr)",
            ),
            timeout=3,
            max_output_bytes=1024,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b"ok")
        self.assertEqual(result.stderr.strip(), b"error")

    def test_invalid_configuration_is_rejected(self):
        for kwargs in (
            {"context": "--host=bad"},
            {"timeout": 0},
            {"timeout": True},
            {"max_output_bytes": 0},
        ):
            values = {
                "context": "desktop-linux",
                "timeout": 5,
                "max_output_bytes": 1024,
            } | kwargs
            with self.subTest(values=values), self.assertRaises(DockerError):
                DockerCli(**values)

    def test_duplicate_json_keys_or_malformed_inspect_denied(self):
        for payload in (b'[{"Id":"a","Id":"b"}]', b"{}", b"[]", b"[1]", b"not json"):
            cli = DockerCli(
                context="desktop-linux",
                timeout=5,
                max_output_bytes=1024,
                runner=lambda *a, data=payload, **k: ProcessResult(0, data, b""),
            )
            with self.subTest(payload=payload), self.assertRaises(DockerError):
                cli.inspect_image("example@sha256:" + "a" * 64)

    def test_inspects_a_local_immutable_image_id_without_shell_expansion(self):
        calls = []
        image_id = "sha256:" + "a" * 64
        cli = DockerCli(
            context="desktop-linux",
            timeout=5,
            max_output_bytes=1024,
            runner=lambda argv, **kwargs: (
                calls.append(argv),
                ProcessResult(0, b'[{"Id":"sha256:' + b"a" * 64 + b'"}]', b""),
            )[1],
        )

        cli.inspect_image(image_id)

        self.assertEqual(
            calls,
            [("docker", "--context", "desktop-linux", "image", "inspect", image_id)],
        )

    def test_runner_errors_do_not_expose_paths_or_output(self):
        def fail(*args, **kwargs):
            raise subprocess.TimeoutExpired("SECRET", 1, output=b"CREDENTIAL")

        cli = DockerCli(
            context="desktop-linux", timeout=5, max_output_bytes=1024, runner=fail
        )
        with self.assertRaisesRegex(DockerError, "^RUNTIME_UNAVAILABLE$"):
            cli.inspect_image("example@sha256:" + "a" * 64)

    def test_daemon_failure_is_not_absence(self):
        cli = DockerCli(
            context="desktop-linux",
            timeout=5,
            max_output_bytes=1024,
            runner=lambda *a, **k: ProcessResult(1, b"", b"connection denied SECRET"),
        )
        with self.assertRaisesRegex(DockerError, "^RUNTIME_UNAVAILABLE$"):
            cli.inspect_container("a" * 64)


_ENGINE_INFO = {
    "ID": "84d593e9-7052-471f-aacb-4806ba541464",
    "Name": "docker-desktop",
    "Containers": 3,
    "ServerVersion": "29.4.2",
    "KernelVersion": "6.18.40.1-microsoft-standard-WSL2",
    "OperatingSystem": "Docker Desktop (containerized)",
    "OSType": "linux",
    "Architecture": "x86_64",
    "Driver": "overlayfs",
    "CgroupDriver": "cgroupfs",
    "CgroupVersion": "2",
    "DefaultRuntime": "runc",
    "InitBinary": "docker-init",
    "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
    "Runtimes": {"runc": {"path": "runc"}, "io.containerd.runc.v2": {}},
}


class QualificationCommandTests(unittest.TestCase):
    def cli(self, runner):
        return DockerCli(
            context="desktop-linux", timeout=5, max_output_bytes=65536, runner=runner
        )

    def test_runs_the_fixed_probe_as_the_configured_user(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, b"probe=1\nend=1\n", b"")

        output = self.cli(runner).run_qualification_probe("a" * 64)

        self.assertEqual(output, b"probe=1\nend=1\n")
        self.assertEqual(
            calls,
            [
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "container",
                    "exec",
                    "a" * 64,
                    "/bin/sh",
                    "-c",
                    PROBE_SCRIPT,
                    "failroom-qualification-probe",
                )
            ],
        )
        self.assertNotIn("--user", calls[0])

    def test_lists_sandbox_processes_with_a_fixed_script(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, b"process=1 S 1\nend=1\n", b"")

        cli = self.cli(runner)
        with self.assertRaisesRegex(DockerError, "^INVALID_DOCKER_REQUEST$"):
            cli.list_sandbox_processes("../etc")
        output = cli.list_sandbox_processes("a" * 64)

        self.assertEqual(output, b"process=1 S 1\nend=1\n")
        self.assertEqual(
            calls,
            [
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "container",
                    "exec",
                    "a" * 64,
                    "/bin/sh",
                    "-c",
                    PROCESS_SCRIPT,
                    "failroom-process-list",
                )
            ],
        )

    def test_reads_runtime_identity_with_a_fixed_script(self):
        calls = []
        reported = b"boot_id=" + b"0" * 8 + b"\nend=1\n"

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, reported, b"")

        cli = self.cli(runner)
        with self.assertRaisesRegex(DockerError, "^INVALID_DOCKER_REQUEST$"):
            cli.read_runtime_identity("../etc")
        output = cli.read_runtime_identity("a" * 64)

        self.assertEqual(output, reported)
        self.assertEqual(
            calls,
            [
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "container",
                    "exec",
                    "a" * 64,
                    "/bin/sh",
                    "-c",
                    IDENTITY_SCRIPT,
                    "failroom-runtime-identity",
                )
            ],
        )

    def test_probe_rejects_invalid_targets_and_any_stderr(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, b"probe=1\nend=1\n", b"warning")

        cli = self.cli(runner)
        with self.assertRaisesRegex(DockerError, "^INVALID_DOCKER_REQUEST$"):
            cli.run_qualification_probe("--privileged")
        self.assertEqual(calls, [])
        with self.assertRaisesRegex(DockerError, "^RUNTIME_UNAVAILABLE$"):
            cli.run_qualification_probe("a" * 64)

    def test_reads_only_the_fixed_engine_identity_fields(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, json.dumps(_ENGINE_INFO).encode(), b"")

        identity = self.cli(runner).engine_identity()

        self.assertEqual(
            calls,
            [
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "info",
                    "--format",
                    "{{json .}}",
                )
            ],
        )
        self.assertEqual(identity.engine_id, _ENGINE_INFO["ID"])
        self.assertEqual(
            dict(identity.configuration),
            {
                "ServerVersion": "29.4.2",
                "KernelVersion": "6.18.40.1-microsoft-standard-WSL2",
                "OperatingSystem": "Docker Desktop (containerized)",
                "OSType": "linux",
                "Architecture": "x86_64",
                "Driver": "overlayfs",
                "CgroupDriver": "cgroupfs",
                "CgroupVersion": "2",
                "DefaultRuntime": "runc",
                "InitBinary": "docker-init",
                "SecurityOptions": ["name=cgroupns", "name=seccomp,profile=builtin"],
                "Runtimes": ["io.containerd.runc.v2", "runc"],
            },
        )

    def test_engine_identity_rejects_malformed_documents(self):
        def changed(**fields):
            return json.dumps({**_ENGINE_INFO, **fields}).encode()

        without_init = {k: v for k, v in _ENGINE_INFO.items() if k != "InitBinary"}
        cases = {
            "id with space": changed(ID="engine id"),
            "missing id": json.dumps(
                {k: v for k, v in _ENGINE_INFO.items() if k != "ID"}
            ).encode(),
            "missing field": json.dumps(without_init).encode(),
            "integer field": changed(ServerVersion=29),
            "control character": changed(KernelVersion="6.18\n"),
            "options not a list": changed(SecurityOptions="name=seccomp"),
            "runtimes not an object": changed(Runtimes=["runc"]),
            "duplicate key": b'{"ID": "a", "ID": "b"}',
            "not an object": json.dumps([_ENGINE_INFO]).encode(),
            "not json": b"engine",
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                cli = self.cli(lambda *a, data=data, **k: ProcessResult(0, data, b""))
                with self.assertRaisesRegex(DockerError, "^INVALID_DOCKER_RESPONSE$"):
                    cli.engine_identity()


_EXITED = "a" * 64
# 2026-10-15T23:14:48.010683342Z, as Docker reports a container's death.
_DIED_NANOSECONDS = 1_792_106_088_010_683_342


def _die_event(**changes):
    event = {
        "Type": "container",
        "Action": "die",
        "Actor": {
            "ID": _EXITED,
            "Attributes": {"exitCode": "0", "failroom.kind": "diagnostic"},
        },
        "scope": "local",
        "time": _DIED_NANOSECONDS // 1_000_000_000,
        "timeNano": _DIED_NANOSECONDS,
    }
    event.update(changes)
    return json.dumps(event).encode()


class ContainerExitTests(unittest.TestCase):
    since = datetime(2026, 10, 15, 23, 14, 40, 500000, tzinfo=UTC)
    until = datetime(2026, 10, 15, 23, 14, 50, 200000, tzinfo=UTC)

    def cli(self, runner):
        return DockerCli(
            context="desktop-linux", timeout=5, max_output_bytes=65536, runner=runner
        )

    def test_reads_the_die_event_with_fixed_filters(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, _die_event() + b"\n", b"")

        record = self.cli(runner).container_exit(
            _EXITED, since=self.since, until=self.until
        )

        self.assertEqual(
            record,
            ContainerExit(0, datetime(2026, 10, 15, 23, 14, 48, 10683, tzinfo=UTC)),
        )
        self.assertEqual(
            calls,
            [
                (
                    "docker",
                    "--context",
                    "desktop-linux",
                    "events",
                    "--since",
                    "1792106080",
                    "--until",
                    "1792106091",
                    "--filter",
                    "type=container",
                    "--filter",
                    "container=" + _EXITED,
                    "--filter",
                    "event=die",
                    "--format",
                    "{{json .}}",
                )
            ],
        )

    def test_no_die_event_reads_as_none(self):
        cli = self.cli(lambda *a, **k: ProcessResult(0, b"", b""))
        self.assertIsNone(
            cli.container_exit(_EXITED, since=self.since, until=self.until)
        )

    def test_rejects_events_that_are_not_one_die_of_that_container(self):
        cases = {
            "two deaths": _die_event() + b"\n" + _die_event(),
            "other container": _die_event(Actor={"ID": "b" * 64, "Attributes": {}}),
            "other action": _die_event(Action="start"),
            "other type": _die_event(Type="network"),
            "exit code not a number": _die_event(
                Actor={"ID": _EXITED, "Attributes": {"exitCode": "zero"}}
            ),
            "exit code out of range": _die_event(
                Actor={"ID": _EXITED, "Attributes": {"exitCode": "1000"}}
            ),
            "missing exit code": _die_event(Actor={"ID": _EXITED, "Attributes": {}}),
            "missing attributes": _die_event(Actor={"ID": _EXITED}),
            "time not a number": _die_event(timeNano="1792106088010683342"),
            "time zero": _die_event(timeNano=0),
            "time too large": _die_event(timeNano=1 << 63),
            "duplicate key": b'{"Type": "container", "Type": "container"}',
            "not an object": b"[]",
            "not json": b"die",
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                cli = self.cli(lambda *a, data=data, **k: ProcessResult(0, data, b""))
                with self.assertRaisesRegex(DockerError, "^INVALID_DOCKER_RESPONSE$"):
                    cli.container_exit(_EXITED, since=self.since, until=self.until)

    def test_rejects_invalid_requests_before_any_docker_call(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return ProcessResult(0, b"", b"")

        cli = self.cli(runner)
        naive = datetime(2026, 10, 15, 23, 14, 40)
        for container_id, since, until in (
            ("failroom-diagnostic-" + "a" * 64, self.since, self.until),
            ("a" * 12, self.since, self.until),
            ("--privileged", self.since, self.until),
            (_EXITED, naive, self.until),
            (_EXITED, self.since, naive),
            (_EXITED, self.until, self.since),
        ):
            with (
                self.subTest(container_id=container_id, since=since, until=until),
                self.assertRaisesRegex(DockerError, "^INVALID_DOCKER_REQUEST$"),
            ):
                cli.container_exit(container_id, since=since, until=until)
        self.assertEqual(calls, [])

    def test_a_failed_events_call_is_not_read_as_no_exit(self):
        cli = self.cli(lambda *a, **k: ProcessResult(1, b"", b"daemon unavailable"))
        with self.assertRaisesRegex(DockerError, "^RUNTIME_UNAVAILABLE$"):
            cli.container_exit(_EXITED, since=self.since, until=self.until)


if __name__ == "__main__":
    unittest.main()
