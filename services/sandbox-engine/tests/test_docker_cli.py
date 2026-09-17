import subprocess
import sys
import unittest

from failroom_sandbox.docker_cli import (
    DockerCli,
    DockerError,
    ProcessResult,
    _run_process,
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
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(
                DockerError, "^INVALID_DOCKER_REQUEST$"
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

        self.assertTrue(
            cli.disk_full_filler_absent("a" * 64, uid=1000, gid=1000)
        )
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
        results = iter((ProcessResult(1, b"", b""), ProcessResult(0, b"", b""), ProcessResult(0, b"", b"")))
        cli = DockerCli(context="desktop-linux", timeout=5, max_output_bytes=1024, runner=lambda argv, **kwargs: (calls.append(argv), next(results))[1])

        self.assertTrue(cli.disk_full_target_initialization_failed("a" * 64, uid=1000, gid=1000))
        cli.start_disk_full_target("a" * 64, uid=1000, gid=1000)
        self.assertTrue(cli.disk_full_target_healthy("a" * 64, uid=1000, gid=1000))

        self.assertEqual(calls[0][-2:], ("/usr/local/bin/failroom-disk-target", "initialize"))
        self.assertEqual(calls[1][4:7], ("exec", "--detach", "--user"))
        self.assertEqual(calls[2][-2:], ("/usr/local/bin/failroom-disk-target", "status"))

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

        self.assertEqual(calls, [("docker", "--context", "desktop-linux", "image", "inspect", image_id)])

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
