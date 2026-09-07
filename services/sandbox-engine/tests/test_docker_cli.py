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
