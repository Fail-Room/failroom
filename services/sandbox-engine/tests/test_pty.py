import os
import select
import signal
import sys
import unittest
from unittest.mock import patch

from failroom_sandbox import pty
from failroom_sandbox.pty import (
    _CLEANUP_SCRIPT,
    DockerPtyRuntime,
    PtyError,
    PtyLimits,
    _cleanup_argv,
    _parse_session_marker,
    _SubprocessPtySession,
)

_WRAPPER = (
    "/bin/sh",
    "-c",
    'printf "FAILROOM_PTY_SESSION=%s\\n" "$$"; exec /bin/bash',
)


class _Process:
    pid = 99_999_999

    def __init__(self, events: list[str] | None = None) -> None:
        self.events = [] if events is None else events

    def poll(self):
        return None

    def wait(self, timeout=None):
        self.events.append("client-wait")
        return 0

    def kill(self):
        self.events.append("client-kill")


class PtyRuntimeTests(unittest.TestCase):
    def limits(self) -> PtyLimits:
        return PtyLimits(
            input_bytes=4096,
            output_bytes=8192,
            session_seconds=60,
            rows=120,
            columns=200,
        )

    def test_invalid_container_selector_is_rejected_before_platform_check(self):
        runtime = DockerPtyRuntime(context="default", limits=self.limits())

        with self.assertRaises(PtyError) as raised:
            runtime.open("not-a-container", command=("/bin/bash",))

        self.assertEqual(raised.exception.code, "PTY_UNAVAILABLE")

    def test_non_bash_command_is_rejected_before_platform_check(self):
        runtime = DockerPtyRuntime(context="default", limits=self.limits())

        with self.assertRaises(PtyError) as raised:
            runtime.open("a" * 64, command=("/bin/sh",))

        self.assertEqual(raised.exception.code, "PTY_UNAVAILABLE")

    def test_invalid_limits_are_rejected(self):
        with self.assertRaises(PtyError) as raised:
            PtyLimits(
                input_bytes=0,
                output_bytes=8192,
                session_seconds=60,
                rows=120,
                columns=200,
            )

        self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")

    @unittest.skipUnless(sys.platform == "linux", "UNVERIFIED: Linux PTY required")
    def test_sigint_writes_ctrl_c_without_killing_docker_exec_client(self):
        read_fd, write_fd = os.pipe()

        class Process:
            pid = 99_999_999

            def poll(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        session = _SubprocessPtySession(write_fd, Process(), self.limits())
        try:
            session.signal(int(signal.SIGINT))
            ready, _, _ = select.select([read_fd], [], [], 0.1)
            self.assertEqual(os.read(read_fd, 1) if ready else b"", b"\x03")
        finally:
            session.close()
            os.close(read_fd)

    @unittest.skipUnless(sys.platform == "linux", "UNVERIFIED: Linux PTY required")
    def test_non_interrupt_signals_are_rejected_without_killing_session(self):
        read_fd, write_fd = os.pipe()

        class Process:
            pid = 99_999_999

            def poll(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        session = _SubprocessPtySession(write_fd, Process(), self.limits())
        try:
            with self.assertRaises(PtyError) as raised:
                session.signal(int(signal.SIGTERM))
            self.assertEqual(raised.exception.code, "INVALID_REQUEST")
        finally:
            session.close()
            os.close(read_fd)

    @unittest.skipUnless(sys.platform == "linux", "UNVERIFIED: Linux PTY required")
    def test_linux_open_uses_exact_docker_exec_argv(self):
        calls: list[tuple[tuple[str, ...], int]] = []

        def opener(argv: tuple[str, ...], slave_fd: int):
            calls.append((argv, slave_fd))
            raise RuntimeError("stop after argv capture")

        runtime = DockerPtyRuntime(
            context="desktop-linux", limits=self.limits(), opener=opener
        )
        with self.assertRaises(PtyError) as raised:
            runtime.open("a" * 64, command=("/bin/bash",))

        self.assertEqual(raised.exception.code, "PTY_UNAVAILABLE")
        self.assertEqual(
            calls[0][0],
            (
                "docker",
                "--context",
                "desktop-linux",
                "exec",
                "--interactive",
                "--tty",
                "a" * 64,
                *_WRAPPER,
            ),
        )

    def test_session_marker_must_lead_the_output(self):
        self.assertEqual(
            _parse_session_marker(b"FAILROOM_PTY_SESSION=42\r\nbash$ "),
            (42, b"bash$ "),
        )
        self.assertEqual(_parse_session_marker(b"FAILROOM_PTY_SESSION=7\n"), (7, b""))
        for rejected in (
            b"noise\nFAILROOM_PTY_SESSION=42\n",
            b"FAILROOM_PTY_SESSION=0\n",
            b"FAILROOM_PTY_SESSION=12345678901\n",
            b"FAILROOM_PTY_SESSION=42",
            b"FAILROOM_PTY_SESSION=4x2\n",
        ):
            with self.subTest(rejected=rejected):
                self.assertIsNone(_parse_session_marker(rejected))

    def test_cleanup_command_is_fixed_and_targets_only_the_session(self):
        self.assertEqual(
            _cleanup_argv("desktop-linux", "a" * 64, 42),
            (
                "docker",
                "--context",
                "desktop-linux",
                "exec",
                "a" * 64,
                "/bin/sh",
                "-c",
                _CLEANUP_SCRIPT,
                "failroom-pty-cleanup",
                "42",
            ),
        )
        # The session PID is passed as an argument, never interpolated.
        self.assertNotIn("42", _CLEANUP_SCRIPT)

    def test_cleanup_runner_must_be_callable(self):
        with self.assertRaises(PtyError) as raised:
            DockerPtyRuntime(
                context="default",
                limits=self.limits(),
                cleanup_runner=None,  # type: ignore[arg-type]
            )

        self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")

    @unittest.skipUnless(sys.platform == "linux", "UNVERIFIED: Linux PTY required")
    def test_open_consumes_marker_and_cleans_the_session_once(self):
        cleanups: list[tuple[str, ...]] = []

        def opener(argv: tuple[str, ...], slave_fd: int):
            os.write(slave_fd, b"FAILROOM_PTY_SESSION=31\r\nbash$ ")
            return _Process()

        runtime = DockerPtyRuntime(
            context="desktop-linux",
            limits=self.limits(),
            opener=opener,
            cleanup_runner=cleanups.append,
        )
        session = runtime.open("a" * 64, command=("/bin/bash",))
        self.assertEqual(session.read(100), b"bash$ ")

        session.close()
        session.close()

        self.assertEqual(cleanups, [_cleanup_argv("desktop-linux", "a" * 64, 31)])

    @unittest.skipUnless(sys.platform == "linux", "UNVERIFIED: Linux PTY required")
    def test_open_fails_closed_without_a_leading_marker(self):
        events: list[str] = []
        cleanups: list[tuple[str, ...]] = []

        def opener(argv: tuple[str, ...], slave_fd: int):
            os.write(slave_fd, b"bash$ echo FAILROOM_PTY_SESSION=1\n")
            return _Process(events)

        runtime = DockerPtyRuntime(
            context="default",
            limits=self.limits(),
            opener=opener,
            cleanup_runner=cleanups.append,
        )
        with self.assertRaises(PtyError) as raised:
            runtime.open("a" * 64, command=("/bin/bash",))

        self.assertEqual(raised.exception.code, "PTY_UNAVAILABLE")
        self.assertIn("client-wait", events)
        self.assertEqual(cleanups, [])

    @unittest.skipUnless(sys.platform == "linux", "UNVERIFIED: Linux PTY required")
    def test_open_fails_closed_when_the_marker_never_arrives(self):
        events: list[str] = []

        def opener(argv: tuple[str, ...], slave_fd: int):
            return _Process(events)

        runtime = DockerPtyRuntime(
            context="default", limits=self.limits(), opener=opener
        )
        with patch.object(pty, "_MARKER_TIMEOUT_SECONDS", 0.2):
            with self.assertRaises(PtyError) as raised:
                runtime.open("a" * 64, command=("/bin/bash",))

        self.assertEqual(raised.exception.code, "PTY_UNAVAILABLE")
        self.assertIn("client-wait", events)

    @unittest.skipUnless(sys.platform == "linux", "UNVERIFIED: Linux PTY required")
    def test_close_cleans_the_remote_session_before_the_local_client(self):
        read_fd, write_fd = os.pipe()
        events: list[str] = []
        session = _SubprocessPtySession(
            write_fd,
            _Process(events),
            self.limits(),
            cleanup=lambda: events.append("remote-cleanup"),
        )
        try:
            session.close()
            session.close()
        finally:
            os.close(read_fd)

        self.assertEqual(events, ["remote-cleanup", "client-wait"])

    @unittest.skipUnless(sys.platform == "linux", "UNVERIFIED: Linux PTY required")
    def test_output_after_the_marker_counts_toward_the_output_limit(self):
        read_fd, write_fd = os.pipe()
        limits = PtyLimits(
            input_bytes=16, output_bytes=8, session_seconds=60, rows=24, columns=80
        )
        session = _SubprocessPtySession(
            write_fd, _Process(), limits, pending=b"0123456789"
        )
        try:
            self.assertEqual(session.read(8), b"01234567")
            with self.assertRaises(PtyError) as raised:
                session.read(8)
            self.assertEqual(raised.exception.code, "OUTPUT_LIMIT")
        finally:
            session.close()
            os.close(read_fd)


if __name__ == "__main__":
    unittest.main()
