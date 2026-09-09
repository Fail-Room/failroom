import os
import select
import signal
import sys
import unittest

from failroom_sandbox.pty import (
    DockerPtyRuntime,
    PtyError,
    PtyLimits,
    _SubprocessPtySession,
)


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
                "/bin/bash",
            ),
        )


if __name__ == "__main__":
    unittest.main()
