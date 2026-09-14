"""Trusted Linux Docker PTY primitive with bounded session operations."""

import os
import re
import signal
import struct
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

try:
    import fcntl
    import termios
    import tty
except ImportError:  # pragma: no cover - exercised by non-Linux interpreters
    fcntl = None  # type: ignore[assignment]
    termios = None  # type: ignore[assignment]
    tty = None  # type: ignore[assignment]

_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_CONTEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_COMMAND = ("/bin/bash",)
_SIGNALS = frozenset({int(signal.SIGINT)})


class PtyError(RuntimeError):
    """A fixed PTY failure without command, path, or provider details."""

    def __init__(self, code: str) -> None:
        if code not in {
            "INVALID_CONFIGURATION",
            "INVALID_REQUEST",
            "PTY_UNAVAILABLE",
            "INPUT_LIMIT",
            "OUTPUT_LIMIT",
            "SESSION_EXPIRED",
        }:
            code = "PTY_UNAVAILABLE"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PtyLimits:
    input_bytes: int
    output_bytes: int
    session_seconds: int
    rows: int
    columns: int

    def __post_init__(self) -> None:
        if (
            type(self.input_bytes) is not int
            or not 1 <= self.input_bytes <= 1_048_576
            or type(self.output_bytes) is not int
            or not 1 <= self.output_bytes <= 16_777_216
            or type(self.session_seconds) is not int
            or not 1 <= self.session_seconds <= 3_600
            or type(self.rows) is not int
            or not 1 <= self.rows <= 500
            or type(self.columns) is not int
            or not 1 <= self.columns <= 1_000
        ):
            raise PtyError("INVALID_CONFIGURATION")


class PtySession(Protocol):
    def read(self, maximum: int) -> bytes: ...

    def write(self, data: bytes) -> None: ...

    def resize(self, rows: int, columns: int) -> None: ...

    def signal(self, value: int) -> None: ...

    def close(self) -> None: ...


class _Process(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


PtyOpener = Callable[[tuple[str, ...], int], _Process]


def _open_process(argv: tuple[str, ...], slave_fd: int) -> _Process:
    return subprocess.Popen(
        argv,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True,
    )


class _SubprocessPtySession:
    def __init__(self, master_fd: int, process: _Process, limits: PtyLimits) -> None:
        self._master_fd = master_fd
        self._process = process
        self._limits = limits
        self._started = time.monotonic()
        self._output_bytes = 0
        self._closed = False

    def _ensure_active(self) -> None:
        if self._closed:
            raise PtyError("PTY_UNAVAILABLE")
        if time.monotonic() - self._started >= self._limits.session_seconds:
            self.close()
            raise PtyError("SESSION_EXPIRED")

    def read(self, maximum: int) -> bytes:
        self._ensure_active()
        if type(maximum) is not int or not 1 <= maximum <= self._limits.output_bytes:
            raise PtyError("OUTPUT_LIMIT")
        remaining = self._limits.output_bytes - self._output_bytes
        if remaining <= 0:
            self.close()
            raise PtyError("OUTPUT_LIMIT")
        try:
            data = os.read(self._master_fd, min(maximum, remaining))
        except BlockingIOError:
            return b""
        except OSError:
            self.close()
            raise PtyError("PTY_UNAVAILABLE") from None
        self._output_bytes += len(data)
        return data

    def write(self, data: bytes) -> None:
        self._ensure_active()
        if type(data) is not bytes or len(data) > self._limits.input_bytes:
            raise PtyError("INPUT_LIMIT")
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(self._master_fd, remaining)
                remaining = remaining[written:]
        except OSError:
            self.close()
            raise PtyError("PTY_UNAVAILABLE") from None

    def resize(self, rows: int, columns: int) -> None:
        self._ensure_active()
        if (
            type(rows) is not int
            or type(columns) is not int
            or not 1 <= rows <= self._limits.rows
            or not 1 <= columns <= self._limits.columns
        ):
            raise PtyError("INVALID_REQUEST")
        if fcntl is None or termios is None:
            raise PtyError("PTY_UNAVAILABLE")
        try:
            fcntl.ioctl(  # type: ignore[attr-defined]
                self._master_fd,
                termios.TIOCSWINSZ,  # type: ignore[attr-defined]
                struct.pack("HHHH", rows, columns, 0, 0),
            )
        except OSError:
            self.close()
            raise PtyError("PTY_UNAVAILABLE") from None

    def signal(self, value: int) -> None:
        self._ensure_active()
        if type(value) is not int or value not in _SIGNALS:
            raise PtyError("INVALID_REQUEST")
        # Write the terminal interrupt byte so the remote PTY line discipline
        # signals its foreground process group without killing docker exec.
        self.write(b"\x03")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            try:
                os.killpg(  # type: ignore[attr-defined]
                    os.getpgid(self._process.pid),  # type: ignore[attr-defined]
                    signal.SIGTERM,
                )
            except (ProcessLookupError, OSError):
                pass
            try:
                self._process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                try:
                    self._process.kill()
                except OSError:
                    pass
                try:
                    self._process.wait(timeout=1.0)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        finally:
            try:
                os.close(self._master_fd)
            except OSError:
                pass


class DockerPtyRuntime:
    """Open one fixed `/bin/bash` PTY through the trusted Docker CLI."""

    def __init__(
        self,
        *,
        context: str,
        limits: PtyLimits,
        opener: PtyOpener = _open_process,
    ) -> None:
        if (
            type(context) is not str
            or _CONTEXT.fullmatch(context) is None
            or type(limits) is not PtyLimits
            or not callable(opener)
        ):
            raise PtyError("INVALID_CONFIGURATION")
        self._context = context
        self._limits = limits
        self._opener = opener

    def open(self, container_id: str, *, command: tuple[str, ...]) -> PtySession:
        if (
            type(container_id) is not str
            or _CONTAINER_ID.fullmatch(container_id) is None
            or command != _COMMAND
        ):
            raise PtyError("PTY_UNAVAILABLE")
        if sys.platform != "linux":
            raise PtyError("PTY_UNAVAILABLE")
        if tty is None:
            raise PtyError("PTY_UNAVAILABLE")
        master_fd, slave_fd = os.openpty()
        try:
            tty.setraw(slave_fd)
            argv = (
                "docker",
                "--context",
                self._context,
                "exec",
                "--interactive",
                "--tty",
                container_id,
                *_COMMAND,
            )
            process = self._opener(argv, slave_fd)
            os.close(slave_fd)
            os.set_blocking(master_fd, False)
            return _SubprocessPtySession(master_fd, process, self._limits)
        except Exception:
            try:
                os.close(slave_fd)
            except OSError:
                pass
            try:
                os.close(master_fd)
            except OSError:
                pass
            raise PtyError("PTY_UNAVAILABLE") from None
