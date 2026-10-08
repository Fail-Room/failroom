"""Trusted Linux Docker PTY primitive with bounded session operations."""

import os
import re
import select
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
# The wrapper reports its in-container PID before any learner input and then
# becomes /bin/bash, so that PID identifies the shell's session.
_SESSION_WRAPPER = (
    "/bin/sh",
    "-c",
    'printf "FAILROOM_PTY_SESSION=%s\\n" "$$"; exec /bin/bash',
)
_SESSION_MARKER = re.compile(rb"FAILROOM_PTY_SESSION=([1-9][0-9]{0,9})\r?\n")
_MARKER_MAX_BYTES = 64
_MARKER_TIMEOUT_SECONDS = 10.0
_CLEANUP_TIMEOUT_SECONDS = 10.0
# Kills every live process of the shell's session: members first so the shell
# can still reap them, then the shell. Processes that left the session with
# setsid are bounded by the sandbox's PID 1 lifetime instead.
_CLEANUP_SCRIPT = r"""target=$1
case $target in ''|*[!0-9]*) exit 2 ;; esac
members() {
  for stat in /proc/[0-9]*/stat; do
    read -r line 2>/dev/null <"$stat" || continue
    pid=${line%% *}
    rest=${line##*") "}
    set -- $rest
    [ "$1" != Z ] && [ "$4" = "$target" ] && printf '%s\n' "$pid"
  done
}
pass=0
while [ "$pass" -lt 5 ]; do
  pass=$((pass + 1))
  found=0
  for pid in $(members); do
    found=1
    [ "$pid" = "$target" ] || kill -KILL "$pid" 2>/dev/null
  done
  [ "$found" = 0 ] && exit 0
  sleep 0.2
  kill -KILL "$target" 2>/dev/null
done
exit 0"""


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
PtyCleanup = Callable[[tuple[str, ...]], None]


def _open_process(argv: tuple[str, ...], slave_fd: int) -> _Process:
    return subprocess.Popen(
        argv,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True,
    )


def _run_cleanup(argv: tuple[str, ...]) -> None:
    subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=_CLEANUP_TIMEOUT_SECONDS,
        check=False,
    )


def _parse_session_marker(buffer: bytes) -> tuple[int, bytes] | None:
    """Return the session PID and the output after a complete marker line."""
    match = _SESSION_MARKER.match(buffer)
    if match is None:
        return None
    return int(match.group(1)), buffer[match.end() :]


def _read_session_marker(master_fd: int) -> tuple[int, bytes]:
    deadline = time.monotonic() + _MARKER_TIMEOUT_SECONDS
    buffer = b""
    while b"\n" not in buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(buffer) >= _MARKER_MAX_BYTES:
            raise PtyError("PTY_UNAVAILABLE")
        ready, _, _ = select.select([master_fd], [], [], remaining)
        if not ready:
            continue
        try:
            chunk = os.read(master_fd, _MARKER_MAX_BYTES - len(buffer))
        except BlockingIOError:
            continue
        except OSError:
            raise PtyError("PTY_UNAVAILABLE") from None
        if not chunk:
            raise PtyError("PTY_UNAVAILABLE")
        buffer += chunk
    parsed = _parse_session_marker(buffer)
    if parsed is None:
        raise PtyError("PTY_UNAVAILABLE")
    return parsed


def _cleanup_argv(context: str, container_id: str, session: int) -> tuple[str, ...]:
    return (
        "docker",
        "--context",
        context,
        "exec",
        container_id,
        "/bin/sh",
        "-c",
        _CLEANUP_SCRIPT,
        "failroom-pty-cleanup",
        str(session),
    )


def _terminate_client(process: _Process) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (ProcessLookupError, OSError):
        pass
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            pass


class _SubprocessPtySession:
    def __init__(
        self,
        master_fd: int,
        process: _Process,
        limits: PtyLimits,
        *,
        pending: bytes = b"",
        cleanup: Callable[[], None] | None = None,
    ) -> None:
        self._master_fd = master_fd
        self._process = process
        self._limits = limits
        self._pending = pending
        self._cleanup = cleanup
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
        if self._pending:
            data = self._pending[: min(maximum, remaining)]
            self._pending = self._pending[len(data) :]
            self._output_bytes += len(data)
            return data
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
            fcntl.ioctl(
                self._master_fd,
                termios.TIOCSWINSZ,
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
            # Stop the shell's session inside the sandbox before the local
            # client; ending `docker exec` alone leaves the remote shell running.
            if self._cleanup is not None:
                try:
                    self._cleanup()
                except Exception:
                    pass
            _terminate_client(self._process)
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
        cleanup_runner: PtyCleanup = _run_cleanup,
    ) -> None:
        if (
            type(context) is not str
            or _CONTEXT.fullmatch(context) is None
            or type(limits) is not PtyLimits
            or not callable(opener)
            or not callable(cleanup_runner)
        ):
            raise PtyError("INVALID_CONFIGURATION")
        self._context = context
        self._limits = limits
        self._opener = opener
        self._cleanup_runner = cleanup_runner

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
        process: _Process | None = None
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
                *_SESSION_WRAPPER,
            )
            process = self._opener(argv, slave_fd)
            os.close(slave_fd)
            slave_fd = -1
            os.set_blocking(master_fd, False)
            session, pending = _read_session_marker(master_fd)
            cleanup_argv = _cleanup_argv(self._context, container_id, session)
            runner = self._cleanup_runner
            return _SubprocessPtySession(
                master_fd,
                process,
                self._limits,
                pending=pending,
                cleanup=lambda: runner(cleanup_argv),
            )
        except Exception:
            if process is not None:
                _terminate_client(process)
            for descriptor in (slave_fd, master_fd):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            raise PtyError("PTY_UNAVAILABLE") from None
