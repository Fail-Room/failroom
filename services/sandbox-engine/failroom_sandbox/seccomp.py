"""Pin verified seccomp bytes for the lifetime of a Docker CLI operation.

Linux is required. The configured store must already exist, be owned by the
control-plane UID with mode 0700, and never be exposed to a sandbox. Ancestors
must belong to root or that UID and prevent other users from replacing entries.
Root-owned sticky directories (for example an OS temporary directory) are valid
ancestors. Root and other processes of the control-plane UID remain trusted;
these filesystem permissions do not isolate mutually hostile same-UID services.

Each pin owns a private subdirectory and a read-only, content-addressed file.
The caller must finish the CLI read before leaving the context. Cleanup uses
held directory descriptors and occurs on normal and exceptional context exit.
"""

import hashlib
import os
import re
import secrets
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

__all__ = ("SeccompError", "SeccompPolicyStore")

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class SeccompError(ValueError):
    """A fixed, code-owned failure without paths or raw operating-system text."""


def _parts(path: str) -> list[str]:
    if not path.startswith("/") or "\x00" in path:
        raise ValueError
    parts = path.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValueError
    return parts


def _trusted_directory(descriptor: int, *, leaf: bool) -> None:
    if sys.platform != "linux":
        raise SeccompError("SECCOMP_PLATFORM_UNSUPPORTED")
    info = os.fstat(descriptor)
    mode = stat.S_IMODE(info.st_mode)
    uid = os.geteuid()
    if leaf:
        safe = info.st_uid == uid and mode == 0o700
    else:
        safe = info.st_uid in (0, uid) and (
            mode & 0o022 == 0 or (info.st_uid == 0 and mode & stat.S_ISVTX != 0)
        )
    if not stat.S_ISDIR(info.st_mode) or not safe:
        raise ValueError


def _open_directory(parts: list[str], *, trusted: bool) -> int:
    if sys.platform != "linux":
        raise SeccompError("SECCOMP_PLATFORM_UNSUPPORTED")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        if trusted:
            _trusted_directory(descriptor, leaf=False)
        for index, part in enumerate(parts):
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            if trusted:
                _trusted_directory(descriptor, leaf=index == len(parts) - 1)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_policy(source_path: str, expected_digest: str, max_bytes: int) -> bytes:
    if sys.platform != "linux":
        raise SeccompError("SECCOMP_PLATFORM_UNSUPPORTED")
    try:
        if type(source_path) is not str or type(expected_digest) is not str:
            raise ValueError
        if _DIGEST.fullmatch(expected_digest) is None:
            raise ValueError
        parts = _parts(source_path)
        directory = _open_directory(parts[:-1], trusted=False)
        try:
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=directory,
            )
        finally:
            os.close(directory)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
                raise ValueError
            content = bytearray()
            while chunk := os.read(
                descriptor, min(65_536, max_bytes + 1 - len(content))
            ):
                content.extend(chunk)
                if len(content) > max_bytes:
                    raise ValueError
            if "sha256:" + hashlib.sha256(content).hexdigest() != expected_digest:
                raise ValueError
            return bytes(content)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise SeccompError("SECCOMP_POLICY_INVALID") from None


class SeccompPolicyStore:
    """Use an explicitly provisioned, private local directory for ephemeral pins."""

    _parts: list[str]
    _directory: Path
    _max_bytes: int

    def __init__(self, directory: Path, *, max_bytes: int) -> None:
        if sys.platform != "linux" or os.name != "posix":
            raise SeccompError("SECCOMP_PLATFORM_UNSUPPORTED")
        try:
            if not isinstance(directory, Path) or type(max_bytes) is not int:
                raise ValueError
            if max_bytes <= 0:
                raise ValueError
            self._parts = _parts(str(directory))
        except ValueError:
            raise SeccompError("INVALID_SECCOMP_CONFIGURATION") from None
        self._directory = directory
        self._max_bytes = max_bytes

    @contextmanager
    def pin(self, source_path: str, expected_digest: str) -> Iterator[str]:
        """Yield a private snapshot path while descriptors hold its cleanup scope."""
        try:
            store_descriptor = _open_directory(self._parts, trusted=True)
        except (OSError, ValueError):
            raise SeccompError("SECCOMP_STORE_UNSAFE") from None
        try:
            content = _read_policy(source_path, expected_digest, self._max_bytes)
            with self._snapshot(store_descriptor, content, expected_digest) as path:
                yield path
        finally:
            os.close(store_descriptor)

    @contextmanager
    def _snapshot(
        self, store_descriptor: int, content: bytes, digest: str
    ) -> Iterator[str]:
        if sys.platform != "linux":
            raise SeccompError("SECCOMP_PLATFORM_UNSUPPORTED")
        name = "pin-" + secrets.token_hex(16)
        filename = digest.removeprefix("sha256:") + ".json"
        directory_created = False
        file_created = False
        directory_descriptor: int | None = None
        try:
            try:
                os.mkdir(name, mode=0o700, dir_fd=store_descriptor)
                directory_created = True
                directory_descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=store_descriptor,
                )
                _trusted_directory(directory_descriptor, leaf=True)
                descriptor = os.open(
                    filename,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    mode=0o600,
                    dir_fd=directory_descriptor,
                )
                file_created = True
                try:
                    remaining = memoryview(content)
                    while remaining:
                        written = os.write(descriptor, remaining)
                        if written <= 0:
                            raise ValueError
                        remaining = remaining[written:]
                    os.fchmod(descriptor, 0o400)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except (OSError, ValueError):
                raise SeccompError("SECCOMP_SNAPSHOT_FAILED") from None
            yield str(self._directory / name / filename)
        finally:
            try:
                if directory_descriptor is not None:
                    try:
                        if file_created:
                            os.unlink(filename, dir_fd=directory_descriptor)
                    finally:
                        os.close(directory_descriptor)
                if directory_created:
                    os.rmdir(name, dir_fd=store_descriptor)
            except OSError:
                raise SeccompError("SECCOMP_SNAPSHOT_FAILED") from None
