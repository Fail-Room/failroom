"""One private scratch directory held by one qualification collection at a time.

Linux is required. The workspace is a fixed directory next to the operator
database, owned by the control-plane UID with mode 0700. A collection holds an
exclusive `flock` on its lock file for its whole duration, and the kernel
releases the lock when the process ends, so anything a collection finds in the
workspace once it holds the lock was left by a collection that is gone. The
lock file is never removed, so two collections can never lock different files.
Root and other processes of the control-plane UID remain trusted.
"""

import os
import stat
import sys
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Protocol, runtime_checkable

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by non-Linux interpreters
    fcntl = None  # type: ignore[assignment]

WORKSPACE_NAME = "failroom-qualification"
LOCK_NAME = "collector.lock"


class WorkspaceError(RuntimeError):
    """A fixed workspace failure without paths or operating-system text."""

    def __init__(self, code: str) -> None:
        if code not in {
            "COLLECTION_IN_PROGRESS",
            "WORKSPACE_UNAVAILABLE",
            "WORKSPACE_UNSAFE",
        }:
            code = "WORKSPACE_UNAVAILABLE"
        self.code = code
        super().__init__(code)


@runtime_checkable
class CollectionWorkspace(Protocol):
    def hold(self) -> AbstractContextManager[Path]: ...


class LockedWorkspace:
    """Create or reuse the private workspace and hold its exclusive lock."""

    def __init__(self, parent: Path) -> None:
        if not isinstance(parent, Path) or not parent.is_absolute():
            raise WorkspaceError("WORKSPACE_UNSAFE")
        self.path = parent / WORKSPACE_NAME

    @contextmanager
    def hold(self) -> Iterator[Path]:
        if sys.platform != "linux" or fcntl is None:
            raise WorkspaceError("WORKSPACE_UNAVAILABLE")
        try:
            os.mkdir(self.path, 0o700)
        except FileExistsError:
            pass
        except OSError:
            raise WorkspaceError("WORKSPACE_UNAVAILABLE") from None
        directory = lock = -1
        try:
            try:
                directory = os.open(
                    self.path,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                lock = os.open(
                    LOCK_NAME,
                    os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory,
                )
                directory_info = os.fstat(directory)
                lock_info = os.fstat(lock)
            except OSError:
                raise WorkspaceError("WORKSPACE_UNSAFE") from None
            uid = os.geteuid()
            if (
                directory_info.st_uid != uid
                or stat.S_IMODE(directory_info.st_mode) != 0o700
                or not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != uid
            ):
                raise WorkspaceError("WORKSPACE_UNSAFE")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise WorkspaceError("COLLECTION_IN_PROGRESS") from None
            except OSError:
                raise WorkspaceError("WORKSPACE_UNAVAILABLE") from None
            yield self.path
        finally:
            # Closing the lock descriptor releases the lock.
            for descriptor in (lock, directory):
                if descriptor >= 0:
                    os.close(descriptor)
