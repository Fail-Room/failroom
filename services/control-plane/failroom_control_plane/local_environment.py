"""Read one explicit local operator environment file without shell evaluation."""

import os
import re
import stat
import sys

__all__ = ("LocalEnvironmentError", "load_operator_environment")

_MAX_BYTES = 65_536
_KEY = re.compile(r"[A-Z][A-Z0-9_]*")


class LocalEnvironmentError(ValueError):
    """Fixed rejection for untrusted local operator input files."""


def load_operator_environment(path: str) -> dict[str, str]:
    """Load an owner-only, non-symlinked Linux environment file."""
    try:
        if (
            sys.platform != "linux"
            or type(path) is not str
            or not os.path.isabs(path)
            or "\x00" in path
        ):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, min(65_536, _MAX_BYTES + 1 - total)):
                chunks.append(chunk)
                total += len(chunk)
                if total > _MAX_BYTES:
                    raise ValueError
        finally:
            os.close(descriptor)
        return _parse_environment(b"".join(chunks).decode("ascii"))
    except (OSError, UnicodeError, ValueError):
        raise LocalEnvironmentError("INVALID_CONFIGURATION") from None


def _parse_environment(document: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in document.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or _KEY.fullmatch(key) is None or key in values:
            raise ValueError
        values[key] = value
    return values
