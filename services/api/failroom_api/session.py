"""HttpOnly browser sessions opened from an already verified credential."""

import hashlib
import math
import re
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from failroom_state import UserIdentity

from .authentication import AuthenticationError, _clock

Clock = Callable[[], datetime]
_TOKEN_BYTES = 32
# token_urlsafe(32) is 43 characters from the URL-safe base64 alphabet.
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_MIN_LIFETIME = timedelta(seconds=60)
_MAX_LIFETIME = timedelta(hours=12)
_MAX_SESSIONS = 64


@dataclass(frozen=True)
class IssuedSession:
    """A new session token, returned once so the caller can set its cookie."""

    token: str
    expires_at: datetime
    lifetime_seconds: int


@dataclass(frozen=True)
class _Session:
    identity: UserIdentity
    expires_at: datetime


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class BrowserSessionAuthority:
    """Open, verify and close browser sessions for verified identities.

    It keeps only the SHA-256 digest of each token, in process memory, so a
    restart ends every session. A session ends at the earlier of its lifetime
    and the expiry of the credential that opened it. At most ``max_sessions``
    exist; opening another ends the one that expires first.
    """

    def __init__(self, *, lifetime: timedelta, max_sessions: int, now: Clock) -> None:
        if (
            type(lifetime) is not timedelta
            or not _MIN_LIFETIME <= lifetime <= _MAX_LIFETIME
            or type(max_sessions) is not int
            or not 1 <= max_sessions <= _MAX_SESSIONS
            or not callable(now)
        ):
            raise AuthenticationError("INVALID_CONFIGURATION")
        self._lifetime = lifetime
        self._max_sessions = max_sessions
        self._now = now
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    def open(
        self, identity: UserIdentity, *, credential_expires_at: datetime
    ) -> IssuedSession:
        if (
            type(identity) is not UserIdentity
            or type(credential_expires_at) is not datetime
            or credential_expires_at.utcoffset() is None
        ):
            raise AuthenticationError("INVALID_CONFIGURATION")
        current = _clock(self._now)
        expires_at = min(
            current + self._lifetime, credential_expires_at.astimezone(UTC)
        )
        lifetime_seconds = math.floor((expires_at - current).total_seconds())
        if lifetime_seconds < 1:
            raise AuthenticationError("AUTHENTICATION_EXPIRED")
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        with self._lock:
            self._sessions = {
                digest: session
                for digest, session in self._sessions.items()
                if session.expires_at > current
            }
            while len(self._sessions) >= self._max_sessions:
                soonest = min(
                    self._sessions, key=lambda digest: self._sessions[digest].expires_at
                )
                del self._sessions[soonest]
            self._sessions[_digest(token)] = _Session(identity, expires_at)
        return IssuedSession(token, expires_at, lifetime_seconds)

    def verify(self, token: str) -> UserIdentity:
        if type(token) is not str or _TOKEN.fullmatch(token) is None:
            raise AuthenticationError("AUTHENTICATION_REQUIRED")
        digest = _digest(token)
        current = _clock(self._now)
        with self._lock:
            session = self._sessions.get(digest)
            if session is None:
                raise AuthenticationError("AUTHENTICATION_REQUIRED")
            if session.expires_at <= current:
                del self._sessions[digest]
                raise AuthenticationError("AUTHENTICATION_EXPIRED")
            return session.identity

    def close(self, token: str) -> None:
        """End one session; an unknown or malformed token is already ended."""
        if type(token) is not str or _TOKEN.fullmatch(token) is None:
            return
        with self._lock:
            self._sessions.pop(_digest(token), None)
