"""Explicit bearer identity verification for the local trusted HTTP boundary."""

import hashlib
import hmac
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from failroom_state import UserIdentity

Clock = Callable[[], datetime]
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PREFIX = "Bearer "
_MIN_TOKEN_BYTES = 32
_MAX_TOKEN_BYTES = 4096


class AuthenticationError(Exception):
    """A fixed authentication failure without credential details."""

    def __init__(self, code: str) -> None:
        if code not in {
            "AUTHENTICATION_REQUIRED",
            "AUTHENTICATION_EXPIRED",
            "INVALID_CONFIGURATION",
        }:
            code = "AUTHENTICATION_REQUIRED"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class BearerCredential:
    """A hashed local bearer credential and its authenticated identity."""

    identity: UserIdentity
    expires_at: datetime


class IdentityVerifier(Protocol):
    def verify(self, authorization: str) -> UserIdentity: ...


def _clock(now: object) -> datetime:
    if not callable(now):
        raise AuthenticationError("INVALID_CONFIGURATION")
    try:
        value = now()
    except Exception:
        raise AuthenticationError("AUTHENTICATION_REQUIRED") from None
    if type(value) is not datetime or value.utcoffset() is None:
        raise AuthenticationError("AUTHENTICATION_REQUIRED")
    return value.astimezone(UTC)


class BearerIdentityVerifier:
    """Verify explicitly configured hashed bearer credentials."""

    def __init__(
        self,
        token_hashes: Mapping[str, BearerCredential],
        *,
        now: Clock,
    ) -> None:
        if not callable(now) or type(token_hashes) not in (dict,):
            raise AuthenticationError("INVALID_CONFIGURATION")
        if not token_hashes:
            raise AuthenticationError("INVALID_CONFIGURATION")
        credentials: dict[str, BearerCredential] = {}
        for digest, credential in token_hashes.items():
            if (
                type(digest) is not str
                or _DIGEST.fullmatch(digest) is None
                or type(credential) is not BearerCredential
                or type(credential.identity) is not UserIdentity
                or type(credential.expires_at) is not datetime
                or credential.expires_at.utcoffset() is None
            ):
                raise AuthenticationError("INVALID_CONFIGURATION")
            credentials[digest] = BearerCredential(
                credential.identity,
                credential.expires_at.astimezone(UTC),
            )
        self._credentials = credentials
        self._now = now

    def verify(self, authorization: str) -> UserIdentity:
        if type(authorization) is not str or not authorization.startswith(_PREFIX):
            raise AuthenticationError("AUTHENTICATION_REQUIRED")
        token = authorization[len(_PREFIX) :]
        try:
            encoded = token.encode("ascii")
        except UnicodeEncodeError:
            raise AuthenticationError("AUTHENTICATION_REQUIRED") from None
        if not _MIN_TOKEN_BYTES <= len(encoded) <= _MAX_TOKEN_BYTES:
            raise AuthenticationError("AUTHENTICATION_REQUIRED")
        candidate = hashlib.sha256(encoded).hexdigest()
        for digest, credential in self._credentials.items():
            if hmac.compare_digest(candidate, digest):
                if credential.expires_at <= _clock(self._now):
                    raise AuthenticationError("AUTHENTICATION_EXPIRED")
                return credential.identity
        raise AuthenticationError("AUTHENTICATION_REQUIRED")
