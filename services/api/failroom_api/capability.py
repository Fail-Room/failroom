"""Bounded HMAC capability codec; transport authentication remains external."""

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from failroom_state import CapabilityClaims, ResourceRef

Clock = Callable[[], datetime]
_MAX_TOKEN_BYTES = 4096
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_HEX_JTI = re.compile(r"^[0-9a-f]{32}$")
_HEX_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_HEADER = {"alg": "HS256", "typ": "FAILROOM_CAPABILITY", "v": 1}
_FIELDS = {
    "jti",
    "user_id",
    "attempt_id",
    "sandbox_id",
    "generation",
    "session_epoch",
    "expires_at",
    "scope",
}


class CapabilityError(Exception):
    """A fixed capability failure without token, key or claim details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _timestamp(value: datetime) -> int:
    if type(value) is not datetime or value.utcoffset() is None:
        raise CapabilityError("INVALID_REQUEST")
    utc = value.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc - epoch
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _instant(value: int) -> datetime:
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    return epoch + timedelta(microseconds=value)


def _clock(now: object) -> datetime:
    if not callable(now):
        raise CapabilityError("INVALID_REQUEST")
    try:
        value = now()
    except Exception:
        raise CapabilityError("INVALID_REQUEST") from None
    if type(value) is not datetime or value.utcoffset() is None:
        raise CapabilityError("INVALID_REQUEST")
    return value


def _segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_segment(value: str) -> bytes:
    if type(value) is not str or not _HEX_SEGMENT.fullmatch(value):
        raise CapabilityError("CAPABILITY_INVALID")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError, UnicodeError):
        raise CapabilityError("CAPABILITY_INVALID") from None


def _json_segment(value: object) -> str:
    return _segment(
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _validate_claims(claims: object) -> None:
    if type(claims) is not CapabilityClaims:
        raise CapabilityError("CAPABILITY_INVALID")
    if type(claims.jti) is not str or _HEX_JTI.fullmatch(claims.jti) is None:
        raise CapabilityError("CAPABILITY_INVALID")
    if (
        type(claims.user_id) is not str
        or _IDENTIFIER.fullmatch(claims.user_id) is None
        or type(claims.ref) is not ResourceRef
        or type(claims.ref.attempt_id) is not str
        or _IDENTIFIER.fullmatch(claims.ref.attempt_id) is None
        or type(claims.ref.sandbox_id) is not str
        or _IDENTIFIER.fullmatch(claims.ref.sandbox_id) is None
        or type(claims.ref.generation) is not int
        or claims.ref.generation < 1
        or type(claims.session_epoch) is not int
        or claims.session_epoch < 0
    ):
        raise CapabilityError("CAPABILITY_INVALID")
    if claims.scope != "terminal:attach":
        raise CapabilityError("CAPABILITY_SCOPE")
    _timestamp(claims.expires_at)


class CapabilityCodec:
    """Issue and verify one bounded, short-lived signed terminal capability."""

    def __init__(self, secret: bytes, *, max_lifetime: timedelta) -> None:
        if (
            type(secret) is not bytes
            or len(secret) < 32
            or type(max_lifetime) is not timedelta
        ):
            raise CapabilityError("INVALID_CONFIGURATION")
        lifetime = (
            max_lifetime.days * 86_400_000_000
            + max_lifetime.seconds * 1_000_000
            + max_lifetime.microseconds
        )
        if not 1 <= lifetime <= 300_000_000:
            raise CapabilityError("INVALID_CONFIGURATION")
        self._secret = secret
        self._max_lifetime = lifetime

    @property
    def max_lifetime(self) -> timedelta:
        return timedelta(microseconds=self._max_lifetime)

    def issue(self, claims: CapabilityClaims, *, now: Clock) -> str:
        _validate_claims(claims)
        clock = _clock(now)
        clock_us = _timestamp(clock)
        expires_at = _timestamp(claims.expires_at)
        if expires_at <= clock_us:
            raise CapabilityError("CAPABILITY_EXPIRED")
        if expires_at - clock_us > self._max_lifetime:
            raise CapabilityError("CAPABILITY_LIFETIME")
        payload = {
            "attempt_id": claims.ref.attempt_id,
            "expires_at": expires_at,
            "generation": claims.ref.generation,
            "jti": claims.jti,
            "sandbox_id": claims.ref.sandbox_id,
            "scope": claims.scope,
            "session_epoch": claims.session_epoch,
            "user_id": claims.user_id,
        }
        encoded_header = _json_segment(_HEADER)
        encoded_payload = _json_segment(payload)
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        token = f"{encoded_header}.{encoded_payload}.{_segment(signature)}"
        if len(token.encode("ascii")) > _MAX_TOKEN_BYTES:
            raise CapabilityError("CAPABILITY_LIFETIME")
        return token

    def verify(self, token: str, *, now: Clock) -> CapabilityClaims:
        if type(token) is not str or len(token.encode("utf-8")) > _MAX_TOKEN_BYTES:
            raise CapabilityError("CAPABILITY_INVALID")
        parts = token.split(".")
        if len(parts) != 3 or any(not part for part in parts):
            raise CapabilityError("CAPABILITY_INVALID")
        encoded_header, encoded_payload, encoded_signature = parts
        header_bytes = _decode_segment(encoded_header)
        payload_bytes = _decode_segment(encoded_payload)
        signature = _decode_segment(encoded_signature)
        try:
            header = json.loads(header_bytes)
            payload = json.loads(payload_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CapabilityError("CAPABILITY_INVALID") from None
        if header != _HEADER or type(payload) is not dict or set(payload) != _FIELDS:
            raise CapabilityError("CAPABILITY_INVALID")
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise CapabilityError("CAPABILITY_INVALID")
        try:
            jti = payload["jti"]
            user_id = payload["user_id"]
            attempt_id = payload["attempt_id"]
            sandbox_id = payload["sandbox_id"]
            generation = payload["generation"]
            session_epoch = payload["session_epoch"]
            expires_at = payload["expires_at"]
            scope = payload["scope"]
            if (
                type(jti) is not str
                or type(user_id) is not str
                or type(attempt_id) is not str
                or type(sandbox_id) is not str
                or type(generation) is not int
                or type(session_epoch) is not int
                or type(expires_at) is not int
                or type(scope) is not str
            ):
                raise ValueError
            claims = CapabilityClaims(
                jti,
                user_id,
                ResourceRef(attempt_id, sandbox_id, generation),
                session_epoch,
                _instant(expires_at),
                scope,
            )
            _validate_claims(claims)
        except (CapabilityError, OverflowError, ValueError):
            raise CapabilityError("CAPABILITY_INVALID") from None
        clock_us = _timestamp(_clock(now))
        if expires_at <= clock_us:
            raise CapabilityError("CAPABILITY_EXPIRED")
        if expires_at - clock_us > self._max_lifetime:
            raise CapabilityError("CAPABILITY_LIFETIME")
        return claims
