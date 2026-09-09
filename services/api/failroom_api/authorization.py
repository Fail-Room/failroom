"""Backend-owned capability issuance and authenticated introspection facade."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from failroom_state import (
    BackendStore,
    CapabilityClaims,
    CapabilityUse,
    ResourceRef,
    ServiceIdentity,
    StoreError,
    UserIdentity,
)

from .capability import CapabilityCodec, CapabilityError

Clock = Callable[[], datetime]
_ATTACHABLE_STATES = frozenset({"READY", "RUNNING"})
_SAFE_CODES = frozenset(
    {
        "ATTEMPT_UNAVAILABLE",
        "CAPABILITY_EXPIRED",
        "CAPABILITY_INVALID",
        "CAPABILITY_LIFETIME",
        "CAPABILITY_REPLAY",
        "INVALID_REQUEST",
        "NOT_AUTHORIZED",
        "STORE_BUSY",
        "STORE_FAILURE",
    }
)


class AuthorityError(Exception):
    """A fixed authority failure without token, claim or storage details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class IssuedCapability:
    """The backend response carrying one short-lived capability."""

    token: str
    ref: ResourceRef
    expires_at: datetime


def _clock(now: object) -> datetime:
    if not callable(now):
        raise AuthorityError("INVALID_REQUEST")
    try:
        value = now()
    except Exception:
        raise AuthorityError("INVALID_REQUEST") from None
    if type(value) is not datetime or value.utcoffset() is None:
        raise AuthorityError("INVALID_REQUEST")
    return value.astimezone(UTC)


def _authority_error(error: StoreError | CapabilityError) -> AuthorityError:
    code = error.code
    return AuthorityError(code if code in _SAFE_CODES else "AUTHORIZATION_FAILED")


class BackendCapabilityAuthority:
    """Compose owned attempt authority with the bounded capability codec."""

    def __init__(self, backend: BackendStore, codec: CapabilityCodec) -> None:
        if type(backend) is not BackendStore or type(codec) is not CapabilityCodec:
            raise AuthorityError("INVALID_CONFIGURATION")
        self._backend = backend
        self._codec = codec

    def issue(
        self,
        identity: UserIdentity,
        attempt_id: str,
        *,
        now: Clock,
    ) -> IssuedCapability:
        clock = _clock(now)
        try:
            attempt = self._backend.inspect(identity, attempt_id)
            if (
                attempt.state not in _ATTACHABLE_STATES
                or attempt.active_sandbox_id != attempt.ref.sandbox_id
                or attempt.expiry_intent
                or attempt.destroy_intent
                or attempt.expires_at <= clock
            ):
                raise AuthorityError("ATTEMPT_UNAVAILABLE")
            expires_at = min(attempt.expires_at, clock + self._codec.max_lifetime)
            claims = self._codec.issue(
                CapabilityClaims(
                    uuid4().hex,
                    identity.user_id,
                    attempt.ref,
                    attempt.session_epoch,
                    expires_at,
                    "terminal:attach",
                ),
                now=lambda: clock,
            )
            return IssuedCapability(claims, attempt.ref, expires_at)
        except AuthorityError:
            raise
        except (StoreError, CapabilityError) as error:
            raise _authority_error(error) from None

    def introspect_and_consume(
        self,
        token: str,
        identity: ServiceIdentity,
        *,
        now: Clock,
    ) -> CapabilityUse:
        try:
            claims = self._codec.verify(token, now=now)
            return self._backend.consume(identity, claims, now=now)
        except (StoreError, CapabilityError) as error:
            raise _authority_error(error) from None
        except Exception:
            raise AuthorityError("AUTHORIZATION_FAILED") from None
