"""Trusted in-process terminal capability-to-lease coordination."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from failroom_api import AuthorityError, BackendCapabilityAuthority
from failroom_state import (
    Action,
    AttachmentLease,
    CapabilityUse,
    ControlPlaneStore,
    Role,
    ServiceIdentity,
    StoreError,
)

Clock = Callable[[], datetime]
_SAFE_CODES = frozenset(
    {
        "ATTEMPT_UNAVAILABLE",
        "CAPABILITY_EXPIRED",
        "CAPABILITY_INVALID",
        "CAPABILITY_LIFETIME",
        "CAPABILITY_REPLAY",
        "IDEMPOTENCY_CONFLICT",
        "INVALID_REQUEST",
        "NOT_AUTHORIZED",
        "STORE_BUSY",
        "STORE_FAILURE",
    }
)


class GatewayError(Exception):
    """A fixed gateway failure without token or provider details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class GatewayAttachment:
    """Non-secret results needed by the trusted PTY adapter."""

    consumed: CapabilityUse
    lease: AttachmentLease


def _gateway_error(error: AuthorityError | StoreError) -> GatewayError:
    code = error.code
    return GatewayError(code if code in _SAFE_CODES else "GATEWAY_FAILURE")


class TerminalGatewayAuthority:
    """Consume one capability and obtain its immediate attachment lease."""

    def __init__(
        self,
        authority: BackendCapabilityAuthority,
        control: ControlPlaneStore,
        identity: ServiceIdentity,
        *,
        lease_duration: timedelta,
    ) -> None:
        if (
            type(authority) is not BackendCapabilityAuthority
            or type(control) is not ControlPlaneStore
            or type(identity) is not ServiceIdentity
            or identity.role is not Role.GATEWAY
            or not {Action.CONSUME, Action.ATTACH} <= identity.scopes
            or type(lease_duration) is not timedelta
        ):
            raise GatewayError("INVALID_CONFIGURATION")
        duration_micros = (
            lease_duration.days * 86_400_000_000
            + lease_duration.seconds * 1_000_000
            + lease_duration.microseconds
        )
        if not 1 <= duration_micros <= 60_000_000:
            raise GatewayError("INVALID_CONFIGURATION")
        self._authority = authority
        self._control = control
        self._identity = identity
        self._lease_duration = lease_duration

    def authorize_and_lease(
        self,
        token: str,
        *,
        gateway_session_id: str,
        idempotency_key: str,
        now: Clock,
    ) -> GatewayAttachment:
        try:
            consumed = self._authority.introspect_and_consume(
                token,
                self._identity,
                now=now,
            )
            lease = self._control.grant_attachment_lease(
                self._identity,
                consumed.ref,
                consumed=consumed,
                gateway_session_id=gateway_session_id,
                lease_duration=self._lease_duration,
                key=idempotency_key,
                now=now,
            )
            return GatewayAttachment(consumed, lease)
        except (AuthorityError, StoreError) as error:
            raise _gateway_error(error) from None
        except Exception:
            raise GatewayError("GATEWAY_FAILURE") from None
