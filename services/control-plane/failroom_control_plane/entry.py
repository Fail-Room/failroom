"""Trusted owner-scoped Enter Room composition."""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from failroom_state import (
    Action,
    BackendStore,
    Receipt,
    Role,
    ServiceIdentity,
    StoreError,
    UserIdentity,
)

Clock = Callable[[], datetime]


class EntryError(RuntimeError):
    """A fixed Enter Room failure without runtime or resource details."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in {"INVALID_CONFIGURATION", "ENTRY_FAILED"}
            else "ENTRY_FAILED"
        )
        super().__init__(self.code)


class Provisioner(Protocol):
    def provision(
        self,
        receipt: Receipt,
        *,
        backend_identity: ServiceIdentity,
        control_identity: ServiceIdentity,
        key: str,
        now: Clock,
    ) -> None: ...


@dataclass(frozen=True)
class RoomEntry:
    """Learner-safe result of one Enter Room request."""

    attempt_id: str
    room_id: str
    state: str
    expires_at: datetime


class RoomEntryService:
    """Create an owned attempt before provisioning its exact resource binding."""

    def __init__(
        self,
        backend: BackendStore,
        provisioner: Provisioner,
        *,
        backend_identity: ServiceIdentity,
        control_identity: ServiceIdentity,
        attempt_ttl: timedelta,
        now: Clock,
    ) -> None:
        if (
            type(backend) is not BackendStore
            or not callable(getattr(provisioner, "provision", None))
            or type(backend_identity) is not ServiceIdentity
            or backend_identity.role is not Role.BACKEND
            or not {Action.CREATE, Action.PUBLISH}.issubset(backend_identity.scopes)
            or type(control_identity) is not ServiceIdentity
            or control_identity.role is not Role.CONTROL_PLANE
            or not {Action.INSPECT, Action.TRANSITION}.issubset(control_identity.scopes)
            or type(attempt_ttl) is not timedelta
            or attempt_ttl <= timedelta(0)
            or not callable(now)
        ):
            raise EntryError("INVALID_CONFIGURATION")
        self._backend = backend
        self._provisioner = provisioner
        self._backend_identity = backend_identity
        self._control_identity = control_identity
        self._attempt_ttl = attempt_ttl
        self._now = now

    def enter(self, identity: UserIdentity, room_id: str, *, key: str) -> RoomEntry:
        expires_at = self._now() + self._attempt_ttl
        receipt = self._backend.create(
            identity,
            room_id,
            key=key,
            expires_at=expires_at,
            now=self._now,
        )
        try:
            self._provisioner.provision(
                receipt,
                backend_identity=self._backend_identity,
                control_identity=self._control_identity,
                key=key,
                now=self._now,
            )
        except Exception:
            try:
                self._backend.leave(
                    identity,
                    receipt.ref,
                    key=_failure_key(receipt, key),
                    now=self._now,
                )
            except StoreError:
                pass
            raise EntryError("ENTRY_FAILED") from None
        attempt = self._backend.inspect(identity, receipt.attempt_id)
        return RoomEntry(
            attempt_id=attempt.attempt_id,
            room_id=attempt.room_id,
            state=attempt.state,
            expires_at=attempt.expires_at,
        )


def _failure_key(receipt: Receipt, key: str) -> str:
    payload = (
        f"{receipt.ref.attempt_id}:{receipt.ref.sandbox_id}:"
        f"{receipt.ref.generation}:{key}"
    )
    return "entry-failed:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
