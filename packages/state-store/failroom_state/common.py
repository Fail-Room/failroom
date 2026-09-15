"""Internal validation and transactional operation log helpers."""

import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from .models import (
    Action,
    Attempt,
    Receipt,
    ResourceRef,
    Role,
    ServiceIdentity,
    StoreError,
    UserIdentity,
)

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def read_clock(clock: object) -> int:
    try:
        if not callable(clock):
            raise ValueError
        return timestamp(clock())
    except Exception:
        raise StoreError("INVALID_REQUEST") from None


def identifier(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value):
        raise StoreError("INVALID_REQUEST")
    return value


def runtime_operation_id(value: object, *, legacy: bool = False) -> str | None:
    if legacy and value is None:
        return None
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise StoreError("INVALID_REQUEST")
    return value


def timestamp(value: datetime) -> int:
    try:
        if type(value) is not datetime or value.utcoffset() is None:
            raise ValueError
        delta = value.astimezone(UTC) - EPOCH
        return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    except Exception:
        raise StoreError("INVALID_REQUEST") from None


def instant(value: int) -> datetime:
    return EPOCH + timedelta(microseconds=value)


def positive(value: int, *, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise StoreError("INVALID_REQUEST")
    return value


def ref_valid(ref: ResourceRef) -> None:
    if type(ref) is not ResourceRef:
        raise StoreError("INVALID_REQUEST")
    identifier(ref.attempt_id)
    identifier(ref.sandbox_id)
    positive(ref.generation)


def service(identity: ServiceIdentity, role: Role, action: Action) -> str:
    if (
        type(identity) is not ServiceIdentity
        or type(identity.role) is not Role
        or identity.role != role
        or type(identity.scopes) is not frozenset
        or any(type(scope) is not Action for scope in identity.scopes)
        or action not in identity.scopes
    ):
        raise StoreError("NOT_AUTHORIZED")
    return "service:" + role.value + ":" + identifier(identity.service_id)


def user(identity: UserIdentity, room_id: str) -> str:
    if (
        type(identity) is not UserIdentity
        or type(identity.authorized_room_ids) is not frozenset
        or room_id not in identity.authorized_room_ids
    ):
        raise StoreError("NOT_AUTHORIZED")
    return "user:" + identifier(identity.user_id)


def owned(
    connection: sqlite3.Connection, identity: UserIdentity, attempt_id: str
) -> sqlite3.Row:
    identifier(attempt_id)
    row = connection.execute(
        "SELECT * FROM room_attempts WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if (
        row is None
        or type(identity) is not UserIdentity
        or row["user_id"] != identity.user_id
    ):
        raise StoreError("NOT_AUTHORIZED")
    user(identity, str(row["room_id"]))
    return row  # type: ignore[no-any-return]


def binding(
    connection: sqlite3.Connection, ref: ResourceRef, *, allow_active: bool = False
) -> sqlite3.Row:
    ref_valid(ref)
    row = connection.execute(
        "SELECT * FROM room_attempts WHERE attempt_id=?", (ref.attempt_id,)
    ).fetchone()
    current = (
        row is not None
        and row["sandbox_id"] == ref.sandbox_id
        and row["generation"] == ref.generation
    )
    active = (
        row is not None
        and row["active_sandbox_id"] == ref.sandbox_id
        and row["active_generation"] == ref.generation
    )
    if not current and (not allow_active or not active):
        raise StoreError("STALE_BINDING")
    return row  # type: ignore[no-any-return]


def row_ref(row: sqlite3.Row) -> ResourceRef:
    return ResourceRef(
        str(row["attempt_id"]), str(row["sandbox_id"]), int(row["generation"])
    )


def attempt_record(row: sqlite3.Row) -> Attempt:
    return Attempt(
        row_ref(row),
        str(row["room_id"]),
        str(row["state"]),
        str(row["active_sandbox_id"]) if row["active_sandbox_id"] else None,
        int(row["active_generation"]) if row["active_generation"] else None,
        str(row["candidate_sandbox_id"]) if row["candidate_sandbox_id"] else None,
        int(row["candidate_generation"]) if row["candidate_generation"] else None,
        int(row["session_epoch"]),
        int(row["version"]),
        instant(int(row["expires_at"])),
        bool(row["provisioning_intent"]),
        bool(row["reset_intent"]),
        bool(row["expiry_intent"]),
        bool(row["destroy_intent"]),
    )


def request_hash(action: str, values: list[object]) -> str:
    payload = json.dumps([action, values], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def replay(
    connection: sqlite3.Connection, actor: str, key: str, fingerprint: str
) -> Receipt | None:
    identifier(key)
    row = connection.execute(
        "SELECT * FROM lifecycle_operations WHERE actor=? AND idempotency_key=?",
        (actor, key),
    ).fetchone()
    if row is None:
        return None
    if row["request_hash"] != fingerprint:
        raise StoreError("IDEMPOTENCY_CONFLICT")
    return Receipt(
        str(row["operation_id"]),
        row_ref(row),
        str(row["result_state"]),
        int(row["result_version"]),
    )


def finish(
    connection: sqlite3.Connection,
    actor: str,
    action: str,
    key: str,
    fingerprint: str,
    ref: ResourceRef,
    state: str,
    version: int,
    error_code: str | None = None,
) -> Receipt:
    receipt = Receipt(str(uuid4()), ref, state, version)
    connection.execute(
        """INSERT INTO lifecycle_operations
        (operation_id,actor,action,idempotency_key,request_hash,attempt_id,
         sandbox_id,generation,status,result_state,result_version,error_code)
        VALUES (?,?,?,?,?,?,?,?,'SUCCEEDED',?,?,?)""",
        (
            receipt.operation_id,
            actor,
            action,
            key,
            fingerprint,
            ref.attempt_id,
            ref.sandbox_id,
            ref.generation,
            state,
            version,
            error_code,
        ),
    )
    return receipt


def digest(value: str | None) -> str:
    if type(value) is not str or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise StoreError("INVALID_REQUEST")
    return value


def cas(row: sqlite3.Row, version: int) -> None:
    if type(version) is not int or version < 0:
        raise StoreError("INVALID_REQUEST")
    if row["version"] != version:
        raise StoreError("STALE_VERSION")
