"""Control-plane-owned resource observations and durable cleanup work.

No method here allocates, inspects or deletes a container. Evidence references
must come from trusted runtime verifiers; accepting a hash does not verify it.
"""

import hashlib
import re
import sqlite3
from datetime import datetime, timedelta
from uuid import uuid4

from .common import (
    binding,
    cas,
    digest,
    finish,
    identifier,
    instant,
    positive,
    read_clock,
    ref_valid,
    replay,
    request_hash,
    row_ref,
    runtime_operation_id,
    service,
    timestamp,
)
from .database import CommitDenial, Database
from .models import (
    Action,
    AttachmentLease,
    CapabilityUse,
    CleanupTask,
    Clock,
    Receipt,
    Resource,
    ResourceRef,
    ResourceState,
    Role,
    ServiceIdentity,
    StoreError,
)

_NEXT = {
    ResourceState.REQUESTED: {ResourceState.CREATING, ResourceState.STOPPING},
    ResourceState.CREATING: {
        ResourceState.STARTING,
        ResourceState.FAILED,
        ResourceState.STOPPING,
    },
    ResourceState.STARTING: {
        ResourceState.READY,
        ResourceState.FAILED,
        ResourceState.STOPPING,
    },
    ResourceState.READY: {ResourceState.RUNNING, ResourceState.STOPPING},
    ResourceState.RUNNING: {ResourceState.RESOLVED, ResourceState.STOPPING},
    ResourceState.RESOLVED: {ResourceState.STOPPING},
    ResourceState.STOPPING: {ResourceState.DESTROYED, ResourceState.FAILED},
    ResourceState.FAILED: {ResourceState.STOPPING},
    ResourceState.DESTROYED: set(),
}


def _resource(connection: sqlite3.Connection, ref: ResourceRef) -> sqlite3.Row:
    row: sqlite3.Row | None = connection.execute(
        "SELECT * FROM sandbox_resources WHERE sandbox_id=?",
        (ref.sandbox_id,),
    ).fetchone()
    if row is None or row_ref(row) != ref:
        raise StoreError("STALE_BINDING")
    return row


def _runtime_binding(row: sqlite3.Row, *, allow_legacy: bool) -> str | None:
    raw = row["runtime_operation_id"]
    if raw is None and not allow_legacy:
        raise StoreError("LEGACY_RUNTIME_BINDING")
    return runtime_operation_id(raw, legacy=allow_legacy)


def _attachment_lease(row: sqlite3.Row) -> AttachmentLease:
    return AttachmentLease(
        str(row["lease_id"]),
        ResourceRef(
            str(row["attempt_id"]),
            str(row["sandbox_id"]),
            int(row["generation"]),
        ),
        str(row["jti_hash"]),
        str(row["gateway_session_hash"]),
        int(row["session_epoch"]),
        instant(int(row["issued_at"])),
        instant(int(row["expires_at"])),
        instant(int(row["consumed_at"])),
    )


def _stop(connection: sqlite3.Connection, row: sqlite3.Row, expired: bool) -> None:
    if row["state"] == "DESTROYED":
        return
    if (
        row["state"] != "STOPPING"
        or not row["destroy_intent"]
        or (expired and not row["expiry_intent"])
    ):
        connection.execute(
            """UPDATE sandbox_resources SET state='STOPPING',destroy_intent=1,
            expiry_intent=max(expiry_intent,?),version=version+1 WHERE sandbox_id=?""",
            (int(expired), row["sandbox_id"]),
        )


def _live(
    connection: sqlite3.Connection,
    attempt: sqlite3.Row,
    resource: sqlite3.Row | None,
    now: int,
) -> None:
    expired = now >= attempt["expires_at"] or bool(attempt["expiry_intent"])
    if (
        expired
        or attempt["destroy_intent"]
        or attempt["state"] in ("STOPPING", "FAILED", "DESTROYED")
        or (resource is not None and resource["destroy_intent"])
    ):
        if expired and resource is not None:
            _stop(connection, resource, expired)
            raise CommitDenial("ATTEMPT_UNAVAILABLE")
        raise StoreError("ATTEMPT_UNAVAILABLE")


class ControlPlaneStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    def accept(
        self, identity: ServiceIdentity, ref: ResourceRef, *, key: str, now: Clock
    ) -> Receipt:
        actor = service(identity, Role.BACKEND, Action.CREATE)
        ref_valid(ref)
        fingerprint = request_hash(
            "accept", [ref.attempt_id, ref.sandbox_id, ref.generation]
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            attempt = binding(connection, ref)
            _live(connection, attempt, None, clock)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            initial_provisioning = (
                attempt["state"] == "PROVISIONING" and attempt["provisioning_intent"]
            )
            reset_provisioning = (
                attempt["state"] == "RESETTING"
                and attempt["provisioning_intent"]
                and attempt["reset_intent"]
                and attempt["candidate_sandbox_id"] == ref.sandbox_id
                and attempt["candidate_generation"] == ref.generation
            )
            if not initial_provisioning and not reset_provisioning:
                raise StoreError("INVALID_TRANSITION")
            if reset_provisioning:
                old = connection.execute(
                    """SELECT state,cleanup_evidence_digest FROM sandbox_resources
                    WHERE sandbox_id=? AND attempt_id=? AND generation=?""",
                    (
                        attempt["active_sandbox_id"],
                        ref.attempt_id,
                        attempt["active_generation"],
                    ),
                ).fetchone()
                if (
                    old is None
                    or old["state"] != "DESTROYED"
                    or old["cleanup_evidence_digest"] is None
                ):
                    raise StoreError("INVALID_TRANSITION")
            if connection.execute(
                "SELECT 1 FROM sandbox_resources WHERE sandbox_id=?", (ref.sandbox_id,)
            ).fetchone():
                raise StoreError("RESOURCE_EXISTS")
            runtime_id = _runtime_binding(attempt, allow_legacy=False)
            connection.execute(
                """INSERT INTO sandbox_resources
                (sandbox_id,attempt_id,generation,state,expires_at,runtime_operation_id)
                VALUES (?,?,?,'REQUESTED',?,?)""",
                (
                    ref.sandbox_id,
                    ref.attempt_id,
                    ref.generation,
                    attempt["expires_at"],
                    runtime_id,
                ),
            )
            return finish(
                connection, actor, "accept", key, fingerprint, ref, "REQUESTED", 0
            )

    def inspect(self, identity: ServiceIdentity, ref: ResourceRef) -> Resource:
        # Runtime details are never returned to a UserIdentity.
        if type(identity) is not ServiceIdentity or identity.role not in (
            Role.BACKEND,
            Role.CONTROL_PLANE,
        ):
            raise StoreError("NOT_AUTHORIZED")
        service(identity, identity.role, Action.INSPECT)
        with self._database._transaction() as connection:
            binding(connection, ref, allow_active=True)
            row = _resource(connection, ref)
            return Resource(
                ref,
                str(row["state"]),
                int(row["version"]),
                row["container_id"],
                row["runtime_operation_id"],
                instant(int(row["expires_at"])),
                bool(row["expiry_intent"]),
                bool(row["destroy_intent"]),
                row["evidence_digest"],
                row["cleanup_evidence_digest"],
            )

    def transition(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        expected_version: int,
        state: ResourceState,
        key: str,
        now: Clock,
        container_id: str | None = None,
        evidence_digest: str | None = None,
        error_code: str | None = None,
    ) -> Receipt:
        actor = service(identity, Role.CONTROL_PLANE, Action.TRANSITION)
        ref_valid(ref)
        if type(state) is not ResourceState:
            raise StoreError("INVALID_REQUEST")
        if state == ResourceState.FAILED:
            if error_code not in (
                "CREATE_FAILED",
                "START_FAILED",
                "RUNTIME_UNAVAILABLE",
                "CLEANUP_INCOMPLETE",
            ):
                raise StoreError("INVALID_REQUEST")
        elif error_code is not None:
            raise StoreError("INVALID_REQUEST")
        if state in (ResourceState.READY, ResourceState.DESTROYED):
            digest(evidence_digest)
        elif evidence_digest is not None:
            raise StoreError("INVALID_REQUEST")
        if state == ResourceState.STARTING:
            identifier(container_id)
        elif container_id is not None:
            raise StoreError("INVALID_REQUEST")
        fingerprint = request_hash(
            "transition",
            [
                ref.attempt_id,
                ref.sandbox_id,
                ref.generation,
                expected_version,
                state.value,
                container_id,
                evidence_digest,
                error_code,
            ],
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            attempt = binding(connection, ref, allow_active=True)
            resource = _resource(connection, ref)
            cleanup = state in (ResourceState.STOPPING, ResourceState.DESTROYED) or (
                state == ResourceState.FAILED and resource["destroy_intent"]
            )
            active = (
                attempt["active_sandbox_id"] == ref.sandbox_id
                and attempt["active_generation"] == ref.generation
            )
            current = (
                attempt["sandbox_id"] == ref.sandbox_id
                and attempt["generation"] == ref.generation
            )
            if active and not current and not cleanup:
                raise StoreError("INVALID_TRANSITION")
            if not cleanup:
                _live(connection, attempt, resource, clock)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            cas(resource, expected_version)
            if state not in _NEXT[ResourceState(resource["state"])]:
                raise StoreError("INVALID_TRANSITION")
            destroy = state in (
                ResourceState.STOPPING,
                ResourceState.FAILED,
                ResourceState.DESTROYED,
            )
            expired = clock >= resource["expires_at"] or bool(attempt["expiry_intent"])
            connection.execute(
                """UPDATE sandbox_resources SET state=?,version=version+1,
                container_id=coalesce(?,container_id),
                destroy_intent=max(destroy_intent,?),expiry_intent=max(expiry_intent,?),
                evidence_digest=coalesce(?,evidence_digest),
                cleanup_evidence_digest=coalesce(?,cleanup_evidence_digest)
                WHERE sandbox_id=?""",
                (
                    state.value,
                    container_id,
                    int(destroy),
                    int(expired),
                    evidence_digest if state == ResourceState.READY else None,
                    evidence_digest if state == ResourceState.DESTROYED else None,
                    ref.sandbox_id,
                ),
            )
            if state == ResourceState.DESTROYED:
                connection.execute(
                    """UPDATE lifecycle_operations SET status='SUCCEEDED',
                    result_state='DESTROYED',result_version=?,error_code=NULL
                    WHERE actor='internal:cleanup' AND idempotency_key=?""",
                    (expected_version + 1, ref.sandbox_id),
                )
            return finish(
                connection,
                actor,
                "transition",
                key,
                fingerprint,
                ref,
                state.value,
                expected_version + 1,
                error_code,
            )

    def grant_attachment_lease(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        consumed: CapabilityUse,
        gateway_session_id: str,
        lease_duration: timedelta,
        key: str,
        now: Clock,
    ) -> AttachmentLease:
        actor = service(identity, Role.GATEWAY, Action.ATTACH)
        ref_valid(ref)
        if type(consumed) is not CapabilityUse or consumed.ref != ref:
            raise StoreError("CAPABILITY_INVALID")
        if (
            type(consumed.jti_hash) is not str
            or re.fullmatch(r"[0-9a-f]{64}", consumed.jti_hash) is None
            or type(consumed.session_epoch) is not int
            or consumed.session_epoch < 0
        ):
            raise StoreError("CAPABILITY_INVALID")
        identifier(gateway_session_id)
        identifier(key)
        if type(lease_duration) is not timedelta:
            raise StoreError("INVALID_REQUEST")
        duration_micros = (
            lease_duration.days * 86_400_000_000
            + lease_duration.seconds * 1_000_000
            + lease_duration.microseconds
        )
        if not 1 <= duration_micros <= 60_000_000:
            raise StoreError("INVALID_REQUEST")
        try:
            consumed_expires_at = timestamp(consumed.expires_at)
        except StoreError:
            raise StoreError("CAPABILITY_INVALID") from None
        session_hash = hashlib.sha256(gateway_session_id.encode("utf-8")).hexdigest()
        fingerprint = request_hash(
            "attachment-lease",
            [
                ref.attempt_id,
                ref.sandbox_id,
                ref.generation,
                consumed.jti_hash,
                consumed.session_epoch,
                session_hash,
                duration_micros,
            ],
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            attempt = binding(connection, ref)
            resource = _resource(connection, ref)
            _live(connection, attempt, resource, clock)
            if (
                resource["state"] not in ("READY", "RUNNING")
                or attempt["active_sandbox_id"] != ref.sandbox_id
                or resource["destroy_intent"]
                or resource["expiry_intent"]
                or attempt["session_epoch"] != consumed.session_epoch
            ):
                raise StoreError("ATTEMPT_UNAVAILABLE")
            capability = connection.execute(
                """SELECT * FROM terminal_capability_uses
                WHERE jti_hash=? AND attempt_id=?""",
                (consumed.jti_hash, ref.attempt_id),
            ).fetchone()
            if (
                capability is None
                or int(capability["expires_at"]) <= clock
                or int(capability["expires_at"]) != consumed_expires_at
            ):
                raise StoreError("CAPABILITY_INVALID")
            existing_key = connection.execute(
                """SELECT * FROM terminal_attachment_leases
                WHERE actor=? AND idempotency_key=?""",
                (actor, key),
            ).fetchone()
            if existing_key is not None:
                if existing_key["request_hash"] != fingerprint:
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                return _attachment_lease(existing_key)
            existing_jti = connection.execute(
                "SELECT * FROM terminal_attachment_leases WHERE jti_hash=?",
                (consumed.jti_hash,),
            ).fetchone()
            if existing_jti is not None:
                if existing_jti["request_hash"] == fingerprint:
                    return _attachment_lease(existing_jti)
                raise StoreError("CAPABILITY_REPLAY")
            existing_session = connection.execute(
                """SELECT 1 FROM terminal_attachment_leases
                WHERE gateway_session_hash=?""",
                (session_hash,),
            ).fetchone()
            if existing_session is not None:
                raise StoreError("CAPABILITY_REPLAY")
            expires_at = min(
                int(capability["expires_at"]),
                int(attempt["expires_at"]),
                clock + duration_micros,
            )
            if expires_at <= clock:
                raise StoreError("CAPABILITY_INVALID")
            lease_id = uuid4().hex
            connection.execute(
                """INSERT INTO terminal_attachment_leases
                (lease_id,jti_hash,actor,idempotency_key,request_hash,attempt_id,
                 sandbox_id,generation,session_epoch,gateway_session_hash,
                 issued_at,expires_at,consumed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    lease_id,
                    consumed.jti_hash,
                    actor,
                    key,
                    fingerprint,
                    ref.attempt_id,
                    ref.sandbox_id,
                    ref.generation,
                    consumed.session_epoch,
                    session_hash,
                    clock,
                    expires_at,
                    clock,
                ),
            )
            row = connection.execute(
                "SELECT * FROM terminal_attachment_leases WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            if row is None:
                raise StoreError("STORE_FAILURE")
            return _attachment_lease(row)

    def reconcile(
        self, identity: ServiceIdentity, *, now: Clock, limit: int
    ) -> tuple[CleanupTask, ...]:
        service(identity, Role.CONTROL_PLANE, Action.RECONCILE)
        positive(limit, maximum=1000)
        tasks: list[CleanupTask] = []
        with self._database._transaction() as connection:
            clock = read_clock(now)
            rows = connection.execute(
                """SELECT * FROM (
                    SELECT a.*,r.sandbox_id AS cleanup_sandbox_id,
                    r.generation AS cleanup_generation
                    FROM room_attempts a JOIN sandbox_resources r
                    ON r.attempt_id=a.attempt_id
                    LEFT JOIN lifecycle_operations o ON o.actor='internal:cleanup'
                    AND o.idempotency_key=r.sandbox_id
                    WHERE a.state!='DESTROYED' AND r.state!='DESTROYED'
                    AND (
                        a.destroy_intent=1 OR a.expires_at<=? OR r.destroy_intent=1
                        OR (
                            a.reset_intent=1
                            AND r.sandbox_id=a.active_sandbox_id
                            AND r.generation=a.active_generation
                        )
                    )
                    AND (o.operation_id IS NULL OR o.retry_at<=?)
                    UNION ALL
                    SELECT a.*,NULL AS cleanup_sandbox_id,
                    NULL AS cleanup_generation
                    FROM room_attempts a
                    LEFT JOIN sandbox_resources r ON r.sandbox_id=a.sandbox_id
                    LEFT JOIN lifecycle_operations o ON o.actor='internal:cleanup'
                    AND o.idempotency_key=a.sandbox_id
                    WHERE a.state!='DESTROYED' AND r.sandbox_id IS NULL
                    AND (a.destroy_intent=1 OR a.expires_at<=?)
                    AND (o.operation_id IS NULL OR o.retry_at<=?)
                ) cleanup_candidates
                ORDER BY expires_at,attempt_id,cleanup_sandbox_id LIMIT ?""",
                (clock, clock, clock, clock, limit),
            ).fetchall()
            for attempt in rows:
                if attempt["cleanup_sandbox_id"] is None:
                    ref = row_ref(attempt)
                else:
                    ref = ResourceRef(
                        str(attempt["attempt_id"]),
                        str(attempt["cleanup_sandbox_id"]),
                        int(attempt["cleanup_generation"]),
                    )
                expired = clock >= attempt["expires_at"] or bool(
                    attempt["expiry_intent"]
                )
                # Even an interrupted create with no resource row has a reserved
                # identity to inspect for absence. Do not silently mark it destroyed.
                if attempt["cleanup_sandbox_id"] is None:
                    connection.execute(
                        """INSERT INTO sandbox_resources
                        (sandbox_id,attempt_id,generation,state,expires_at,destroy_intent,
                         expiry_intent,runtime_operation_id) VALUES (?,?,?,'STOPPING',?,1,?,?)
                        ON CONFLICT(sandbox_id) DO NOTHING""",
                        (
                            ref.sandbox_id,
                            ref.attempt_id,
                            ref.generation,
                            attempt["expires_at"],
                            int(expired),
                            _runtime_binding(attempt, allow_legacy=True),
                        ),
                    )
                _stop(connection, _resource(connection, ref), expired)
                resource = _resource(connection, ref)
                connection.execute(
                    """INSERT INTO lifecycle_operations
                    (operation_id,actor,action,idempotency_key,request_hash,
                     attempt_id,sandbox_id,generation,status,result_state,result_version)
                    VALUES (?,'internal:cleanup','cleanup',?,?,?,?,?,'PENDING','STOPPING',?)
                    ON CONFLICT(actor,idempotency_key) DO NOTHING""",
                    (
                        str(uuid4()),
                        ref.sandbox_id,
                        request_hash(
                            "cleanup", [ref.attempt_id, ref.sandbox_id, ref.generation]
                        ),
                        ref.attempt_id,
                        ref.sandbox_id,
                        ref.generation,
                        resource["version"],
                    ),
                )
                operation = connection.execute(
                    """SELECT * FROM lifecycle_operations WHERE actor='internal:cleanup'
                    AND idempotency_key=?""",
                    (ref.sandbox_id,),
                ).fetchone()
                tasks.append(
                    CleanupTask(
                        str(operation["operation_id"]),
                        ref,
                        str(resource["state"]),
                        int(resource["version"]),
                        bool(resource["expiry_intent"]),
                        int(operation["retry_count"]),
                    )
                )
        return tuple(tasks)

    def cleanup_failed(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        operation_id: str,
        expected_version: int,
        key: str,
        error_code: str,
        retry_at: datetime,
        now: Clock,
    ) -> Receipt:
        actor = service(identity, Role.CONTROL_PLANE, Action.RECONCILE)
        identifier(operation_id)
        ref_valid(ref)
        retry = timestamp(retry_at)
        if error_code not in ("RUNTIME_UNAVAILABLE", "CLEANUP_INCOMPLETE"):
            raise StoreError("INVALID_REQUEST")
        fingerprint = request_hash(
            "cleanup-failed",
            [
                ref.attempt_id,
                ref.sandbox_id,
                ref.generation,
                operation_id,
                expected_version,
                error_code,
                retry,
            ],
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            binding(connection, ref, allow_active=True)
            resource = _resource(connection, ref)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            if retry <= clock:
                raise StoreError("INVALID_REQUEST")
            cas(resource, expected_version)
            operation = connection.execute(
                """SELECT * FROM lifecycle_operations WHERE operation_id=?
                AND actor='internal:cleanup' AND idempotency_key=?""",
                (operation_id, ref.sandbox_id),
            ).fetchone()
            if (
                resource["state"] != "STOPPING"
                or operation is None
                or operation["status"] == "SUCCEEDED"
            ):
                raise StoreError("INVALID_TRANSITION")
            connection.execute(
                """UPDATE sandbox_resources SET state='FAILED',version=version+1
                WHERE sandbox_id=?""",
                (ref.sandbox_id,),
            )
            connection.execute(
                """UPDATE lifecycle_operations SET status='RETRY',retry_count=retry_count+1,
                retry_at=?,error_code=?,result_state='FAILED',result_version=?
                WHERE operation_id=?""",
                (retry, error_code, expected_version + 1, operation_id),
            )
            return finish(
                connection,
                actor,
                "cleanup-failed",
                key,
                fingerprint,
                ref,
                "FAILED",
                expected_version + 1,
                error_code,
            )
