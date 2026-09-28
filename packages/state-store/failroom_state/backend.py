"""Backend-owned attempt authority and atomic one-time capability consumption."""

import hashlib
import sqlite3
from datetime import datetime
from uuid import uuid4

from .common import (
    attempt_record,
    binding,
    cas,
    finish,
    identifier,
    instant,
    owned,
    positive,
    read_clock,
    ref_valid,
    replay,
    request_hash,
    row_ref,
    service,
    timestamp,
    user,
)
from .database import CommitDenial, Database
from .models import (
    Action,
    Attempt,
    CapabilityClaims,
    CapabilityUse,
    Clock,
    Receipt,
    ResourceRef,
    Role,
    ServiceIdentity,
    StoreError,
    UserIdentity,
)


def _stop(connection: sqlite3.Connection, row: sqlite3.Row, now: int) -> None:
    if row["state"] == "DESTROYED":
        return
    expired = now >= row["expires_at"]
    if not row["destroy_intent"] or (expired and not row["expiry_intent"]):
        connection.execute(
            """UPDATE room_attempts SET state='STOPPING', destroy_intent=1,
            expiry_intent=max(expiry_intent,?), provisioning_intent=0,
            session_epoch=session_epoch+?, version=version+1 WHERE attempt_id=?""",
            (int(expired), int(not row["destroy_intent"]), row["attempt_id"]),
        )


def _live(connection: sqlite3.Connection, row: sqlite3.Row, now: int) -> None:
    if now >= row["expires_at"]:
        _stop(connection, row, now)
        raise CommitDenial("ATTEMPT_UNAVAILABLE")
    if row["destroy_intent"] or row["state"] in ("STOPPING", "FAILED", "DESTROYED"):
        raise StoreError("ATTEMPT_UNAVAILABLE")


class BackendStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        identity: UserIdentity,
        room_id: str,
        *,
        key: str,
        expires_at: datetime,
        now: Clock,
    ) -> Receipt:
        actor = user(identity, room_id)
        identifier(room_id)
        deadline = timestamp(expires_at)
        fingerprint = request_hash("create", [room_id, deadline])
        with self._database._transaction() as connection:
            clock = read_clock(now)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            if deadline <= clock:
                raise StoreError("INVALID_REQUEST")
            ref = ResourceRef(str(uuid4()), str(uuid4()), 1)
            runtime_id = uuid4().hex
            connection.execute(
                """INSERT INTO room_attempts
                (attempt_id,user_id,room_id,sandbox_id,generation,candidate_sandbox_id,
                 candidate_generation,state,created_at,expires_at,runtime_operation_id)
                VALUES (?,?,?,?,1,?,1,'PROVISIONING',?,?,?)""",
                (
                    ref.attempt_id,
                    identity.user_id,
                    room_id,
                    ref.sandbox_id,
                    ref.sandbox_id,
                    clock,
                    deadline,
                    runtime_id,
                ),
            )
            return finish(
                connection, actor, "create", key, fingerprint, ref, "PROVISIONING", 0
            )

    def inspect(self, identity: UserIdentity, attempt_id: str) -> Attempt:
        with self._database._transaction() as connection:
            return attempt_record(owned(connection, identity, attempt_id))

    def room_id_for_binding(
        self, identity: ServiceIdentity, ref: ResourceRef
    ) -> str:
        """Read the trusted Room selector for the exact current resource binding."""
        service(identity, Role.BACKEND, Action.CREATE)
        ref_valid(ref)
        with self._database._transaction() as connection:
            return str(binding(connection, ref)["room_id"])

    def leave(
        self, identity: UserIdentity, ref: ResourceRef, *, key: str, now: Clock
    ) -> Receipt:
        ref_valid(ref)
        fingerprint = request_hash(
            "leave", [ref.attempt_id, ref.sandbox_id, ref.generation]
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            row = owned(connection, identity, ref.attempt_id)
            binding(connection, ref)
            actor = user(identity, str(row["room_id"]))
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            _stop(connection, row, clock)
            row = binding(connection, ref)
            return finish(
                connection,
                actor,
                "leave",
                key,
                fingerprint,
                ref,
                str(row["state"]),
                int(row["version"]),
            )

    def begin_reset(
        self, identity: UserIdentity, ref: ResourceRef, *, key: str, now: Clock
    ) -> Receipt:
        ref_valid(ref)
        with self._database._transaction() as connection:
            clock = read_clock(now)
            row = owned(connection, identity, ref.attempt_id)
            actor = user(identity, str(row["room_id"]))
            fingerprint = request_hash(
                "begin-reset", [ref.attempt_id, ref.sandbox_id, ref.generation]
            )
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            binding(connection, ref)
            if clock >= row["expires_at"]:
                _stop(connection, row, clock)
                raise CommitDenial("ATTEMPT_UNAVAILABLE")
            if (
                row["state"] not in ("READY", "RUNNING", "RESOLVED")
                or row["destroy_intent"]
                or row["active_sandbox_id"] != ref.sandbox_id
                or row["active_generation"] != ref.generation
            ):
                raise StoreError("INVALID_TRANSITION")
            candidate = ResourceRef(ref.attempt_id, str(uuid4()), ref.generation + 1)
            runtime_id = uuid4().hex
            version = int(row["version"]) + 1
            connection.execute(
                """UPDATE room_attempts SET sandbox_id=?,generation=?,
                candidate_sandbox_id=?,candidate_generation=?,state='RESETTING',
                provisioning_intent=1,reset_intent=1,session_epoch=session_epoch+1,
                version=?,runtime_operation_id=? WHERE attempt_id=?""",
                (
                    candidate.sandbox_id,
                    candidate.generation,
                    candidate.sandbox_id,
                    candidate.generation,
                    version,
                    runtime_id,
                    ref.attempt_id,
                ),
            )
            return finish(
                connection,
                actor,
                "begin-reset",
                key,
                fingerprint,
                candidate,
                "RESETTING",
                version,
            )

    def publish_ready(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        expected_version: int,
        key: str,
        now: Clock,
    ) -> Receipt:
        actor = service(identity, Role.BACKEND, Action.PUBLISH)
        ref_valid(ref)
        fingerprint = request_hash(
            "publish-ready",
            [ref.attempt_id, ref.sandbox_id, ref.generation, expected_version],
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            row = binding(connection, ref)
            _live(connection, row, clock)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            cas(row, expected_version)
            resource = connection.execute(
                "SELECT * FROM sandbox_resources WHERE sandbox_id=?",
                (ref.sandbox_id,),
            ).fetchone()
            if (
                row["state"] != "PROVISIONING"
                or resource is None
                or resource["state"] != "READY"
                or resource["destroy_intent"]
            ):
                raise StoreError("INVALID_TRANSITION")
            connection.execute(
                """UPDATE room_attempts SET state='READY',active_sandbox_id=sandbox_id,
                active_generation=generation,candidate_sandbox_id=NULL,
                candidate_generation=NULL,provisioning_intent=0,version=version+1
                WHERE attempt_id=?""",
                (ref.attempt_id,),
            )
            return finish(
                connection,
                actor,
                "publish-ready",
                key,
                fingerprint,
                ref,
                "READY",
                expected_version + 1,
            )

    def publish_running(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        expected_version: int,
        key: str,
        now: Clock,
    ) -> Receipt:
        return self._publish_runtime_state(
            identity,
            ref,
            expected_version=expected_version,
            key=key,
            now=now,
            source="READY",
            target="RUNNING",
        )

    def publish_resolved(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        expected_version: int,
        key: str,
        now: Clock,
    ) -> Receipt:
        return self._publish_runtime_state(
            identity,
            ref,
            expected_version=expected_version,
            key=key,
            now=now,
            source="RUNNING",
            target="RESOLVED",
        )

    def _publish_runtime_state(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        expected_version: int,
        key: str,
        now: Clock,
        source: str,
        target: str,
    ) -> Receipt:
        actor = service(identity, Role.BACKEND, Action.PUBLISH)
        ref_valid(ref)
        fingerprint = request_hash(
            "publish-" + target.lower(),
            [ref.attempt_id, ref.sandbox_id, ref.generation, expected_version],
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            row = binding(connection, ref)
            _live(connection, row, clock)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            cas(row, expected_version)
            resource = connection.execute(
                "SELECT * FROM sandbox_resources WHERE sandbox_id=?",
                (ref.sandbox_id,),
            ).fetchone()
            if (
                row["state"] != source
                or resource is None
                or resource["state"] != target
                or resource["destroy_intent"]
                or (target == "RESOLVED" and resource["evidence_digest"] is None)
            ):
                raise StoreError("INVALID_TRANSITION")
            connection.execute(
                "UPDATE room_attempts SET state=?,version=version+1 WHERE attempt_id=?",
                (target, ref.attempt_id),
            )
            return finish(
                connection,
                actor,
                "publish-" + target.lower(),
                key,
                fingerprint,
                ref,
                target,
                expected_version + 1,
            )

    def publish_reset_ready(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        expected_version: int,
        key: str,
        now: Clock,
    ) -> Receipt:
        actor = service(identity, Role.BACKEND, Action.PUBLISH)
        ref_valid(ref)
        fingerprint = request_hash(
            "publish-reset-ready",
            [ref.attempt_id, ref.sandbox_id, ref.generation, expected_version],
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            row = binding(connection, ref)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            if clock >= row["expires_at"]:
                _stop(connection, row, clock)
                raise CommitDenial("ATTEMPT_UNAVAILABLE")
            if row["destroy_intent"]:
                raise StoreError("ATTEMPT_UNAVAILABLE")
            cas(row, expected_version)
            candidate = connection.execute(
                "SELECT * FROM sandbox_resources WHERE sandbox_id=?",
                (ref.sandbox_id,),
            ).fetchone()
            active = connection.execute(
                "SELECT * FROM sandbox_resources WHERE sandbox_id=?",
                (row["active_sandbox_id"],),
            ).fetchone()
            if (
                row["state"] != "RESETTING"
                or not row["reset_intent"]
                or not row["provisioning_intent"]
                or row["candidate_sandbox_id"] != ref.sandbox_id
                or row["candidate_generation"] != ref.generation
                or candidate is None
                or candidate["state"] != "READY"
                or candidate["destroy_intent"]
                or active is None
                or active["state"] != "DESTROYED"
                or active["cleanup_evidence_digest"] is None
            ):
                raise StoreError("INVALID_TRANSITION")
            connection.execute(
                """UPDATE room_attempts SET state='READY',active_sandbox_id=?,
                active_generation=?,candidate_sandbox_id=NULL,candidate_generation=NULL,
                provisioning_intent=0,reset_intent=0,version=version+1
                WHERE attempt_id=?""",
                (ref.sandbox_id, ref.generation, ref.attempt_id),
            )
            return finish(
                connection,
                actor,
                "publish-reset-ready",
                key,
                fingerprint,
                ref,
                "READY",
                expected_version + 1,
            )

    def fail_reset(
        self,
        identity: ServiceIdentity,
        ref: ResourceRef,
        *,
        expected_version: int,
        key: str,
        now: Clock,
    ) -> Receipt:
        actor = service(identity, Role.BACKEND, Action.PUBLISH)
        ref_valid(ref)
        fingerprint = request_hash(
            "fail-reset",
            [ref.attempt_id, ref.sandbox_id, ref.generation, expected_version],
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            row = binding(connection, ref)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            if clock >= row["expires_at"]:
                _stop(connection, row, clock)
                raise CommitDenial("ATTEMPT_UNAVAILABLE")
            if row["destroy_intent"]:
                raise StoreError("ATTEMPT_UNAVAILABLE")
            cas(row, expected_version)
            candidate = connection.execute(
                "SELECT * FROM sandbox_resources WHERE sandbox_id=?",
                (ref.sandbox_id,),
            ).fetchone()
            if (
                row["state"] != "RESETTING"
                or not row["reset_intent"]
                or not row["provisioning_intent"]
                or row["candidate_sandbox_id"] != ref.sandbox_id
                or row["candidate_generation"] != ref.generation
                or candidate is None
                or candidate["state"] != "FAILED"
                or not candidate["destroy_intent"]
            ):
                raise StoreError("INVALID_TRANSITION")
            connection.execute(
                """UPDATE room_attempts SET state='FAILED',provisioning_intent=0,
                version=version+1 WHERE attempt_id=?""",
                (ref.attempt_id,),
            )
            return finish(
                connection,
                actor,
                "fail-reset",
                key,
                fingerprint,
                ref,
                "FAILED",
                expected_version + 1,
            )

    def expire(
        self, identity: ServiceIdentity, *, now: Clock, limit: int
    ) -> tuple[ResourceRef, ...]:
        service(identity, Role.BACKEND, Action.EXPIRE)
        positive(limit, maximum=1000)
        with self._database._transaction() as connection:
            clock = read_clock(now)
            rows = connection.execute(
                """SELECT * FROM room_attempts WHERE expires_at<=? AND expiry_intent=0
                AND state!='DESTROYED' ORDER BY expires_at,attempt_id LIMIT ?""",
                (clock, limit),
            ).fetchall()
            for row in rows:
                _stop(connection, row, clock)
            return tuple(row_ref(row) for row in rows)

    def pending_finalizations(
        self, identity: ServiceIdentity, *, limit: int
    ) -> tuple[ResourceRef, ...]:
        service(identity, Role.BACKEND, Action.RECONCILE)
        positive(limit, maximum=1000)
        with self._database._transaction() as connection:
            rows = connection.execute(
                """SELECT a.* FROM room_attempts a JOIN sandbox_resources r
                ON r.sandbox_id=a.sandbox_id AND r.attempt_id=a.attempt_id
                AND r.generation=a.generation
                WHERE a.state!='DESTROYED' AND r.state='DESTROYED'
                AND r.cleanup_evidence_digest IS NOT NULL
                ORDER BY a.expires_at,a.attempt_id LIMIT ?""",
                (limit,),
            ).fetchall()
            return tuple(row_ref(row) for row in rows)

    def pending_reset_provisioning(
        self, identity: ServiceIdentity, *, limit: int
    ) -> tuple[Receipt, ...]:
        service(identity, Role.BACKEND, Action.RECONCILE)
        positive(limit, maximum=1000)
        with self._database._transaction() as connection:
            rows = connection.execute(
                """SELECT a.*,o.operation_id,o.result_version
                FROM room_attempts a
                JOIN sandbox_resources old ON old.attempt_id=a.attempt_id
                AND old.sandbox_id=a.active_sandbox_id
                AND old.generation=a.active_generation
                LEFT JOIN sandbox_resources candidate
                ON candidate.attempt_id=a.attempt_id
                AND candidate.sandbox_id=a.sandbox_id
                AND candidate.generation=a.generation
                JOIN lifecycle_operations o ON o.attempt_id=a.attempt_id
                AND o.sandbox_id=a.sandbox_id AND o.generation=a.generation
                AND o.action='begin-reset' AND o.result_state='RESETTING'
                WHERE a.state='RESETTING' AND a.provisioning_intent=1
                AND a.reset_intent=1 AND a.expiry_intent=0 AND a.destroy_intent=0
                AND old.state='DESTROYED'
                AND old.cleanup_evidence_digest IS NOT NULL
                AND (candidate.sandbox_id IS NULL OR candidate.state IN ('REQUESTED','READY'))
                ORDER BY a.expires_at,a.attempt_id LIMIT ?""",
                (limit,),
            ).fetchall()
            return tuple(
                Receipt(
                    str(row["operation_id"]),
                    row_ref(row),
                    "RESETTING",
                    int(row["result_version"]),
                )
                for row in rows
            )

    def complete_cleanup(
        self, identity: ServiceIdentity, ref: ResourceRef, *, key: str, now: Clock
    ) -> Receipt:
        actor = service(identity, Role.BACKEND, Action.PUBLISH)
        ref_valid(ref)
        fingerprint = request_hash(
            "complete-cleanup", [ref.attempt_id, ref.sandbox_id, ref.generation]
        )
        with self._database._transaction() as connection:
            clock = read_clock(now)
            row = binding(connection, ref, allow_active=True)
            previous = replay(connection, actor, key, fingerprint)
            if previous is not None:
                return previous
            resource = connection.execute(
                "SELECT * FROM sandbox_resources WHERE sandbox_id=?",
                (ref.sandbox_id,),
            ).fetchone()
            if (
                resource is None
                or resource["state"] != "DESTROYED"
                or resource["cleanup_evidence_digest"] is None
            ):
                raise StoreError("CLEANUP_UNVERIFIED")
            current = (
                row["sandbox_id"] == ref.sandbox_id
                and row["generation"] == ref.generation
            )
            if not current:
                if row["state"] != "RESETTING" or not row["reset_intent"]:
                    raise StoreError("INVALID_TRANSITION")
                return finish(
                    connection,
                    actor,
                    "complete-cleanup",
                    key,
                    fingerprint,
                    ref,
                    "DESTROYED",
                    int(resource["version"]),
                )
            _stop(connection, row, clock)
            row = binding(connection, ref)
            version = int(row["version"]) + int(row["state"] != "DESTROYED")
            connection.execute(
                """UPDATE room_attempts SET state='DESTROYED',active_sandbox_id=NULL,
                active_generation=NULL,version=? WHERE attempt_id=?""",
                (version, ref.attempt_id),
            )
            return finish(
                connection,
                actor,
                "complete-cleanup",
                key,
                fingerprint,
                ref,
                "DESTROYED",
                version,
            )

    def consume(
        self, identity: ServiceIdentity, claims: CapabilityClaims, *, now: Clock
    ) -> CapabilityUse:
        service(identity, Role.GATEWAY, Action.CONSUME)
        if type(claims) is not CapabilityClaims:
            raise StoreError("INVALID_REQUEST")
        ref_valid(claims.ref)
        identifier(claims.user_id)
        identifier(claims.jti)
        if type(claims.session_epoch) is not int or claims.session_epoch < 0:
            raise StoreError("INVALID_REQUEST")
        if claims.scope != "terminal:attach":
            raise StoreError("CAPABILITY_INVALID")
        deadline = timestamp(claims.expires_at)
        hashed_jti = hashlib.sha256(claims.jti.encode("ascii")).hexdigest()
        with self._database._transaction() as connection:
            clock = read_clock(now)
            row = binding(connection, claims.ref)
            if row["user_id"] != claims.user_id:
                raise StoreError("NOT_AUTHORIZED")
            _live(connection, row, clock)
            if (
                row["state"] not in ("READY", "RUNNING")
                or row["active_sandbox_id"] != claims.ref.sandbox_id
                or row["session_epoch"] != claims.session_epoch
                or deadline <= clock
                or deadline > row["expires_at"]
            ):
                raise StoreError("CAPABILITY_INVALID")
            resource = connection.execute(
                "SELECT * FROM sandbox_resources WHERE sandbox_id=?",
                (claims.ref.sandbox_id,),
            ).fetchone()
            if (
                resource is None
                or resource["state"] not in ("READY", "RUNNING")
                or resource["destroy_intent"]
                or resource["expiry_intent"]
            ):
                raise StoreError("ATTEMPT_UNAVAILABLE")
            if connection.execute(
                "SELECT 1 FROM terminal_capability_uses WHERE jti_hash=?",
                (hashed_jti,),
            ).fetchone():
                raise StoreError("CAPABILITY_REPLAY")
            connection.execute(
                """INSERT INTO terminal_capability_uses
                (jti_hash,attempt_id,consumed_at,expires_at) VALUES (?,?,?,?)""",
                (hashed_jti, claims.ref.attempt_id, clock, deadline),
            )
            return CapabilityUse(
                hashed_jti,
                claims.ref,
                claims.session_epoch,
                instant(deadline),
            )
