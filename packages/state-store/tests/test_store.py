import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from uuid import uuid4

from failroom_state import (
    Action,
    BackendStore,
    CapabilityClaims,
    ControlPlaneStore,
    Database,
    ResourceState,
    Role,
    ServiceIdentity,
    StoreError,
    UserIdentity,
)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.db = Database(self.path, busy_timeout_ms=5000)
        self.db.initialize()
        self.backend = BackendStore(self.db)
        self.control = ControlPlaneStore(self.db)
        self.now = datetime(2026, 9, 7, tzinfo=UTC)
        self.deadline = self.now + timedelta(minutes=30)
        self.alice = UserIdentity("alice", frozenset({"disk-full"}))
        self.bob = UserIdentity("bob", frozenset({"disk-full"}))
        self.evidence = "sha256:" + "a" * 64

    def service(self, role, action):
        return ServiceIdentity("test-" + role.value, role, frozenset({action}))

    def create(self, key="create-1"):
        return self.backend.create(
            self.alice,
            "disk-full",
            key=key,
            expires_at=self.deadline,
            now=lambda: self.now,
        )

    def accept(self, receipt):
        return self.control.accept(
            self.service(Role.BACKEND, Action.CREATE),
            receipt.ref,
            key="accept-" + receipt.attempt_id,
            now=lambda: self.now,
        )

    def advance(self, receipt, state, key=None, now=None, **kwargs):
        if state == ResourceState.FAILED:
            kwargs.setdefault("error_code", "RUNTIME_UNAVAILABLE")
        return self.control.transition(
            self.service(Role.CONTROL_PLANE, Action.TRANSITION),
            receipt.ref,
            expected_version=receipt.version,
            state=state,
            key=key or state.value + receipt.attempt_id,
            now=now or (lambda: self.now),
            **kwargs,
        )

    def ready(self):
        attempt = self.create()
        resource = self.accept(attempt)
        resource = self.advance(resource, ResourceState.CREATING)
        resource = self.advance(resource, ResourceState.STARTING, container_id="c-1")
        resource = self.advance(
            resource,
            ResourceState.READY,
            evidence_digest=self.evidence,
        )
        self.backend.publish_ready(
            self.service(Role.BACKEND, Action.PUBLISH),
            resource.ref,
            expected_version=0,
            key="publish",
            now=lambda: self.now,
        )
        return self.backend.inspect(self.alice, attempt.attempt_id), resource

    def claims(self, attempt):
        return CapabilityClaims(
            "unique-jti",
            "alice",
            attempt.ref,
            attempt.session_epoch,
            self.now + timedelta(seconds=30),
            "terminal:attach",
        )

    def consume(self, claims, now=None):
        return self.backend.consume(
            self.service(Role.GATEWAY, Action.CONSUME),
            claims,
            now=now or (lambda: self.now),
        )

    def assert_error(self, code, fn):
        with self.assertRaises(StoreError) as caught:
            fn()
        self.assertEqual(code, caught.exception.code)
        self.assertEqual(code, str(caught.exception))

    def test_schema_has_four_tables_and_is_reopenable(self):
        Database(self.path, busy_timeout_ms=5000).initialize()
        with closing(sqlite3.connect(self.path)) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertEqual(
                tables,
                {
                    "room_attempts",
                    "sandbox_resources",
                    "terminal_capability_uses",
                    "lifecycle_operations",
                },
            )
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_preallocation_and_owner_filtered_inspect(self):
        receipt = self.create()
        attempt = self.backend.inspect(self.alice, receipt.attempt_id)
        self.assertEqual(attempt.ref, receipt.ref)
        self.assertEqual(attempt.generation, 1)
        self.assertEqual(attempt.state, "PROVISIONING")
        self.assertTrue(attempt.provisioning_intent)
        self.assertIsNone(attempt.active_sandbox_id)
        self.assertEqual(attempt.expires_at, self.deadline)
        self.assert_error(
            "NOT_AUTHORIZED",
            lambda: self.backend.inspect(
                self.bob,
                receipt.attempt_id,
            ),
        )

    def test_accepted_resource_exposes_preallocated_runtime_operation_id(self):
        receipt = self.create()
        self.accept(receipt)

        resource = self.control.inspect(
            self.service(Role.CONTROL_PLANE, Action.INSPECT), receipt.ref
        )

        self.assertRegex(
            getattr(resource, "runtime_operation_id", ""), r"^[0-9a-f]{32}$"
        )

    def test_runtime_operation_id_cannot_change_at_sql_boundary(self):
        receipt = self.create()
        self.accept(receipt)

        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE sandbox_resources SET runtime_operation_id=? "
                    "WHERE sandbox_id=?",
                    ("f" * 32, receipt.ref.sandbox_id),
                )

    def test_create_requires_room_authority_and_future_aware_deadline(self):
        for user, room in [(None, "disk-full"), (self.alice, "other")]:
            self.assert_error(
                "NOT_AUTHORIZED",
                lambda user=user, room=room: self.backend.create(
                    user,
                    room,
                    key="bad",
                    expires_at=self.deadline,
                    now=lambda: self.now,
                ),
            )
        for deadline in [self.now, self.now.replace(tzinfo=None)]:
            self.assert_error(
                "INVALID_REQUEST",
                lambda deadline=deadline: self.backend.create(
                    self.alice,
                    "disk-full",
                    key="bad",
                    expires_at=deadline,
                    now=lambda: self.now,
                ),
            )

    def test_idempotency_survives_restart_and_rejects_changed_request(self):
        receipt = self.create()
        restarted = BackendStore(Database(self.path, busy_timeout_ms=5000))
        self.assertEqual(
            receipt,
            restarted.create(
                self.alice,
                "disk-full",
                key="create-1",
                expires_at=self.deadline,
                now=lambda: self.now + timedelta(seconds=1),
            ),
        )
        self.assert_error(
            "IDEMPOTENCY_CONFLICT",
            lambda: self.backend.create(
                self.alice,
                "disk-full",
                key="create-1",
                expires_at=self.deadline + timedelta(seconds=1),
                now=lambda: self.now,
            ),
        )

    def test_concurrent_create_allocates_one_tuple(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(pool.map(lambda _: self.create(), range(16)))
        self.assertEqual(len(set(receipts)), 1)
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM room_attempts").fetchone()[0], 1
            )

    def test_control_plane_requires_role_scope_and_preallocated_tuple(self):
        receipt = self.create()
        for identity in [
            None,
            self.alice,
            self.service(Role.GATEWAY, Action.CREATE),
            self.service(Role.BACKEND, Action.INSPECT),
        ]:
            self.assert_error(
                "NOT_AUTHORIZED",
                lambda identity=identity: self.control.accept(
                    identity,
                    receipt.ref,
                    key="bad",
                    now=lambda: self.now,
                ),
            )
        for ref in [
            replace(receipt.ref, generation=2),
            replace(receipt.ref, sandbox_id="unallocated"),
        ]:
            self.assert_error(
                "STALE_BINDING",
                lambda ref=ref: self.control.accept(
                    self.service(Role.BACKEND, Action.CREATE),
                    ref,
                    key="bad",
                    now=lambda: self.now,
                ),
            )

    def test_valid_transitions_and_stale_version(self):
        resource = self.accept(self.create())
        self.assert_error(
            "INVALID_TRANSITION",
            lambda: self.advance(
                resource,
                ResourceState.READY,
                evidence_digest=self.evidence,
            ),
        )
        creating = self.advance(resource, ResourceState.CREATING)
        self.assert_error(
            "STALE_VERSION",
            lambda: self.advance(
                resource,
                ResourceState.CREATING,
                key="other",
            ),
        )
        self.assertEqual(creating, self.advance(resource, ResourceState.CREATING))
        self.assert_error(
            "IDEMPOTENCY_CONFLICT",
            lambda: self.advance(
                creating,
                ResourceState.STARTING,
                key=ResourceState.CREATING.value + resource.attempt_id,
                container_id="c-1",
            ),
        )

    def test_ready_requires_observation_and_backend_publication(self):
        resource = self.accept(self.create())
        resource = self.advance(resource, ResourceState.CREATING)
        resource = self.advance(resource, ResourceState.STARTING, container_id="c-1")
        self.assert_error(
            "INVALID_REQUEST",
            lambda: self.advance(
                resource,
                ResourceState.READY,
            ),
        )
        resource = self.advance(
            resource, ResourceState.READY, evidence_digest=self.evidence
        )
        attempt = self.backend.inspect(self.alice, resource.attempt_id)
        self.assertEqual(attempt.state, "PROVISIONING")
        self.assertIsNone(attempt.active_sandbox_id)

    def test_capability_consumption_is_atomic_and_only_hash_is_stored(self):
        attempt, _ = self.ready()
        claims = self.claims(attempt)

        def consume(_):
            try:
                self.consume(claims)
                return "ok"
            except StoreError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(consume, range(16)))
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(results.count("CAPABILITY_REPLAY"), 15)
        with closing(sqlite3.connect(self.path)) as conn:
            row = conn.execute("SELECT * FROM terminal_capability_uses").fetchone()
            self.assertNotIn("unique-jti", str(row))
        self.backend = BackendStore(Database(self.path, busy_timeout_ms=5000))
        self.assert_error("CAPABILITY_REPLAY", lambda: self.consume(claims))

    def test_invalid_claims_do_not_consume_jti(self):
        attempt, _ = self.ready()
        claims = self.claims(attempt)
        bad_claims = [
            replace(claims, user_id="bob"),
            replace(claims, ref=replace(claims.ref, generation=2)),
            replace(claims, ref=replace(claims.ref, sandbox_id="other")),
            replace(claims, session_epoch=42),
            replace(claims, scope="sandbox:create"),
            replace(claims, expires_at=self.now),
            replace(claims, expires_at=self.deadline + timedelta(seconds=1)),
        ]
        for claim in bad_claims:
            with self.subTest(claim=claim):
                with self.assertRaises(StoreError):
                    self.consume(claim)
        self.consume(claims)

    def test_leave_is_owned_durable_and_revokes_terminal(self):
        attempt, _ = self.ready()
        self.assert_error(
            "NOT_AUTHORIZED",
            lambda: self.backend.leave(
                self.bob,
                attempt.ref,
                key="leave",
                now=lambda: self.now,
            ),
        )
        receipt = self.backend.leave(
            self.alice, attempt.ref, key="leave", now=lambda: self.now
        )
        self.assertEqual(
            receipt,
            self.backend.leave(
                self.alice,
                attempt.ref,
                key="leave",
                now=lambda: self.now,
            ),
        )
        self.assert_error(
            "ATTEMPT_UNAVAILABLE", lambda: self.consume(self.claims(attempt))
        )
        state = self.backend.inspect(self.alice, attempt.attempt_id)
        self.assertEqual(state.session_epoch, attempt.session_epoch + 1)
        self.assertTrue(state.destroy_intent)
        self.assertEqual(state.expires_at, self.deadline)

    def test_ttl_is_immutable_at_sql_boundary(self):
        attempt = self.create()
        self.accept(attempt)
        for table in ["room_attempts", "sandbox_resources"]:
            with closing(sqlite3.connect(self.path)) as conn:
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(f"UPDATE {table} SET expires_at=expires_at+1")

    def test_expired_create_and_late_ready_never_publish(self):
        attempt = self.create()
        self.assert_error(
            "ATTEMPT_UNAVAILABLE",
            lambda: self.control.accept(
                self.service(Role.BACKEND, Action.CREATE),
                attempt.ref,
                key="late-create",
                now=lambda: self.deadline,
            ),
        )
        self.backend.expire(
            self.service(Role.BACKEND, Action.EXPIRE),
            now=lambda: self.deadline,
            limit=100,
        )
        state = self.backend.inspect(self.alice, attempt.attempt_id)
        self.assertTrue(state.expiry_intent)
        self.assertTrue(state.destroy_intent)
        self.assertEqual(state.state, "STOPPING")

    def test_expiry_wins_ready_and_consume_race(self):
        attempt, resource = self.ready()

        def expire():
            self.backend.expire(
                self.service(Role.BACKEND, Action.EXPIRE),
                now=lambda: self.deadline,
                limit=100,
            )

        def consume():
            try:
                self.consume(self.claims(attempt), now=lambda: self.deadline)
                return "unexpected-success"
            except StoreError:
                return "denied"

        with ThreadPoolExecutor(max_workers=2) as pool:
            expiry = pool.submit(expire)
            consumption = pool.submit(consume)
            expiry.result()
            self.assertEqual(consumption.result(), "denied")
        self.assert_error(
            "ATTEMPT_UNAVAILABLE",
            lambda: self.advance(
                resource,
                ResourceState.RUNNING,
                now=lambda: self.deadline,
            ),
        )
        self.assertTrue(
            self.backend.inspect(self.alice, attempt.attempt_id).expiry_intent
        )

    def test_restart_recovers_cleanup_for_unallocated_and_failed_resources(self):
        first = self.create()
        second = self.create("create-2")
        resource = self.advance(self.accept(second), ResourceState.CREATING)
        self.advance(resource, ResourceState.FAILED)
        self.backend.expire(
            self.service(Role.BACKEND, Action.EXPIRE),
            now=lambda: self.deadline,
            limit=100,
        )
        self.control = ControlPlaneStore(Database(self.path, busy_timeout_ms=5000))
        tasks = self.control.reconcile(
            self.service(Role.CONTROL_PLANE, Action.RECONCILE),
            now=lambda: self.deadline,
            limit=100,
        )
        self.assertEqual({task.ref for task in tasks}, {first.ref, second.ref})
        self.assertTrue(all(task.expiry_intent for task in tasks))
        self.assertTrue(all(task.state == "STOPPING" for task in tasks))

    def test_cleanup_failure_retries_after_restart_and_requires_evidence(self):
        attempt, _ = self.ready()
        self.backend.leave(self.alice, attempt.ref, key="leave", now=lambda: self.now)
        reconciler = self.service(Role.CONTROL_PLANE, Action.RECONCILE)
        (task,) = self.control.reconcile(reconciler, now=lambda: self.now, limit=10)
        self.control.cleanup_failed(
            reconciler,
            task.ref,
            operation_id=task.operation_id,
            expected_version=task.version,
            key="cleanup-failure-1",
            error_code="RUNTIME_UNAVAILABLE",
            retry_at=self.now + timedelta(seconds=5),
            now=lambda: self.now,
        )
        self.control = ControlPlaneStore(Database(self.path, busy_timeout_ms=5000))
        self.assertEqual(
            self.control.reconcile(reconciler, now=lambda: self.now, limit=10), ()
        )
        (retried,) = self.control.reconcile(
            reconciler,
            now=lambda: self.now + timedelta(seconds=5),
            limit=10,
        )
        self.assertEqual(retried.operation_id, task.operation_id)
        self.assertEqual(retried.retry_count, 1)
        self.assert_error(
            "INVALID_REQUEST",
            lambda: self.advance(
                retried,
                ResourceState.DESTROYED,
            ),
        )
        self.advance(retried, ResourceState.DESTROYED, evidence_digest=self.evidence)
        self.backend.complete_cleanup(
            self.service(Role.BACKEND, Action.PUBLISH),
            attempt.ref,
            key="completed",
            now=lambda: self.now,
        )
        self.assertEqual(
            self.control.reconcile(reconciler, now=lambda: self.now, limit=10), ()
        )
        self.assertEqual(
            self.backend.inspect(self.alice, attempt.attempt_id).state, "DESTROYED"
        )

    def test_process_restart_sees_committed_state(self):
        receipt = self.create()
        code = (
            "from pathlib import Path; from failroom_state import *; "
            "import sys; db=Database(Path(sys.argv[1]), busy_timeout_ms=5000); "
            "db.initialize(); a=BackendStore(db).inspect("
            "UserIdentity('alice', frozenset({'disk-full'})),sys.argv[2]); "
            "print(a.state, a.generation, a.provisioning_intent)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.path), receipt.attempt_id],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        self.assertEqual(result.stdout.strip(), "PROVISIONING 1 True")

    def test_unknown_database_version_is_rejected_without_replacement(self):
        self.create()
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("PRAGMA user_version=99")
        self.assert_error("UNSUPPORTED_SCHEMA", self.db.initialize)
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 99)
            self.assertEqual(
                conn.execute("SELECT count(*) FROM room_attempts").fetchone()[0], 1
            )

    def test_failed_operation_rolls_back_preallocation_and_operation_log(self):
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("""CREATE TRIGGER fail_log BEFORE INSERT ON lifecycle_operations
                         BEGIN SELECT RAISE(ABORT,'test failure'); END""")
        self.assert_error("STORE_FAILURE", self.create)
        with closing(sqlite3.connect(self.path)) as conn:
            for table in ("room_attempts", "lifecycle_operations"):
                self.assertEqual(
                    conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0
                )

    def test_abrupt_process_exit_rolls_back_uncommitted_change(self):
        attempt = self.create()
        code = """import os, sys
from pathlib import Path
from failroom_state import Database
db = Database(Path(sys.argv[1]), busy_timeout_ms=5000)
with db._transaction() as conn:
    conn.execute("UPDATE room_attempts SET state='STOPPING',destroy_intent=1")
    os._exit(17)
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 17)
        restarted = BackendStore(Database(self.path, busy_timeout_ms=5000))
        state = restarted.inspect(self.alice, attempt.attempt_id)
        self.assertEqual(state.state, "PROVISIONING")
        self.assertFalse(state.destroy_intent)

    def test_separate_process_recovers_committed_cleanup_intent(self):
        attempt = self.create()
        self.backend.leave(self.alice, attempt.ref, key="leave", now=lambda: self.now)
        code = """import sys
from pathlib import Path
from datetime import datetime
from failroom_state import Database, ControlPlaneStore, ServiceIdentity, Role, Action
db = Database(Path(sys.argv[1]), busy_timeout_ms=5000)
db.initialize()
identity = ServiceIdentity('worker', Role.CONTROL_PLANE, frozenset({Action.RECONCILE}))
task, = ControlPlaneStore(db).reconcile(identity, now=lambda: datetime.fromisoformat(sys.argv[2]), limit=10)
print(task.attempt_id, task.state)
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.path), self.now.isoformat()],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        self.assertEqual(result.stdout.strip(), attempt.attempt_id + " STOPPING")

    def test_busy_database_fails_with_bounded_safe_error(self):
        impatient = BackendStore(Database(self.path, busy_timeout_ms=10))
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self.assert_error(
                "STORE_BUSY",
                lambda: impatient.create(
                    self.alice,
                    "disk-full",
                    key="busy",
                    expires_at=self.deadline,
                    now=lambda: self.now,
                ),
            )
        self.create()

    def test_foreign_database_is_not_adopted_or_switched_to_wal(self):
        path = Path(self.temp.name) / "foreign.sqlite3"
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("CREATE TABLE foreign_data (id INTEGER)")
        self.assert_error(
            "UNSUPPORTED_SCHEMA",
            lambda: Database(
                path,
                busy_timeout_ms=5000,
            ).initialize(),
        )
        with closing(sqlite3.connect(path)) as conn:
            self.assertEqual(
                conn.execute("PRAGMA journal_mode").fetchone()[0], "delete"
            )
            self.assertEqual(
                conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall(),
                [("foreign_data",)],
            )

    def test_expired_publish_commits_revocation_before_returning_denial(self):
        attempt = self.create()
        resource = self.advance(self.accept(attempt), ResourceState.CREATING)
        resource = self.advance(resource, ResourceState.STARTING, container_id="c-1")
        resource = self.advance(
            resource, ResourceState.READY, evidence_digest=self.evidence
        )
        self.assert_error(
            "ATTEMPT_UNAVAILABLE",
            lambda: self.backend.publish_ready(
                self.service(Role.BACKEND, Action.PUBLISH),
                resource.ref,
                expected_version=0,
                key="too-late",
                now=lambda: self.deadline,
            ),
        )
        state = self.backend.inspect(self.alice, attempt.attempt_id)
        self.assertEqual(state.state, "STOPPING")
        self.assertTrue(state.expiry_intent)
        self.assertEqual(state.session_epoch, 1)
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertIsNone(
                conn.execute(
                    "SELECT 1 FROM lifecycle_operations WHERE idempotency_key='too-late'"
                ).fetchone()
            )

    def test_expired_resource_transition_persists_its_own_cleanup_intent(self):
        resource = self.advance(self.accept(self.create()), ResourceState.CREATING)
        resource = self.advance(resource, ResourceState.STARTING, container_id="c-1")
        self.assert_error(
            "ATTEMPT_UNAVAILABLE",
            lambda: self.advance(
                resource,
                ResourceState.READY,
                evidence_digest=self.evidence,
                now=lambda: self.deadline,
            ),
        )
        record = self.control.inspect(
            self.service(Role.BACKEND, Action.INSPECT), resource.ref
        )
        self.assertEqual(record.state, "STOPPING")
        self.assertTrue(record.expiry_intent)
        self.assertTrue(record.destroy_intent)
        # Resource owner does not overwrite the backend-owned attempt.
        self.assertEqual(
            self.backend.inspect(self.alice, resource.attempt_id).state, "PROVISIONING"
        )

    def test_cleanup_flags_and_ownership_cannot_be_cleared_in_sql(self):
        attempt = self.create()
        self.backend.expire(
            self.service(Role.BACKEND, Action.EXPIRE),
            now=lambda: self.deadline,
            limit=10,
        )
        self.control.reconcile(
            self.service(Role.CONTROL_PLANE, Action.RECONCILE),
            now=lambda: self.deadline,
            limit=10,
        )
        with closing(sqlite3.connect(self.path)) as conn:
            for table in ("room_attempts", "sandbox_resources"):
                for change in ("expiry_intent=0", "destroy_intent=0", "generation=2"):
                    with self.subTest(table=table, change=change):
                        with self.assertRaises(sqlite3.IntegrityError):
                            conn.execute(f"UPDATE {table} SET {change}")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE room_attempts SET user_id='bob'")
        self.assertTrue(
            self.backend.inspect(self.alice, attempt.attempt_id).expiry_intent
        )

    def test_failed_resource_only_enters_cleanup_and_blocks_consumption(self):
        resource = self.advance(self.accept(self.create()), ResourceState.CREATING)
        failed = self.advance(resource, ResourceState.FAILED)
        self.assert_error(
            "ATTEMPT_UNAVAILABLE",
            lambda: self.advance(
                failed,
                ResourceState.CREATING,
                key="retry-create",
            ),
        )
        unchanged = self.control.inspect(
            self.service(Role.CONTROL_PLANE, Action.INSPECT), failed.ref
        )
        self.assertEqual(unchanged.state, "FAILED")
        self.assertEqual(unchanged.version, failed.version)
        tasks = self.control.reconcile(
            self.service(Role.CONTROL_PLANE, Action.RECONCILE),
            now=lambda: self.now,
            limit=10,
        )
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].ref, failed.ref)

    def test_internal_inspect_denies_user_and_wrong_scope(self):
        resource = self.accept(self.create())
        for identity in (
            self.alice,
            self.service(Role.GATEWAY, Action.INSPECT),
            self.service(Role.BACKEND, Action.CREATE),
        ):
            self.assert_error(
                "NOT_AUTHORIZED",
                lambda identity=identity: self.control.inspect(
                    identity,
                    resource.ref,
                ),
            )

    def test_stale_binding_is_rejected_for_leave_publish_and_inspect(self):
        attempt, resource = self.ready()
        for ref in (
            replace(resource.ref, generation=2),
            replace(resource.ref, sandbox_id="another"),
        ):
            calls = [
                lambda ref=ref: self.backend.leave(
                    self.alice, ref, key="stale", now=lambda: self.now
                ),
                lambda ref=ref: self.backend.publish_ready(
                    self.service(Role.BACKEND, Action.PUBLISH),
                    ref,
                    expected_version=attempt.version,
                    key="stale",
                    now=lambda: self.now,
                ),
                lambda ref=ref: self.control.inspect(
                    self.service(Role.BACKEND, Action.INSPECT), ref
                ),
            ]
            for call in calls:
                self.assert_error("STALE_BINDING", call)

    def test_reconcile_is_bounded_and_repeated_requests_return_same_work(self):
        first, second = self.create(), self.create("second")
        for receipt in (first, second):
            self.backend.leave(
                self.alice,
                receipt.ref,
                key="leave-" + receipt.attempt_id,
                now=lambda: self.now,
            )
        identity = self.service(Role.CONTROL_PLANE, Action.RECONCILE)
        (task,) = self.control.reconcile(identity, now=lambda: self.now, limit=1)
        self.assertEqual(
            (task,), self.control.reconcile(identity, now=lambda: self.now, limit=1)
        )
        self.advance(task, ResourceState.DESTROYED, evidence_digest=self.evidence)
        (next_task,) = self.control.reconcile(identity, now=lambda: self.now, limit=1)
        self.assertNotEqual(next_task.ref, task.ref)

    def test_cleanup_failure_is_idempotent(self):
        attempt = self.create()
        self.backend.leave(self.alice, attempt.ref, key="leave", now=lambda: self.now)
        identity = self.service(Role.CONTROL_PLANE, Action.RECONCILE)
        (task,) = self.control.reconcile(identity, now=lambda: self.now, limit=1)

        def fail():
            return self.control.cleanup_failed(
                identity,
                task.ref,
                operation_id=task.operation_id,
                expected_version=task.version,
                key="failure",
                error_code="CLEANUP_INCOMPLETE",
                retry_at=self.now + timedelta(seconds=1),
                now=lambda: self.now,
            )

        self.assertEqual(fail(), fail())
        (retried,) = self.control.reconcile(
            identity, now=lambda: self.now + timedelta(seconds=1), limit=1
        )
        self.assertEqual(retried.retry_count, 1)

    def test_restart_after_resource_destruction_recovers_backend_finalization(self):
        attempt = self.create()
        self.backend.leave(self.alice, attempt.ref, key="leave", now=lambda: self.now)
        (task,) = self.control.reconcile(
            self.service(Role.CONTROL_PLANE, Action.RECONCILE),
            now=lambda: self.now,
            limit=1,
        )
        self.advance(task, ResourceState.DESTROYED, evidence_digest=self.evidence)
        restarted = BackendStore(Database(self.path, busy_timeout_ms=5000))
        identity = self.service(Role.BACKEND, Action.RECONCILE)
        self.assertEqual(
            restarted.pending_finalizations(identity, limit=10), (attempt.ref,)
        )
        restarted.complete_cleanup(
            self.service(Role.BACKEND, Action.PUBLISH),
            attempt.ref,
            key="finalize",
            now=lambda: self.now,
        )
        self.assertEqual(restarted.pending_finalizations(identity, limit=10), ())
        self.assertEqual(
            restarted.inspect(self.alice, attempt.attempt_id).state, "DESTROYED"
        )

    def test_clock_is_sampled_after_waiting_for_writer_lock(self):
        attempt, _ = self.ready()
        claims = self.claims(attempt)
        clock_called = Event()
        task_started = Event()
        current = [self.now]

        def clock():
            clock_called.set()
            return current[0]

        def consume():
            task_started.set()
            try:
                self.backend.consume(
                    self.service(Role.GATEWAY, Action.CONSUME), claims, now=clock
                )
                return "unexpected-success"
            except StoreError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=1) as pool:
            with closing(sqlite3.connect(self.path)) as conn:
                conn.execute("BEGIN IMMEDIATE")
                result = pool.submit(consume)
                self.assertTrue(task_started.wait(timeout=1))
                self.assertFalse(clock_called.wait(timeout=0.05))
                current[0] = self.deadline
            self.assertEqual(result.result(timeout=5), "ATTEMPT_UNAVAILABLE")
        self.assertTrue(clock_called.is_set())
        self.assertTrue(
            self.backend.inspect(self.alice, attempt.attempt_id).expiry_intent
        )

    def test_resource_state_transition_matrix(self):
        allowed = {
            "REQUESTED": {"CREATING", "STOPPING"},
            "CREATING": {"STARTING", "FAILED", "STOPPING"},
            "STARTING": {"READY", "FAILED", "STOPPING"},
            "READY": {"RUNNING", "STOPPING"},
            "RUNNING": {"RESOLVED", "STOPPING"},
            "RESOLVED": {"STOPPING"},
            "STOPPING": {"FAILED", "DESTROYED"},
            "FAILED": {"STOPPING"},
            "DESTROYED": set(),
        }
        paths = {
            "REQUESTED": [],
            "CREATING": ["CREATING"],
            "STARTING": ["CREATING", "STARTING"],
            "READY": ["CREATING", "STARTING", "READY"],
            "RUNNING": ["CREATING", "STARTING", "READY", "RUNNING"],
            "RESOLVED": ["CREATING", "STARTING", "READY", "RUNNING", "RESOLVED"],
            "STOPPING": ["STOPPING"],
            "FAILED": ["CREATING", "FAILED"],
            "DESTROYED": ["STOPPING", "DESTROYED"],
        }

        def options(state):
            if state in ("READY", "DESTROYED"):
                return {"evidence_digest": self.evidence}
            if state == "STARTING":
                return {"container_id": str(uuid4())}
            return {}

        for source in ResourceState:
            for target in ResourceState:
                with self.subTest(source=source, target=target):
                    resource = self.accept(self.create(str(uuid4())))
                    for state in paths[source]:
                        resource = self.advance(
                            resource, ResourceState(state), **options(state)
                        )
                    if target in allowed[source]:
                        result = self.advance(
                            resource, target, key=str(uuid4()), **options(target)
                        )
                        self.assertEqual(result.state, target)
                    else:
                        with self.assertRaises(StoreError):
                            self.advance(
                                resource, target, key=str(uuid4()), **options(target)
                            )

    def test_failed_transition_requires_and_persists_safe_reason(self):
        resource = self.advance(self.accept(self.create()), ResourceState.CREATING)
        identity = self.service(Role.CONTROL_PLANE, Action.TRANSITION)
        self.assert_error(
            "INVALID_REQUEST",
            lambda: self.control.transition(
                identity,
                resource.ref,
                expected_version=resource.version,
                state=ResourceState.FAILED,
                key="fail",
                now=lambda: self.now,
            ),
        )
        for reason in ("raw error with secret", "CREATE_FAILED"):
            if reason == "CREATE_FAILED":
                result = self.control.transition(
                    identity,
                    resource.ref,
                    expected_version=resource.version,
                    state=ResourceState.FAILED,
                    key="fail",
                    now=lambda: self.now,
                    error_code=reason,
                )
            else:
                self.assert_error(
                    "INVALID_REQUEST",
                    lambda reason=reason: self.control.transition(
                        identity,
                        resource.ref,
                        expected_version=resource.version,
                        state=ResourceState.FAILED,
                        key="fail",
                        now=lambda: self.now,
                        error_code=reason,
                    ),
                )
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT error_code FROM lifecycle_operations WHERE operation_id=?",
                    (result.operation_id,),
                ).fetchone()[0],
                "CREATE_FAILED",
            )


if __name__ == "__main__":
    unittest.main()
