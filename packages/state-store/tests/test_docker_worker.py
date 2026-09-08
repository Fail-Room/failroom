import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from failroom_state import (
    Action,
    BackendStore,
    ControlPlaneStore,
    Database,
    ResourceState,
    Role,
    ServiceIdentity,
    StoreError,
    UserIdentity,
    docker_worker,
)


class RecordingRuntime:
    def __init__(self, action=None):
        self.targets = []
        self.action = action

    def destroy_and_verify_absent(self, target):
        self.targets.append(target)
        if self.action is not None:
            return self.action(target)
        return "sha256:" + "a" * 64


class DockerCleanupWorkerTests(unittest.TestCase):
    def setUp(self):
        self.module = docker_worker
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.database = Database(self.path, busy_timeout_ms=100)
        self.database.initialize()
        self.control = ControlPlaneStore(self.database)
        self.backend = BackendStore(self.database)
        self.current = datetime(2026, 9, 7, tzinfo=UTC)
        self.alice = UserIdentity("alice", frozenset({"disk-full"}))
        self.control_identity = ServiceIdentity(
            "cleanup-control",
            Role.CONTROL_PLANE,
            frozenset({Action.RECONCILE, Action.INSPECT, Action.TRANSITION}),
        )
        self.backend_identity = ServiceIdentity(
            "cleanup-backend",
            Role.BACKEND,
            frozenset({Action.RECONCILE, Action.PUBLISH}),
        )
        self.runtime = RecordingRuntime()

    def worker(self, *, backend=None, control=None, runtime=None, retry_delay=None):
        return self.module.DockerCleanupWorker(
            control or self.control,
            backend or self.backend,
            runtime or self.runtime,
            retry_delay=timedelta(seconds=10) if retry_delay is None else retry_delay,
        )

    def run_worker(self, *, worker=None, limit=10, control=None, backend=None):
        return (worker or self.worker()).run_once(
            self.control_identity if control is None else control,
            self.backend_identity if backend is None else backend,
            now=lambda: self.current,
            limit=limit,
        )

    def create(self, key="create", *, container_id=None, leave=True):
        receipt = self.backend.create(
            self.alice,
            "disk-full",
            key=key,
            expires_at=self.current + timedelta(minutes=30),
            now=lambda: self.current,
        )
        if container_id is not None:
            resource = self.control.accept(
                ServiceIdentity("creator", Role.BACKEND, frozenset({Action.CREATE})),
                receipt.ref,
                key="accept-" + key,
                now=lambda: self.current,
            )
            for state, kwargs in (
                (ResourceState.CREATING, {}),
                (ResourceState.STARTING, {"container_id": container_id}),
            ):
                resource = self.control.transition(
                    self.control_identity,
                    receipt.ref,
                    expected_version=resource.version,
                    state=state,
                    key=state + "-" + key,
                    now=lambda: self.current,
                    **kwargs,
                )
        if leave:
            self.backend.leave(
                self.alice, receipt.ref, key="leave-" + key, now=lambda: self.current
            )
        return receipt.ref

    def cleanup_task(self):
        (task,) = self.control.reconcile(
            self.control_identity, now=lambda: self.current, limit=1
        )
        return task

    def resource(self, ref):
        return self.control.inspect(self.control_identity, ref)

    def operation(self, ref):
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute(
                """SELECT status,retry_count,retry_at,error_code
                FROM lifecycle_operations WHERE actor='internal:cleanup'
                AND sandbox_id=?""",
                (ref.sandbox_id,),
            ).fetchone()

    def mark_destroyed(self, task):
        self.control.transition(
            self.control_identity,
            task.ref,
            expected_version=task.version,
            state=ResourceState.DESTROYED,
            key="external-destroy-" + task.operation_id,
            now=lambda: self.current,
            evidence_digest="sha256:" + "a" * 64,
        )

    def assert_counts(self, result, destroyed, deferred, finalized):
        self.assertEqual(
            (result.destroyed, result.deferred, result.finalized),
            (destroyed, deferred, finalized),
        )

    def test_verified_cleanup_uses_exact_target_and_finalizes_backend(self):
        ref = self.create(container_id="container-1")
        task = self.cleanup_task()

        def verify(target):
            self.assertEqual(self.resource(ref).state, "STOPPING")
            self.assertEqual(
                self.backend.inspect(self.alice, ref.attempt_id).state, "STOPPING"
            )
            return "sha256:" + "b" * 64

        self.runtime.action = verify
        self.assert_counts(self.run_worker(), 1, 0, 1)
        self.assertEqual(
            self.runtime.targets,
            [
                self.module.CleanupTarget(
                    ref,
                    "container-1",
                    self.resource(ref).runtime_operation_id,
                    task.operation_id,
                )
            ],
        )
        self.assertEqual(
            self.resource(ref).cleanup_evidence_digest, "sha256:" + "b" * 64
        )
        self.assertEqual(self.resource(ref).state, "DESTROYED")
        self.assertEqual(
            self.backend.inspect(self.alice, ref.attempt_id).state, "DESTROYED"
        )
        self.assertEqual(self.operation(ref)[:2], ("SUCCEEDED", 0))
        self.assert_counts(self.run_worker(), 0, 0, 0)
        self.assertEqual(len(self.runtime.targets), 1)

    def test_missing_container_identity_still_requires_absence_verification(self):
        ref = self.create()
        self.assert_counts(self.run_worker(), 1, 0, 1)
        self.assertIsNone(self.runtime.targets[0].container_id)
        self.assertEqual(self.runtime.targets[0].ref, ref)
        self.assertIsNotNone(self.resource(ref).cleanup_evidence_digest)

    def test_expired_attempt_is_reconciled_without_preexisting_resource(self):
        ref = self.create(leave=False)
        self.current += timedelta(minutes=30)
        self.assert_counts(self.run_worker(), 1, 0, 1)
        self.assertTrue(self.resource(ref).expiry_intent)
        self.assertTrue(self.backend.inspect(self.alice, ref.attempt_id).expiry_intent)

    def test_runtime_failure_persists_fixed_code_and_future_backoff(self):
        for code in ("RUNTIME_UNAVAILABLE", "CLEANUP_INCOMPLETE"):
            with self.subTest(code=code):
                ref = self.create(code)

                def fail(target, reason=code):
                    raise self.module.RuntimeCleanupError(reason)

                self.runtime.action = fail
                self.assert_counts(self.run_worker(), 0, 1, 0)
                operation = self.operation(ref)
                self.assertEqual(operation[:2], ("RETRY", 1))
                self.assertEqual(operation[3], code)
                self.assertEqual(
                    operation[2],
                    int((self.current + timedelta(seconds=10)).timestamp() * 1_000_000),
                )
                self.assertEqual(self.resource(ref).state, "FAILED")
                self.assertTrue(self.resource(ref).destroy_intent)
                self.current += timedelta(seconds=9)
                self.assert_counts(self.run_worker(), 0, 0, 0)
                self.current += timedelta(seconds=1)
                self.runtime.action = None
                self.assert_counts(self.run_worker(), 1, 0, 1)
                self.assertEqual(
                    self.runtime.targets[-1].operation_id,
                    self.runtime.targets[-2].operation_id,
                )

    def test_unknown_exception_and_invalid_digest_never_persist_raw_content(self):
        for value in (
            "sha256:" + "A" * 64,
            "secret-raw-output",
            None,
            "sha256:" + "a" * 65,
        ):
            with self.subTest(value=value):
                ref = self.create(str(len(self.runtime.targets)))
                self.runtime.action = lambda target, result=value: result
                self.assert_counts(self.run_worker(), 0, 1, 0)
                self.assertEqual(self.operation(ref)[3], "CLEANUP_INCOMPLETE")
                self.assertIsNone(self.resource(ref).cleanup_evidence_digest)
        ref = self.create("exception")

        def raw_error(target):
            raise RuntimeError("secret raw container output")

        self.runtime.action = raw_error
        self.assert_counts(self.run_worker(), 0, 1, 0)
        self.assertEqual(self.operation(ref)[3], "CLEANUP_INCOMPLETE")
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertNotIn("secret", "\n".join(connection.iterdump()))

    def test_runtime_error_rejects_unbounded_reason(self):
        with self.assertRaises(ValueError) as caught:
            self.module.RuntimeCleanupError("raw secret")
        self.assertNotIn("secret", str(caught.exception))

    def test_mutated_runtime_failure_reason_is_reduced_to_fixed_code(self):
        ref = self.create()

        def fail(target):
            error = self.module.RuntimeCleanupError("RUNTIME_UNAVAILABLE")
            error.code = {"secret": "raw output"}
            raise error

        self.runtime.action = fail
        self.assert_counts(self.run_worker(), 0, 1, 0)
        self.assertEqual(self.operation(ref)[3], "CLEANUP_INCOMPLETE")

    def test_retry_time_starts_after_runtime_failure(self):
        ref = self.create()

        def fail(target):
            self.current += timedelta(seconds=25)
            raise self.module.RuntimeCleanupError("RUNTIME_UNAVAILABLE")

        self.runtime.action = fail
        self.assert_counts(self.run_worker(), 0, 1, 0)
        self.assertEqual(
            self.operation(ref)[2],
            int((self.current + timedelta(seconds=10)).timestamp() * 1_000_000),
        )

    def test_retry_deadline_elapsed_during_store_wait_defers_without_false_failure(
        self,
    ):
        ref = self.create()
        original = self.control.cleanup_failed

        def delayed_store(*args, **kwargs):
            self.current += timedelta(seconds=11)
            return original(*args, **kwargs)

        def fail(target):
            raise self.module.RuntimeCleanupError("RUNTIME_UNAVAILABLE")

        self.runtime.action = fail
        with patch.object(self.control, "cleanup_failed", side_effect=delayed_store):
            self.assert_counts(self.run_worker(), 0, 1, 0)
        self.assertEqual(self.resource(ref).state, "STOPPING")
        self.assertEqual(self.operation(ref)[:2], ("PENDING", 0))
        self.assertEqual(len(self.runtime.targets), 1)

    def test_stale_version_and_ineligible_observation_never_call_runtime(self):
        ref = self.create()
        task = self.cleanup_task()
        observation = self.resource(ref)
        for changed in (
            replace(observation, version=task.version + 1),
            replace(observation, state="DESTROYED"),
            replace(observation, destroy_intent=False),
            replace(observation, ref=replace(ref, generation=ref.generation + 1)),
        ):
            with (
                self.subTest(changed=changed),
                patch.object(self.control, "inspect", return_value=changed),
            ):
                self.assert_counts(self.run_worker(), 0, 1, 0)
        self.assertEqual(self.runtime.targets, [])
        self.assertEqual(self.operation(ref)[:2], ("PENDING", 0))

    def test_restart_drains_finalizations_without_runtime_call(self):
        ref = self.create()
        self.mark_destroyed(self.cleanup_task())
        worker = self.worker(
            backend=BackendStore(Database(self.path, busy_timeout_ms=100)),
            control=ControlPlaneStore(Database(self.path, busy_timeout_ms=100)),
        )
        self.assert_counts(self.run_worker(worker=worker), 0, 0, 1)
        self.assertEqual(self.runtime.targets, [])
        self.assertEqual(
            self.backend.inspect(self.alice, ref.attempt_id).state, "DESTROYED"
        )
        self.assert_counts(self.run_worker(worker=worker), 0, 0, 0)

    def test_finalization_failure_is_recoverable_without_repeating_runtime(self):
        ref = self.create()
        with patch.object(
            self.backend, "complete_cleanup", side_effect=StoreError("STORE_BUSY")
        ):
            self.assert_counts(self.run_worker(), 1, 1, 0)
        self.assertEqual(self.resource(ref).state, "DESTROYED")
        self.assertEqual(self.operation(ref)[:2], ("SUCCEEDED", 0))
        self.assert_counts(self.run_worker(), 0, 0, 1)
        self.assertEqual(len(self.runtime.targets), 1)

    def test_cas_loss_after_absence_does_not_record_runtime_failure(self):
        ref = self.create()

        def concurrent_transition(target):
            task = self.cleanup_task()
            self.control.cleanup_failed(
                self.control_identity,
                ref,
                operation_id=task.operation_id,
                expected_version=task.version,
                key="competitor",
                error_code="RUNTIME_UNAVAILABLE",
                retry_at=self.current + timedelta(seconds=10),
                now=lambda: self.current,
            )
            return "sha256:" + "a" * 64

        self.runtime.action = concurrent_transition
        self.assert_counts(self.run_worker(), 0, 1, 0)
        self.assertEqual(self.operation(ref)[:2], ("RETRY", 1))
        self.assertEqual(self.operation(ref)[3], "RUNTIME_UNAVAILABLE")
        self.assertIsNone(self.resource(ref).cleanup_evidence_digest)

    def test_concurrent_workers_reuse_exact_operation_and_cas_receipt(self):
        ref = self.create()
        barrier = Barrier(2)

        def verify(target):
            barrier.wait(timeout=5)
            return "sha256:" + "a" * 64

        self.runtime.action = verify
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.run_worker(), range(2)))
        self.assertTrue(all(result.deferred == 0 for result in results))
        self.assertEqual(len(self.runtime.targets), 2)
        self.assertEqual(self.runtime.targets[0], self.runtime.targets[1])
        self.assertEqual(self.resource(ref).version, 1)
        self.assertEqual(self.operation(ref)[:2], ("SUCCEEDED", 0))
        self.assertEqual(
            self.backend.inspect(self.alice, ref.attempt_id).state, "DESTROYED"
        )

    def test_store_errors_defer_without_runtime_failure_records(self):
        ref = self.create()
        self.cleanup_task()
        cases = (
            (self.backend, "pending_finalizations", "STORE_BUSY"),
            (self.control, "reconcile", "STORE_BUSY"),
            (self.control, "inspect", "STALE_BINDING"),
            (self.control, "transition", "STORE_BUSY"),
        )
        for store, method, code in cases:
            with (
                self.subTest(method=method),
                patch.object(store, method, side_effect=StoreError(code)),
            ):
                self.assert_counts(self.run_worker(), 0, 1, 0)
                self.assertEqual(self.operation(ref)[:2], ("PENDING", 0))
                self.assertIsNone(self.operation(ref)[3])

    def test_real_sqlite_writer_contention_defers_without_runtime_call(self):
        self.create()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.assert_counts(self.run_worker(), 0, 1, 0)
        self.assertEqual(self.runtime.targets, [])
        self.assert_counts(self.run_worker(), 1, 0, 1)

    def test_failed_cleanup_persistence_cas_loss_does_not_retry_inline(self):
        ref = self.create()

        def fail(target):
            raise self.module.RuntimeCleanupError("CLEANUP_INCOMPLETE")

        self.runtime.action = fail
        with patch.object(
            self.control, "cleanup_failed", side_effect=StoreError("STALE_VERSION")
        ):
            self.assert_counts(self.run_worker(), 0, 1, 0)
        self.assertEqual(len(self.runtime.targets), 1)
        self.assertEqual(self.operation(ref)[:2], ("PENDING", 0))

    def test_all_required_identities_are_checked_before_any_side_effect(self):
        ref = self.create()
        identities = (
            ("control", self.alice),
            ("backend", self.alice),
            ("control", replace(self.control_identity, role=Role.BACKEND)),
            ("backend", replace(self.backend_identity, service_id="invalid secret")),
        )
        for name, identity in identities:
            with (
                self.subTest(name=name, identity=identity),
                self.assertRaises(StoreError),
            ):
                self.run_worker(**{name: identity})
        for name, identity in (
            ("control", self.control_identity),
            ("backend", self.backend_identity),
        ):
            for scope in identity.scopes:
                invalid = replace(identity, scopes=identity.scopes - {scope})
                with (
                    self.subTest(name=name, missing=scope),
                    self.assertRaises(StoreError),
                ):
                    self.run_worker(**{name: invalid})
        self.assertEqual(self.runtime.targets, [])
        self.assertIsNone(self.operation(ref))

    def test_run_limit_covers_pending_finalizations_before_new_cleanup(self):
        first = self.create("first")
        self.mark_destroyed(self.cleanup_task())
        second = self.create("second")
        self.assert_counts(self.run_worker(limit=1), 0, 0, 1)
        self.assertEqual(self.runtime.targets, [])
        self.assertEqual(
            self.backend.inspect(self.alice, first.attempt_id).state, "DESTROYED"
        )
        self.assertIsNone(self.operation(second))
        self.assert_counts(self.run_worker(limit=1), 1, 0, 1)
        self.assertEqual(self.runtime.targets[0].ref, second)

    def test_invalid_configuration_limit_and_clock_cause_no_runtime_effects(self):
        ref = self.create()
        for delay in (timedelta(0), timedelta(seconds=-1), "10", 1):
            with self.subTest(delay=delay), self.assertRaises(StoreError):
                self.worker(retry_delay=delay)
        for limit in (0, -1, 1001, True):
            with self.subTest(limit=limit), self.assertRaises(StoreError):
                self.run_worker(limit=limit)
        with self.assertRaises(StoreError):
            self.worker().run_once(
                self.control_identity,
                self.backend_identity,
                now=lambda: "invalid",
                limit=1,
            )
        self.assertEqual(self.runtime.targets, [])
        self.assertIsNone(self.operation(ref))

    def test_cleanup_target_keeps_original_runtime_operation_id(self):
        ref = self.create(container_id="container-2")
        task = self.cleanup_task()
        with closing(sqlite3.connect(self.path)) as connection:
            runtime_id = connection.execute(
                "SELECT runtime_operation_id FROM room_attempts WHERE attempt_id=?",
                (ref.attempt_id,),
            ).fetchone()[0]

        self.assertRegex(runtime_id or "", r"^[0-9a-f]{32}$")
        self.assert_counts(self.run_worker(), 1, 0, 1)
        target = self.runtime.targets[0]
        self.assertEqual(target.runtime_operation_id, runtime_id)
        self.assertNotEqual(target.runtime_operation_id, task.operation_id)

    def test_legacy_cleanup_keeps_null_runtime_operation_id(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                """INSERT INTO room_attempts
                (attempt_id,user_id,room_id,sandbox_id,generation,state,created_at,expires_at,
                 destroy_intent,runtime_operation_id)
                VALUES ('legacy-cleanup-attempt','alice','disk-full',
                'legacy-cleanup-sandbox',1,'STOPPING',?,?,1,NULL)""",
                (
                    int(self.current.timestamp() * 1_000_000),
                    int((self.current + timedelta(minutes=30)).timestamp() * 1_000_000),
                ),
            )
            connection.commit()

        self.assert_counts(self.run_worker(), 1, 0, 1)
        target = self.runtime.targets[0]
        self.assertIsNone(target.runtime_operation_id)


if __name__ == "__main__":
    unittest.main()
