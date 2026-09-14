import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from failroom_state import (
    Action,
    BackendStore,
    CleanupRun,
    Database,
    Role,
    ServiceIdentity,
    UserIdentity,
)

from failroom_control_plane.lifecycle import LifecycleError, RoomLifecycleService


class RecordingCleanupWorker:
    def __init__(self) -> None:
        self.calls: list[tuple[ServiceIdentity, ServiceIdentity, int]] = []

    def run_once(
        self,
        control_identity: ServiceIdentity,
        backend_identity: ServiceIdentity,
        *,
        now,
        limit: int,
    ) -> CleanupRun:
        self.calls.append((control_identity, backend_identity, limit))
        now()
        return CleanupRun(destroyed=0, deferred=0, finalized=0)


class RoomLifecycleServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 9, 14, 12, tzinfo=UTC)
        database = Database(
            Path(self.temp.name) / "state.sqlite3", busy_timeout_ms=5000
        )
        database.initialize()
        self.backend = BackendStore(database)
        self.alice = UserIdentity("alice", frozenset({"room-1"}))
        self.bob = UserIdentity("bob", frozenset({"room-1"}))
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
        self.cleanup = RecordingCleanupWorker()

    def _create_attempt(self) -> str:
        return self.backend.create(
            self.alice,
            "room-1",
            key="create-attempt",
            expires_at=self.now + timedelta(minutes=5),
            now=lambda: self.now,
        ).attempt_id

    def _service(self) -> RoomLifecycleService:
        return RoomLifecycleService(
            self.backend,
            self.cleanup,
            control_identity=self.control_identity,
            backend_identity=self.backend_identity,
            cleanup_limit=10,
            now=lambda: self.now,
        )

    def test_status_returns_a_safe_owned_attempt_view(self) -> None:
        attempt_id = self._create_attempt()

        status = self._service().status(self.alice, attempt_id)

        self.assertEqual(status.attempt_id, attempt_id)
        self.assertEqual(status.room_id, "room-1")
        self.assertEqual(status.state, "PROVISIONING")
        self.assertEqual(status.expires_at, self.now + timedelta(minutes=5))
        self.assertFalse(status.destroy_intent)
        self.assertFalse(hasattr(status, "sandbox_id"))
        self.assertFalse(hasattr(status, "generation"))

    def test_leave_uses_owned_binding_then_runs_one_bounded_cleanup_pass(self) -> None:
        attempt_id = self._create_attempt()

        status = self._service().leave(self.alice, attempt_id, key="leave-attempt")

        self.assertEqual(status.state, "STOPPING")
        self.assertTrue(status.destroy_intent)
        self.assertEqual(
            self.cleanup.calls,
            [(self.control_identity, self.backend_identity, 10)],
        )

    def test_leave_rejects_foreign_attempt_before_cleanup(self) -> None:
        attempt_id = self._create_attempt()

        with self.assertRaises(LifecycleError) as raised:
            self._service().leave(self.bob, attempt_id, key="leave-attempt")

        self.assertEqual(raised.exception.code, "NOT_AUTHORIZED")
        self.assertEqual(self.cleanup.calls, [])


if __name__ == "__main__":
    unittest.main()
