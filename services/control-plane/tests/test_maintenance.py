import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from failroom_state import (
    Action,
    BackendStore,
    CleanupRun,
    Database,
    Receipt,
    ResourceRef,
    Role,
    ServiceIdentity,
    UserIdentity,
)

from failroom_control_plane.maintenance import (
    LifecycleMaintenanceService,
    MaintenanceError,
)


class RecordingCleanupWorker:
    def __init__(self) -> None:
        self.calls: list[tuple[ServiceIdentity, ServiceIdentity, int]] = []
        self.failure: Exception | None = None

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
        if self.failure is not None:
            raise self.failure
        return CleanupRun(destroyed=0, deferred=0, finalized=0)


class RecordingResetProvisioner:
    def __init__(self) -> None:
        self.calls: list[tuple[Receipt, str]] = []

    def provision(
        self,
        receipt: Receipt,
        *,
        backend_identity: ServiceIdentity,
        control_identity: ServiceIdentity,
        key: str,
        now,
    ) -> None:
        del backend_identity, control_identity
        now()
        self.calls.append((receipt, key))


class LifecycleMaintenanceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 9, 14, 12, tzinfo=UTC)
        database = Database(
            Path(self.temp.name) / "state.sqlite3", busy_timeout_ms=5000
        )
        database.initialize()
        self.backend = BackendStore(database)
        self.user = UserIdentity("alice", frozenset({"room-1"}))
        self.control_identity = ServiceIdentity(
            "cleanup-control",
            Role.CONTROL_PLANE,
            frozenset({Action.RECONCILE, Action.INSPECT, Action.TRANSITION}),
        )
        self.backend_identity = ServiceIdentity(
            "maintenance-backend",
            Role.BACKEND,
            frozenset({Action.CREATE, Action.EXPIRE, Action.RECONCILE, Action.PUBLISH}),
        )
        self.cleanup = RecordingCleanupWorker()

    def test_run_once_persists_expiry_before_invoking_bounded_cleanup(self) -> None:
        attempt_id = self.backend.create(
            self.user,
            "room-1",
            key="expired-attempt",
            expires_at=self.now,
            now=lambda: self.now - timedelta(seconds=1),
        ).attempt_id
        service = LifecycleMaintenanceService(
            self.backend,
            self.cleanup,
            control_identity=self.control_identity,
            backend_identity=self.backend_identity,
            limit=10,
            now=lambda: self.now,
        )

        result = service.run_once()

        self.assertEqual(result.expired, 1)
        self.assertEqual(result.cleanup, CleanupRun(0, 0, 0))
        self.assertEqual(
            self.cleanup.calls,
            [(self.control_identity, self.backend_identity, 10)],
        )
        attempt = self.backend.inspect(self.user, attempt_id)
        self.assertEqual(attempt.state, "STOPPING")
        self.assertTrue(attempt.expiry_intent)

    def test_run_once_preserves_expiry_intent_when_cleanup_fails(self) -> None:
        attempt_id = self.backend.create(
            self.user,
            "room-1",
            key="expired-cleanup-failure",
            expires_at=self.now,
            now=lambda: self.now - timedelta(seconds=1),
        ).attempt_id
        self.cleanup.failure = RuntimeError("runtime detail must not escape")
        service = LifecycleMaintenanceService(
            self.backend,
            self.cleanup,
            control_identity=self.control_identity,
            backend_identity=self.backend_identity,
            limit=10,
            now=lambda: self.now,
        )

        with self.assertRaises(MaintenanceError) as raised:
            service.run_once()

        self.assertEqual(raised.exception.code, "MAINTENANCE_INCOMPLETE")
        attempt = self.backend.inspect(self.user, attempt_id)
        self.assertEqual(attempt.state, "STOPPING")
        self.assertTrue(attempt.expiry_intent)

    def test_run_once_resumes_exact_reset_candidate_after_cleanup(self) -> None:
        candidate = Receipt(
            "reset-operation",
            ResourceRef("attempt-reset", "sandbox-reset", 2),
            "RESETTING",
            3,
        )
        provisioner = RecordingResetProvisioner()
        service = LifecycleMaintenanceService(
            self.backend,
            self.cleanup,
            control_identity=self.control_identity,
            backend_identity=self.backend_identity,
            limit=10,
            now=lambda: self.now,
            reset_provisioner=provisioner,
        )

        with patch.object(
            self.backend,
            "pending_reset_provisioning",
            return_value=(candidate,),
        ) as pending:
            service.run_once()

        pending.assert_called_once_with(self.backend_identity, limit=10)
        self.assertEqual(len(provisioner.calls), 1)
        self.assertEqual(provisioner.calls[0][0], candidate)
        self.assertTrue(provisioner.calls[0][1].startswith("reset-resume:"))


if __name__ == "__main__":
    unittest.main()
