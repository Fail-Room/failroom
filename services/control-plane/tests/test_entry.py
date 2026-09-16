import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from failroom_state import (
    Action,
    BackendStore,
    Database,
    Receipt,
    Role,
    ServiceIdentity,
    UserIdentity,
)

from failroom_control_plane.entry import EntryError, RoomEntryService


class RecordingProvisioner:
    def __init__(self) -> None:
        self.calls: list[tuple[Receipt, ServiceIdentity, ServiceIdentity, str]] = []
        self.failure: Exception | None = None

    def provision(
        self,
        receipt: Receipt,
        *,
        backend_identity: ServiceIdentity,
        control_identity: ServiceIdentity,
        key: str,
        now,
    ) -> None:
        self.calls.append((receipt, backend_identity, control_identity, key))
        now()
        if self.failure is not None:
            raise self.failure


class RoomEntryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 9, 14, 12, tzinfo=UTC)
        database = Database(
            Path(self.temp.name) / "state.sqlite3", busy_timeout_ms=5000
        )
        database.initialize()
        self.backend = BackendStore(database)
        self.provisioner = RecordingProvisioner()
        self.user = UserIdentity("alice", frozenset({"room-1"}))
        self.backend_identity = ServiceIdentity(
            "backend",
            Role.BACKEND,
            frozenset({Action.CREATE, Action.PUBLISH}),
        )
        self.control_identity = ServiceIdentity(
            "control",
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.TRANSITION}),
        )

    def test_enter_preallocates_owned_attempt_then_provisions_exact_receipt(
        self,
    ) -> None:
        service = RoomEntryService(
            self.backend,
            self.provisioner,
            backend_identity=self.backend_identity,
            control_identity=self.control_identity,
            attempt_ttl=timedelta(minutes=15),
            now=lambda: self.now,
        )

        entry = service.enter(self.user, "room-1", key="enter-room")

        self.assertEqual(entry.room_id, "room-1")
        self.assertEqual(entry.state, "PROVISIONING")
        self.assertEqual(entry.expires_at, self.now + timedelta(minutes=15))
        self.assertEqual(len(self.provisioner.calls), 1)
        receipt, backend_identity, control_identity, key = self.provisioner.calls[0]
        self.assertEqual(receipt.attempt_id, entry.attempt_id)
        self.assertEqual(backend_identity, self.backend_identity)
        self.assertEqual(control_identity, self.control_identity)
        self.assertEqual(key, "enter-room")
        attempt = self.backend.inspect(self.user, entry.attempt_id)
        self.assertEqual(attempt.ref, receipt.ref)
        self.assertEqual(attempt.expires_at, entry.expires_at)

    def test_enter_preserves_stop_intent_when_provisioning_fails(self) -> None:
        self.provisioner.failure = RuntimeError("runtime detail must not escape")
        service = RoomEntryService(
            self.backend,
            self.provisioner,
            backend_identity=self.backend_identity,
            control_identity=self.control_identity,
            attempt_ttl=timedelta(minutes=15),
            now=lambda: self.now,
        )

        with self.assertRaises(EntryError) as raised:
            service.enter(self.user, "room-1", key="failed-enter")

        self.assertEqual(raised.exception.code, "ENTRY_FAILED")
        receipt = self.provisioner.calls[0][0]
        attempt = self.backend.inspect(self.user, receipt.attempt_id)
        self.assertEqual(attempt.state, "STOPPING")
        self.assertTrue(attempt.destroy_intent)

    def test_constructor_rejects_missing_trusted_scope_or_ttl(self) -> None:
        with self.assertRaises(EntryError) as missing_scope:
            RoomEntryService(
                self.backend,
                self.provisioner,
                backend_identity=ServiceIdentity(
                    "backend",
                    Role.BACKEND,
                    frozenset({Action.CREATE}),
                ),
                control_identity=self.control_identity,
                attempt_ttl=timedelta(minutes=15),
                now=lambda: self.now,
            )
        with self.assertRaises(EntryError) as invalid_ttl:
            RoomEntryService(
                self.backend,
                self.provisioner,
                backend_identity=self.backend_identity,
                control_identity=self.control_identity,
                attempt_ttl=timedelta(0),
                now=lambda: self.now,
            )

        self.assertEqual(missing_scope.exception.code, "INVALID_CONFIGURATION")
        self.assertEqual(invalid_ttl.exception.code, "INVALID_CONFIGURATION")


if __name__ == "__main__":
    unittest.main()
