import sqlite3
import tempfile
import unittest
from contextlib import closing
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
from failroom_control_plane.room_scenarios import RoomScenarioRegistry


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
        self.path = Path(self.temp.name) / "state.sqlite3"
        database = Database(self.path, busy_timeout_ms=5000)
        database.initialize()
        self.backend = BackendStore(database)
        self.provisioner = RecordingProvisioner()
        self.user = UserIdentity("alice", frozenset({"disk-full", "room-1"}))
        self.outsider = UserIdentity("mallory", frozenset({"room-1"}))
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

    def service(self, **overrides: object) -> RoomEntryService:
        arguments: dict[str, object] = {
            "backend_identity": self.backend_identity,
            "control_identity": self.control_identity,
            "attempt_ttl": timedelta(minutes=15),
            "now": lambda: self.now,
            "rooms": RoomScenarioRegistry(),
        }
        arguments.update(overrides)
        return RoomEntryService(self.backend, self.provisioner, **arguments)

    def attempt_count(self) -> int:
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute("SELECT COUNT(*) FROM room_attempts").fetchone()
        return int(row[0])

    def test_enter_preallocates_owned_attempt_then_provisions_exact_receipt(
        self,
    ) -> None:
        entry = self.service().enter(self.user, "disk-full", key="enter-room")

        self.assertEqual(entry.room_id, "disk-full")
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

        with self.assertRaises(EntryError) as raised:
            self.service().enter(self.user, "disk-full", key="failed-enter")

        self.assertEqual(raised.exception.code, "ENTRY_FAILED")
        receipt = self.provisioner.calls[0][0]
        attempt = self.backend.inspect(self.user, receipt.attempt_id)
        self.assertEqual(attempt.state, "STOPPING")
        self.assertTrue(attempt.destroy_intent)

    def test_enter_rejects_an_unreviewed_room_before_state_or_runtime(self) -> None:
        for room_id in ("room-1", "scenario-less-room", "DISK-FULL"):
            with self.subTest(room_id=room_id):
                with self.assertRaises(EntryError) as raised:
                    self.service().enter(self.user, room_id, key="enter-" + room_id)

                self.assertEqual(raised.exception.code, "ROOM_UNAVAILABLE")
        self.assertEqual(self.provisioner.calls, [])
        self.assertEqual(self.attempt_count(), 0)

    def test_enter_denies_a_reviewed_room_outside_the_users_scope(self) -> None:
        with self.assertRaises(EntryError) as raised:
            self.service().enter(self.outsider, "disk-full", key="foreign-enter")

        self.assertEqual(raised.exception.code, "NOT_AUTHORIZED")
        self.assertEqual(self.provisioner.calls, [])
        self.assertEqual(self.attempt_count(), 0)

    def test_enter_reduces_other_store_failures_without_provisioning(self) -> None:
        service = self.service()
        service.enter(self.user, "disk-full", key="reused-key")
        self.now += timedelta(minutes=1)

        with self.assertRaises(EntryError) as raised:
            service.enter(self.user, "disk-full", key="reused-key")

        self.assertEqual(raised.exception.code, "ENTRY_FAILED")
        self.assertEqual(len(self.provisioner.calls), 1)
        self.assertEqual(self.attempt_count(), 1)

    def test_constructor_rejects_missing_trusted_scope_ttl_or_room_catalog(
        self,
    ) -> None:
        invalid = (
            {
                "backend_identity": ServiceIdentity(
                    "backend", Role.BACKEND, frozenset({Action.CREATE})
                )
            },
            {"attempt_ttl": timedelta(0)},
            {"rooms": object()},
            {"rooms": None},
        )
        for overrides in invalid:
            with self.subTest(overrides=sorted(overrides)):
                with self.assertRaises(EntryError) as raised:
                    self.service(**overrides)
                self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")


if __name__ == "__main__":
    unittest.main()
