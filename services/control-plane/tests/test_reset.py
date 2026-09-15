import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from failroom_state import (
    Action,
    BackendStore,
    ControlPlaneStore,
    Database,
    ResourceState,
    Role,
    ServiceIdentity,
    UserIdentity,
)

from failroom_control_plane.reset import ResetError, RoomResetService


class RoomResetServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 9, 14, 12, tzinfo=UTC)
        database = Database(
            Path(self.temp.name) / "state.sqlite3", busy_timeout_ms=5000
        )
        database.initialize()
        self.backend = BackendStore(database)
        self.control = ControlPlaneStore(database)
        self.alice = UserIdentity("alice", frozenset({"room-1"}))
        self.bob = UserIdentity("bob", frozenset({"room-1"}))
        self.backend_identity = ServiceIdentity(
            "backend", Role.BACKEND, frozenset({Action.CREATE, Action.PUBLISH})
        )
        self.control_identity = ServiceIdentity(
            "control",
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.TRANSITION}),
        )

    def _ready_attempt(self) -> str:
        receipt = self.backend.create(
            self.alice,
            "room-1",
            key="create-ready-reset",
            expires_at=self.now + timedelta(minutes=5),
            now=lambda: self.now,
        )
        resource = self.control.accept(
            self.backend_identity,
            receipt.ref,
            key="accept-ready-reset",
            now=lambda: self.now,
        )
        resource = self.control.transition(
            self.control_identity,
            receipt.ref,
            expected_version=resource.version,
            state=ResourceState.CREATING,
            key="create-ready-reset",
            now=lambda: self.now,
        )
        resource = self.control.transition(
            self.control_identity,
            receipt.ref,
            expected_version=resource.version,
            state=ResourceState.STARTING,
            key="start-ready-reset",
            container_id="a" * 64,
            now=lambda: self.now,
        )
        self.control.transition(
            self.control_identity,
            receipt.ref,
            expected_version=resource.version,
            state=ResourceState.READY,
            key="ready-ready-reset",
            evidence_digest="sha256:" + "a" * 64,
            now=lambda: self.now,
        )
        self.backend.publish_ready(
            self.backend_identity,
            receipt.ref,
            expected_version=receipt.version,
            key="publish-ready-reset",
            now=lambda: self.now,
        )
        return receipt.attempt_id

    def _service(self) -> RoomResetService:
        return RoomResetService(self.backend, now=lambda: self.now)

    def test_reset_reserves_owned_candidate_and_returns_safe_resetting_view(self):
        attempt_id = self._ready_attempt()

        status = self._service().reset(self.alice, attempt_id, key="reset-room")

        self.assertEqual(status.attempt_id, attempt_id)
        self.assertEqual(status.room_id, "room-1")
        self.assertEqual(status.state, "RESETTING")
        self.assertFalse(status.destroy_intent)
        self.assertFalse(hasattr(status, "sandbox_id"))
        self.assertFalse(hasattr(status, "generation"))

    def test_reset_rejects_foreign_owner_without_state_change(self):
        attempt_id = self._ready_attempt()

        with self.assertRaises(ResetError) as raised:
            self._service().reset(self.bob, attempt_id, key="foreign-reset")

        self.assertEqual(raised.exception.code, "NOT_AUTHORIZED")
        self.assertEqual(
            self.backend.inspect(self.alice, attempt_id).state,
            "READY",
        )


if __name__ == "__main__":
    unittest.main()
