import hashlib
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from failroom_api import (
    BackendCapabilityAuthority,
    BearerCredential,
    BearerIdentityVerifier,
    CapabilityCodec,
)
from failroom_state import (
    Action,
    BackendStore,
    CleanupRun,
    ControlPlaneStore,
    Database,
    ResourceState,
    Role,
    ServiceIdentity,
    UserIdentity,
)
from fastapi.testclient import TestClient

from failroom_control_plane.entry import RoomEntryService
from failroom_control_plane.http import create_app
from failroom_control_plane.lifecycle import RoomLifecycleService
from failroom_control_plane.reset import RoomResetService


class RecordingCleanupWorker:
    def __init__(self) -> None:
        self.calls = 0

    def run_once(
        self,
        control_identity,
        backend_identity,
        *,
        now,
        limit,
    ) -> CleanupRun:
        self.calls += 1
        now()
        return CleanupRun(destroyed=0, deferred=0, finalized=0)


class RecordingProvisioner:
    def __init__(self) -> None:
        self.keys: list[str] = []
        self.failure: Exception | None = None

    def provision(
        self,
        receipt,
        *,
        backend_identity,
        control_identity,
        key,
        now,
    ) -> None:
        del receipt, backend_identity, control_identity
        self.keys.append(key)
        now()
        if self.failure is not None:
            raise self.failure


class CapabilityHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 9, 9, 12, tzinfo=UTC)
        self.deadline = self.now + timedelta(minutes=5)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.database = Database(self.path, busy_timeout_ms=5000)
        self.database.initialize()
        self.backend = BackendStore(self.database)
        self.control = ControlPlaneStore(self.database)
        self.user = UserIdentity("alice", frozenset({"room-1"}))
        self.other_user = UserIdentity("bob", frozenset({"room-1"}))
        self.backend_identity = ServiceIdentity(
            "backend", Role.BACKEND, frozenset({Action.CREATE, Action.PUBLISH})
        )
        self.control_identity = ServiceIdentity(
            "control", Role.CONTROL_PLANE, frozenset({Action.TRANSITION})
        )
        self.codec = CapabilityCodec(b"k" * 32, max_lifetime=timedelta(seconds=60))
        self.authority = BackendCapabilityAuthority(self.backend, self.codec)
        self.cleanup = RecordingCleanupWorker()
        self.lifecycle = RoomLifecycleService(
            self.backend,
            self.cleanup,
            control_identity=ServiceIdentity(
                "cleanup-control",
                Role.CONTROL_PLANE,
                frozenset({Action.RECONCILE, Action.INSPECT, Action.TRANSITION}),
            ),
            backend_identity=ServiceIdentity(
                "cleanup-backend",
                Role.BACKEND,
                frozenset({Action.RECONCILE, Action.PUBLISH}),
            ),
            cleanup_limit=10,
            now=lambda: self.now,
        )
        self.provisioner = RecordingProvisioner()
        self.entry = RoomEntryService(
            self.backend,
            self.provisioner,
            backend_identity=self.backend_identity,
            control_identity=ServiceIdentity(
                "entry-control",
                Role.CONTROL_PLANE,
                frozenset({Action.INSPECT, Action.TRANSITION}),
            ),
            attempt_ttl=timedelta(minutes=15),
            now=lambda: self.now,
        )
        self.reset = RoomResetService(self.backend, now=lambda: self.now)
        self.token = "local-token-with-at-least-32-bytes-0001"
        self.other_token = "other-token-with-at-least-32-bytes-0001"
        verifier = BearerIdentityVerifier(
            {
                hashlib.sha256(
                    self.token.encode("ascii")
                ).hexdigest(): BearerCredential(
                    self.user,
                    self.now + timedelta(minutes=10),
                ),
                hashlib.sha256(
                    self.other_token.encode("ascii")
                ).hexdigest(): BearerCredential(
                    self.other_user,
                    self.now + timedelta(minutes=10),
                ),
            },
            now=lambda: self.now,
        )
        self.client = TestClient(
            create_app(
                authority=self.authority,
                verifier=verifier,
                now=lambda: self.now,
                lifecycle=self.lifecycle,
                entry=self.entry,
                reset=self.reset,
            )
        )

    def _ready(self) -> str:
        receipt = self.backend.create(
            self.user,
            "room-1",
            key="create-" + uuid4().hex,
            expires_at=self.deadline,
            now=lambda: self.now,
        )
        accepted = self.control.accept(
            self.backend_identity,
            receipt.ref,
            key="accept-" + uuid4().hex,
            now=lambda: self.now,
        )
        creating = self.control.transition(
            self.control_identity,
            receipt.ref,
            expected_version=accepted.version,
            state=ResourceState.CREATING,
            key="creating-" + uuid4().hex,
            now=lambda: self.now,
        )
        starting = self.control.transition(
            self.control_identity,
            receipt.ref,
            expected_version=creating.version,
            state=ResourceState.STARTING,
            container_id="container-1",
            key="starting-" + uuid4().hex,
            now=lambda: self.now,
        )
        self.control.transition(
            self.control_identity,
            receipt.ref,
            expected_version=starting.version,
            state=ResourceState.READY,
            evidence_digest="sha256:" + "a" * 64,
            key="ready-" + uuid4().hex,
            now=lambda: self.now,
        )
        self.backend.publish_ready(
            self.backend_identity,
            receipt.ref,
            expected_version=0,
            key="publish-" + uuid4().hex,
            now=lambda: self.now,
        )
        return receipt.attempt_id

    def test_capability_endpoint_uses_verified_identity(self) -> None:
        attempt_id = self._ready()

        response = self.client.post(
            f"/v1/attempts/{attempt_id}/terminal-capability",
            headers={"Authorization": "Bearer " + self.token},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"capability", "expires_at"})
        self.assertNotIn("sandbox_id", response.json())

    def test_unknown_identity_returns_fixed_error(self) -> None:
        attempt_id = self._ready()

        response = self.client.post(
            f"/v1/attempts/{attempt_id}/terminal-capability",
            headers={"Authorization": "Bearer unknown-token-with-32-bytes-0001"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"code": "AUTHENTICATION_REQUIRED"})

    def test_enter_room_creates_a_safe_owned_attempt(self) -> None:
        response = self.client.post(
            "/v1/rooms/room-1/attempts",
            headers={
                "Authorization": "Bearer " + self.token,
                "Idempotency-Key": "enter-room",
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            set(response.json()),
            {"attempt_id", "room_id", "state", "expires_at"},
        )
        self.assertEqual(response.json()["room_id"], "room-1")
        self.assertEqual(response.json()["state"], "PROVISIONING")
        self.assertEqual(self.provisioner.keys, ["enter-room"])
        self.assertNotIn("sandbox_id", response.json())
        self.assertNotIn("generation", response.json())

    def test_enter_room_requires_an_idempotency_key(self) -> None:
        response = self.client.post(
            "/v1/rooms/room-1/attempts",
            headers={"Authorization": "Bearer " + self.token},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"code": "INVALID_REQUEST"})
        self.assertEqual(self.provisioner.keys, [])

    def test_enter_room_reduces_provisioning_failure(self) -> None:
        self.provisioner.failure = RuntimeError("runtime detail must not escape")

        response = self.client.post(
            "/v1/rooms/room-1/attempts",
            headers={
                "Authorization": "Bearer " + self.token,
                "Idempotency-Key": "failed-enter-room",
            },
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"code": "ENTRY_FAILED"})

    def test_status_endpoint_returns_only_safe_owned_attempt_fields(self) -> None:
        attempt_id = self._ready()

        response = self.client.get(
            f"/v1/attempts/{attempt_id}/status",
            headers={"Authorization": "Bearer " + self.token},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "attempt_id": attempt_id,
                "room_id": "room-1",
                "state": "READY",
                "expires_at": self.deadline.isoformat(),
                "destroy_intent": False,
            },
        )
        self.assertNotIn("sandbox_id", response.json())
        self.assertNotIn("generation", response.json())

    def test_leave_endpoint_requires_key_then_runs_cleanup(self) -> None:
        attempt_id = self._ready()

        missing = self.client.post(
            f"/v1/attempts/{attempt_id}/leave",
            headers={"Authorization": "Bearer " + self.token},
        )
        accepted = self.client.post(
            f"/v1/attempts/{attempt_id}/leave",
            headers={
                "Authorization": "Bearer " + self.token,
                "Idempotency-Key": "leave-attempt",
            },
        )

        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.json(), {"code": "INVALID_REQUEST"})
        self.assertEqual(accepted.status_code, 202)
        self.assertEqual(accepted.json()["state"], "STOPPING")
        self.assertTrue(accepted.json()["destroy_intent"])
        self.assertEqual(self.cleanup.calls, 1)

    def test_reset_endpoint_returns_safe_owned_resetting_attempt(self) -> None:
        attempt_id = self._ready()

        missing = self.client.post(
            f"/v1/attempts/{attempt_id}/reset",
            headers={"Authorization": "Bearer " + self.token},
        )
        accepted = self.client.post(
            f"/v1/attempts/{attempt_id}/reset",
            headers={
                "Authorization": "Bearer " + self.token,
                "Idempotency-Key": "reset-attempt",
            },
        )

        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.json(), {"code": "INVALID_REQUEST"})
        self.assertEqual(accepted.status_code, 202)
        self.assertEqual(
            accepted.json(),
            {
                "attempt_id": attempt_id,
                "room_id": "room-1",
                "state": "RESETTING",
                "expires_at": self.deadline.isoformat(),
                "destroy_intent": False,
            },
        )
        self.assertNotIn("sandbox_id", accepted.json())
        self.assertNotIn("generation", accepted.json())

    def test_reset_endpoint_reduces_foreign_owner_denial(self) -> None:
        attempt_id = self._ready()

        response = self.client.post(
            f"/v1/attempts/{attempt_id}/reset",
            headers={
                "Authorization": "Bearer " + self.other_token,
                "Idempotency-Key": "foreign-reset",
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"code": "AUTHORIZATION_FAILED"})
        self.assertEqual(self.backend.inspect(self.user, attempt_id).state, "READY")

    def test_status_endpoint_reduces_authentication_and_ownership_failures(
        self,
    ) -> None:
        attempt_id = self._ready()

        unauthenticated = self.client.get(
            f"/v1/attempts/{attempt_id}/status",
            headers={"Authorization": "Bearer unknown-token"},
        )
        foreign = self.client.get(
            f"/v1/attempts/{attempt_id}/status",
            headers={"Authorization": "Bearer " + self.other_token},
        )

        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(unauthenticated.json(), {"code": "AUTHENTICATION_REQUIRED"})
        self.assertEqual(foreign.status_code, 403)
        self.assertEqual(foreign.json(), {"code": "AUTHORIZATION_FAILED"})


if __name__ == "__main__":
    unittest.main()
