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
    ControlPlaneStore,
    Database,
    ResourceState,
    Role,
    ServiceIdentity,
    UserIdentity,
)
from fastapi.testclient import TestClient

from failroom_control_plane.http import create_app


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
        self.backend_identity = ServiceIdentity(
            "backend", Role.BACKEND, frozenset({Action.CREATE, Action.PUBLISH})
        )
        self.control_identity = ServiceIdentity(
            "control", Role.CONTROL_PLANE, frozenset({Action.TRANSITION})
        )
        self.codec = CapabilityCodec(b"k" * 32, max_lifetime=timedelta(seconds=60))
        self.authority = BackendCapabilityAuthority(self.backend, self.codec)
        self.token = "local-token-with-at-least-32-bytes-0001"
        verifier = BearerIdentityVerifier(
            {
                hashlib.sha256(
                    self.token.encode("ascii")
                ).hexdigest(): BearerCredential(
                    self.user,
                    self.now + timedelta(minutes=10),
                )
            },
            now=lambda: self.now,
        )
        self.client = TestClient(
            create_app(
                authority=self.authority,
                verifier=verifier,
                now=lambda: self.now,
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


if __name__ == "__main__":
    unittest.main()
