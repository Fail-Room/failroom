import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
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


class AttachmentLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.database = Database(self.path, busy_timeout_ms=5000)
        self.database.initialize()
        self.backend = BackendStore(self.database)
        self.control = ControlPlaneStore(self.database)
        self.now = datetime(2026, 9, 9, tzinfo=UTC)
        self.deadline = self.now + timedelta(minutes=5)
        self.user = UserIdentity("alice", frozenset({"disk-full"}))
        self.backend_identity = ServiceIdentity(
            "backend", Role.BACKEND, frozenset({Action.CREATE, Action.PUBLISH})
        )
        self.control_identity = ServiceIdentity(
            "control", Role.CONTROL_PLANE, frozenset({Action.TRANSITION})
        )
        self.gateway_identity = ServiceIdentity(
            "gateway", Role.GATEWAY, frozenset({Action.CONSUME, Action.ATTACH})
        )
        self.evidence = "sha256:" + "a" * 64

    def _ready(self):
        receipt = self.backend.create(
            self.user,
            "disk-full",
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
            evidence_digest=self.evidence,
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
        return receipt

    def _consumed(self, receipt, *, expires_in: timedelta = timedelta(seconds=30)):
        claims = CapabilityClaims(
            uuid4().hex,
            self.user.user_id,
            receipt.ref,
            0,
            self.now + expires_in,
            "terminal:attach",
        )
        consumed = self.backend.consume(
            self.gateway_identity, claims, now=lambda: self.now
        )
        return claims, consumed

    def _grant(self, receipt, consumed, *, session="gateway-session-1", key=None):
        return self.control.grant_attachment_lease(
            self.gateway_identity,
            receipt.ref,
            consumed=consumed,
            gateway_session_id=session,
            lease_duration=timedelta(seconds=10),
            key=key or "lease-" + uuid4().hex,
            now=lambda: self.now,
        )

    def test_grant_binds_consumed_capability_and_hashes_private_values(self):
        receipt = self._ready()
        claims, consumed = self._consumed(receipt)

        lease = self._grant(receipt, consumed)

        self.assertEqual(lease.ref, receipt.ref)
        self.assertEqual(lease.jti_hash, consumed.jti_hash)
        self.assertEqual(lease.session_epoch, 0)
        self.assertLessEqual(lease.expires_at, claims.expires_at)
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                "SELECT jti_hash,gateway_session_hash,consumed_at FROM "
                "terminal_attachment_leases"
            ).fetchone()
        self.assertEqual(row[0], consumed.jti_hash)
        self.assertNotEqual(row[0], claims.jti)
        self.assertNotEqual(row[1], "gateway-session-1")
        self.assertIsNotNone(row[2])

    def test_same_consumed_capability_cannot_attach_to_another_session(self):
        receipt = self._ready()
        _, consumed = self._consumed(receipt)
        self._grant(receipt, consumed)

        with self.assertRaises(StoreError) as caught:
            self._grant(receipt, consumed, session="different-session")
        self.assertEqual(caught.exception.code, "CAPABILITY_REPLAY")

    def test_grant_rejects_expired_capability_and_destroy_intent(self):
        receipt = self._ready()
        _, consumed = self._consumed(receipt, expires_in=timedelta(seconds=1))

        with self.assertRaises(StoreError) as caught:
            self.control.grant_attachment_lease(
                self.gateway_identity,
                receipt.ref,
                consumed=consumed,
                gateway_session_id="expired-session",
                lease_duration=timedelta(seconds=10),
                key="expired-lease",
                now=lambda: self.now + timedelta(seconds=2),
            )
        self.assertEqual(caught.exception.code, "CAPABILITY_INVALID")

        _, second_consumed = self._consumed(receipt)
        self.backend.leave(
            self.user,
            receipt.ref,
            key="leave-" + uuid4().hex,
            now=lambda: self.now,
        )
        with self.assertRaises(StoreError) as caught:
            self._grant(receipt, second_consumed, session="after-leave")
        self.assertEqual(caught.exception.code, "ATTEMPT_UNAVAILABLE")

    def test_concurrent_grants_consume_one_jti(self):
        receipt = self._ready()
        _, consumed = self._consumed(receipt)

        def grant(index: int):
            try:
                return self._grant(
                    receipt,
                    consumed,
                    session=f"concurrent-{index}",
                    key=f"concurrent-key-{index}",
                )
            except StoreError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(grant, (1, 2)))

        self.assertEqual(sum(result != "CAPABILITY_REPLAY" for result in results), 1)
        self.assertEqual(sum(result == "CAPABILITY_REPLAY" for result in results), 1)


if __name__ == "__main__":
    unittest.main()
