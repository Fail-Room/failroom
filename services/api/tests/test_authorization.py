import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

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

from failroom_api.authorization import (
    AuthorityError,
    BackendCapabilityAuthority,
    IssuedCapability,
)
from failroom_api.capability import CapabilityCodec


class BackendCapabilityAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.database = Database(self.path, busy_timeout_ms=5000)
        self.database.initialize()
        self.backend = BackendStore(self.database)
        self.control = ControlPlaneStore(self.database)
        self.codec = CapabilityCodec(
            b"k" * 32,
            max_lifetime=timedelta(seconds=60),
        )
        self.authority = BackendCapabilityAuthority(self.backend, self.codec)
        self.now = datetime(2026, 9, 9, 12, tzinfo=UTC)
        self.deadline = self.now + timedelta(minutes=5)
        self.user = UserIdentity("alice", frozenset({"disk-full"}))
        self.other_user = UserIdentity("bob", frozenset({"disk-full"}))
        self.backend_identity = ServiceIdentity(
            "backend", Role.BACKEND, frozenset({Action.CREATE, Action.PUBLISH})
        )
        self.control_identity = ServiceIdentity(
            "control", Role.CONTROL_PLANE, frozenset({Action.TRANSITION})
        )
        self.gateway_identity = ServiceIdentity(
            "gateway", Role.GATEWAY, frozenset({Action.CONSUME})
        )
        self.evidence = "sha256:" + "a" * 64

    def _create(self):
        return self.backend.create(
            self.user,
            "disk-full",
            key="create-" + uuid4().hex,
            expires_at=self.deadline,
            now=lambda: self.now,
        )

    def _ready(self):
        receipt = self._create()
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
        ready = self.control.transition(
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
        self.assertEqual(ready.state, "READY")
        return receipt

    def test_issue_returns_verified_capability_bound_to_owned_ready_attempt(self):
        receipt = self._ready()

        issued = self.authority.issue(
            self.user,
            receipt.attempt_id,
            now=lambda: self.now,
        )

        self.assertIsInstance(issued, IssuedCapability)
        claims = self.codec.verify(issued.token, now=lambda: self.now)
        self.assertEqual(claims.user_id, self.user.user_id)
        self.assertEqual(claims.ref, receipt.ref)
        self.assertEqual(claims.session_epoch, 0)
        self.assertEqual(issued.expires_at, claims.expires_at)
        self.assertLessEqual(issued.expires_at, self.deadline)

    def test_issue_rejects_wrong_owner_and_non_attachable_attempt(self):
        receipt = self._create()

        with self.assertRaises(AuthorityError) as caught:
            self.authority.issue(
                self.other_user,
                receipt.attempt_id,
                now=lambda: self.now,
            )
        self.assertEqual(caught.exception.code, "NOT_AUTHORIZED")

        with self.assertRaises(AuthorityError) as caught:
            self.authority.issue(
                self.user,
                receipt.attempt_id,
                now=lambda: self.now,
            )
        self.assertEqual(caught.exception.code, "ATTEMPT_UNAVAILABLE")

    def test_consume_verifies_and_atomically_consumes_capability(self):
        receipt = self._ready()
        issued = self.authority.issue(
            self.user, receipt.attempt_id, now=lambda: self.now
        )

        consumed = self.authority.introspect_and_consume(
            issued.token,
            self.gateway_identity,
            now=lambda: self.now,
        )

        self.assertEqual(consumed.ref, receipt.ref)
        self.assertEqual(consumed.session_epoch, 0)
        with self.assertRaises(AuthorityError) as caught:
            self.authority.introspect_and_consume(
                issued.token,
                self.gateway_identity,
                now=lambda: self.now,
            )
        self.assertEqual(caught.exception.code, "CAPABILITY_REPLAY")

    def test_consume_rechecks_current_authority_after_issue(self):
        receipt = self._ready()
        issued = self.authority.issue(
            self.user, receipt.attempt_id, now=lambda: self.now
        )
        self.backend.leave(
            self.user,
            receipt.ref,
            key="leave-" + uuid4().hex,
            now=lambda: self.now,
        )

        with self.assertRaises(AuthorityError) as caught:
            self.authority.introspect_and_consume(
                issued.token,
                self.gateway_identity,
                now=lambda: self.now,
            )
        self.assertEqual(caught.exception.code, "ATTEMPT_UNAVAILABLE")

    def test_concurrent_introspection_consumes_one_capability(self):
        receipt = self._ready()
        issued = self.authority.issue(
            self.user, receipt.attempt_id, now=lambda: self.now
        )

        def consume():
            try:
                return self.authority.introspect_and_consume(
                    issued.token,
                    self.gateway_identity,
                    now=lambda: self.now,
                )
            except AuthorityError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), (1, 2)))

        self.assertEqual(sum(isinstance(result, str) for result in results), 1)
        self.assertEqual(sum(result == "CAPABILITY_REPLAY" for result in results), 1)

    def test_invalid_token_is_reduced_to_fixed_authority_error(self):
        with self.assertRaises(AuthorityError) as caught:
            self.authority.introspect_and_consume(
                "not-a-capability",
                self.gateway_identity,
                now=lambda: self.now,
            )
        self.assertEqual(caught.exception.code, "CAPABILITY_INVALID")


if __name__ == "__main__":
    unittest.main()
