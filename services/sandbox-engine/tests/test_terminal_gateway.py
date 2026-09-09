import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from failroom_api import BackendCapabilityAuthority, CapabilityCodec
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

from failroom_sandbox.terminal_gateway import (
    GatewayAttachment,
    GatewayError,
    TerminalGatewayAuthority,
)


class TerminalGatewayAuthorityTests(unittest.TestCase):
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
        self.gateway = TerminalGatewayAuthority(
            self.authority,
            self.control,
            ServiceIdentity(
                "gateway",
                Role.GATEWAY,
                frozenset({Action.CONSUME, Action.ATTACH}),
            ),
            lease_duration=timedelta(seconds=10),
        )
        self.now = datetime(2026, 9, 9, 12, tzinfo=UTC)
        self.deadline = self.now + timedelta(minutes=5)
        self.user = UserIdentity("alice", frozenset({"disk-full"}))
        self.backend_identity = ServiceIdentity(
            "backend", Role.BACKEND, frozenset({Action.CREATE, Action.PUBLISH})
        )
        self.control_identity = ServiceIdentity(
            "control", Role.CONTROL_PLANE, frozenset({Action.TRANSITION})
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

    def test_authorize_consumes_capability_and_grants_bound_lease(self):
        receipt = self._ready()
        issued = self.authority.issue(
            self.user, receipt.attempt_id, now=lambda: self.now
        )

        attachment = self.gateway.authorize_and_lease(
            issued.token,
            gateway_session_id="gateway-session-1",
            idempotency_key="lease-" + uuid4().hex,
            now=lambda: self.now,
        )

        self.assertIsInstance(attachment, GatewayAttachment)
        self.assertEqual(attachment.consumed.ref, receipt.ref)
        self.assertEqual(
            attachment.lease.jti_hash,
            attachment.consumed.jti_hash,
        )
        self.assertEqual(attachment.lease.ref, receipt.ref)
        self.assertLessEqual(attachment.lease.expires_at, issued.expires_at)

    def test_invalid_capability_returns_fixed_error_without_token(self):
        secret = "raw-capability-value"
        with self.assertRaises(GatewayError) as caught:
            self.gateway.authorize_and_lease(
                secret,
                gateway_session_id="gateway-session-1",
                idempotency_key="lease-invalid",
                now=lambda: self.now,
            )
        self.assertEqual(caught.exception.code, "CAPABILITY_INVALID")
        self.assertNotIn(secret, str(caught.exception))

    def test_replay_is_rejected_after_lease_consumption(self):
        receipt = self._ready()
        issued = self.authority.issue(
            self.user, receipt.attempt_id, now=lambda: self.now
        )
        self.gateway.authorize_and_lease(
            issued.token,
            gateway_session_id="gateway-session-1",
            idempotency_key="lease-first",
            now=lambda: self.now,
        )

        with self.assertRaises(GatewayError) as caught:
            self.gateway.authorize_and_lease(
                issued.token,
                gateway_session_id="gateway-session-2",
                idempotency_key="lease-second",
                now=lambda: self.now,
            )
        self.assertEqual(caught.exception.code, "CAPABILITY_REPLAY")

    def test_current_authority_is_rechecked_before_lease(self):
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

        with self.assertRaises(GatewayError) as caught:
            self.gateway.authorize_and_lease(
                issued.token,
                gateway_session_id="gateway-session-1",
                idempotency_key="lease-after-leave",
                now=lambda: self.now,
            )
        self.assertEqual(caught.exception.code, "ATTEMPT_UNAVAILABLE")

    def test_concurrent_gateway_open_consumes_one_capability(self):
        receipt = self._ready()
        issued = self.authority.issue(
            self.user, receipt.attempt_id, now=lambda: self.now
        )

        def open_session(index: int):
            try:
                return self.gateway.authorize_and_lease(
                    issued.token,
                    gateway_session_id=f"gateway-session-{index}",
                    idempotency_key=f"lease-{index}",
                    now=lambda: self.now,
                )
            except GatewayError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(open_session, (1, 2)))

        self.assertEqual(
            sum(isinstance(result, GatewayAttachment) for result in results),
            1,
        )
        self.assertEqual(
            sum(result == "CAPABILITY_REPLAY" for result in results),
            1,
        )


if __name__ == "__main__":
    unittest.main()
