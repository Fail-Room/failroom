import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import asynccontextmanager, closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from failroom_api import (
    BackendCapabilityAuthority,
    BearerCredential,
    BearerIdentityVerifier,
    BrowserSessionAuthority,
    CapabilityCodec,
)
from failroom_sandbox.scenario_runtime import ScenarioObservation
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

from failroom_control_plane.browser import LoopbackOrigin
from failroom_control_plane.entry import RoomEntryService
from failroom_control_plane.http import create_app
from failroom_control_plane.lifecycle import RoomLifecycleService
from failroom_control_plane.recovery import RecoveryVerificationService
from failroom_control_plane.reset import RoomResetService
from failroom_control_plane.room_scenarios import RoomScenarioRegistry


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


class RecordingRecoveryRuntime:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, binding, runtime_operation_id, room_id, container_id):
        del binding, runtime_operation_id, room_id, container_id
        self.calls += 1
        return ScenarioObservation("sha256:" + "b" * 64)


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
        self.user = UserIdentity("alice", frozenset({"room-1", "disk-full"}))
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
            rooms=RoomScenarioRegistry(),
        )
        self.reset = RoomResetService(self.backend, now=lambda: self.now)
        self.recovery_runtime = RecordingRecoveryRuntime()
        self.recovery = RecoveryVerificationService(
            self.backend,
            self.control,
            self.recovery_runtime,
            backend_identity=self.backend_identity,
            control_identity=ServiceIdentity(
                "recovery-control",
                Role.CONTROL_PLANE,
                frozenset({Action.INSPECT, Action.TRANSITION}),
            ),
            now=lambda: self.now,
        )
        self.token = "local-token-with-at-least-32-bytes-0001"
        self.other_token = "other-token-with-at-least-32-bytes-0001"
        self.verifier = BearerIdentityVerifier(
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
        self.origin = LoopbackOrigin(
            frozenset({"testserver"}), frozenset({"http://testserver"})
        )
        self.sessions = BrowserSessionAuthority(
            lifetime=timedelta(minutes=30), max_sessions=4, now=lambda: self.now
        )
        self.client = TestClient(
            create_app(
                authority=self.authority,
                verifier=self.verifier,
                origin=self.origin,
                now=lambda: self.now,
                sessions=self.sessions,
                lifecycle=self.lifecycle,
                entry=self.entry,
                reset=self.reset,
                recovery=self.recovery,
            )
        )

    def test_create_app_runs_injected_lifespan(self) -> None:
        events: list[str] = []

        @asynccontextmanager
        async def lifespan(_app):
            events.append("started")
            yield
            events.append("stopped")

        app = create_app(
            authority=self.authority,
            verifier=self.verifier,
            origin=self.origin,
            now=lambda: self.now,
            lifespan=lifespan,
        )

        with TestClient(app):
            self.assertEqual(events, ["started"])
        self.assertEqual(events, ["started", "stopped"])

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

    RUNTIME = {"origin": "http://testserver"}

    def _sign_in(self) -> str:
        response = self.client.post(
            "/v1/session",
            headers={"Authorization": "Bearer " + self.token, **self.RUNTIME},
        )
        self.assertEqual(response.status_code, 201)
        return self.client.cookies["failroom_session"]

    def test_a_host_that_does_not_name_the_runtime_is_refused(self) -> None:
        stranger = TestClient(self.client.app, base_url="http://attacker.example")

        for response in (
            stranger.get(
                "/v1/attempts/any/status",
                headers={"Authorization": "Bearer " + self.token},
            ),
            stranger.post(
                "/v1/session",
                headers={
                    "Authorization": "Bearer " + self.token,
                    "origin": "http://attacker.example",
                },
            ),
        ):
            self.assertEqual(
                (response.status_code, response.json()),
                (400, {"code": "HOST_NOT_ALLOWED"}),
            )
            self.assertNotIn("set-cookie", response.headers)

    def test_signing_in_sets_a_strict_http_only_session_cookie(self) -> None:
        response = self.client.post(
            "/v1/session",
            headers={"Authorization": "Bearer " + self.token, **self.RUNTIME},
        )

        self.assertEqual(response.status_code, 201)
        # The credential expires in ten minutes, before the 30-minute lifetime.
        self.assertEqual(
            response.json(),
            {"expires_at": (self.now + timedelta(minutes=10)).isoformat()},
        )
        cookie = response.headers["set-cookie"]
        self.assertRegex(cookie, r"^failroom_session=[A-Za-z0-9_-]{43}; ")
        for attribute in ("httponly", "max-age=600", "path=/v1", "samesite=strict"):
            self.assertIn(attribute, cookie.lower())
        self.assertNotIn(self.token, cookie)

    def test_signing_in_needs_the_runtime_origin_and_a_valid_credential(
        self,
    ) -> None:
        bearer = {"Authorization": "Bearer " + self.token}
        cases = (
            (bearer, 403, "ORIGIN_NOT_ALLOWED"),
            (
                {**bearer, "origin": "http://attacker.example"},
                403,
                "ORIGIN_NOT_ALLOWED",
            ),
            (
                {"Authorization": "Bearer " + "w" * 40, **self.RUNTIME},
                401,
                "AUTHENTICATION_REQUIRED",
            ),
            (dict(self.RUNTIME), 401, "AUTHENTICATION_REQUIRED"),
        )
        for headers, status, code in cases:
            with self.subTest(headers=headers):
                response = self.client.post("/v1/session", headers=headers)
                self.assertEqual(
                    (response.status_code, response.json()), (status, {"code": code})
                )
                self.assertNotIn("set-cookie", response.headers)

    def test_the_session_cookie_authenticates_room_requests(self) -> None:
        attempt_id = self._ready()
        self._sign_in()

        status = self.client.get(f"/v1/attempts/{attempt_id}/status")
        capability = self.client.post(
            f"/v1/attempts/{attempt_id}/terminal-capability", headers=self.RUNTIME
        )
        entered = self.client.post(
            "/v1/rooms/disk-full/attempts",
            headers={"Idempotency-Key": "enter-with-cookie", **self.RUNTIME},
        )

        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["attempt_id"], attempt_id)
        self.assertEqual(capability.status_code, 200)
        self.assertEqual(set(capability.json()), {"capability", "expires_at"})
        self.assertEqual(capability.headers["cache-control"], "no-store")
        self.assertEqual(entered.status_code, 201)
        self.assertEqual(len(self.provisioner.keys), 1)

    def test_a_cookie_request_that_changes_state_needs_the_runtime_origin(
        self,
    ) -> None:
        attempt_id = self._ready()
        self._sign_in()

        for headers in ({}, {"origin": "http://attacker.example"}, {"origin": "null"}):
            for path in (
                f"/v1/attempts/{attempt_id}/terminal-capability",
                f"/v1/attempts/{attempt_id}/leave",
                f"/v1/attempts/{attempt_id}/reset",
                "/v1/rooms/disk-full/attempts",
            ):
                with self.subTest(headers=headers, path=path):
                    response = self.client.post(
                        path, headers={"Idempotency-Key": uuid4().hex, **headers}
                    )
                    self.assertEqual(
                        (response.status_code, response.json()),
                        (403, {"code": "ORIGIN_NOT_ALLOWED"}),
                    )
        self.assertEqual(self.provisioner.keys, [])
        status = self.client.get(f"/v1/attempts/{attempt_id}/status")
        self.assertEqual(status.json()["state"], "READY")

    def test_signing_out_ends_the_session_and_clears_the_cookie(self) -> None:
        attempt_id = self._ready()
        token = self._sign_in()

        refused = self.client.delete("/v1/session")
        response = self.client.delete("/v1/session", headers=self.RUNTIME)
        replayed = self.client.get(
            f"/v1/attempts/{attempt_id}/status", cookies={"failroom_session": token}
        )

        self.assertEqual(
            (refused.status_code, refused.json()), (403, {"code": "ORIGIN_NOT_ALLOWED"})
        )
        self.assertEqual(response.status_code, 204)
        self.assertIn("max-age=0", response.headers["set-cookie"].lower())
        self.assertEqual(
            (replayed.status_code, replayed.json()),
            (401, {"code": "AUTHENTICATION_REQUIRED"}),
        )
        again = self.client.delete("/v1/session", headers=self.RUNTIME)
        self.assertEqual(again.status_code, 204)

    def test_a_bearer_header_takes_precedence_over_a_session_cookie(self) -> None:
        attempt_id = self._ready()
        self._sign_in()

        response = self.client.get(
            f"/v1/attempts/{attempt_id}/status",
            headers={"Authorization": "Bearer " + self.other_token},
        )

        self.assertEqual(response.status_code, 403)

    def test_api_responses_carry_hardening_headers(self) -> None:
        response = self.client.get(
            "/v1/attempts/missing/status",
            headers={"Authorization": "Bearer " + self.token},
        )

        for name, value in (
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("content-security-policy", "default-src 'none'; frame-ancestors 'none'"),
            ("cross-origin-resource-policy", "same-origin"),
        ):
            self.assertEqual(response.headers[name], value)

    def test_without_browser_sessions_there_is_no_cookie_sign_in(self) -> None:
        client = TestClient(
            create_app(
                authority=self.authority,
                verifier=self.verifier,
                origin=self.origin,
                now=lambda: self.now,
                lifecycle=self.lifecycle,
            )
        )
        attempt_id = self._ready()
        token = self._sign_in()

        self.assertEqual(
            client.post(
                "/v1/session",
                headers={"Authorization": "Bearer " + self.token, **self.RUNTIME},
            ).status_code,
            404,
        )
        self.assertEqual(
            client.get(
                f"/v1/attempts/{attempt_id}/status",
                cookies={"failroom_session": token},
            ).status_code,
            401,
        )

    def test_browser_sessions_need_a_credential_verifier(self) -> None:
        class IdentityOnly:
            def verify(self, authorization: str) -> UserIdentity:
                raise AssertionError("not called")

        for arguments in (
            {
                "verifier": IdentityOnly(),
                "origin": self.origin,
                "sessions": self.sessions,
            },
            {"verifier": self.verifier, "origin": {"testserver"}, "sessions": None},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                create_app(authority=self.authority, now=lambda: self.now, **arguments)

    def test_capability_endpoint_uses_verified_identity(self) -> None:
        attempt_id = self._ready()

        response = self.client.post(
            f"/v1/attempts/{attempt_id}/terminal-capability",
            headers={"Authorization": "Bearer " + self.token},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"capability", "expires_at"})
        self.assertNotIn("sandbox_id", response.json())

    def test_recovery_endpoint_requires_idempotency_and_returns_only_safe_status(
        self,
    ) -> None:
        attempt_id = self._ready()

        missing_key = self.client.post(
            f"/v1/attempts/{attempt_id}/verify-recovery",
            headers={"Authorization": "Bearer " + self.token},
        )
        response = self.client.post(
            f"/v1/attempts/{attempt_id}/verify-recovery",
            headers={
                "Authorization": "Bearer " + self.token,
                "Idempotency-Key": "verify-recovery",
            },
        )

        self.assertEqual(missing_key.status_code, 400)
        self.assertEqual(missing_key.json(), {"code": "INVALID_REQUEST"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "RESOLVED")
        self.assertNotIn("sandbox_id", response.json())
        self.assertEqual(self.recovery_runtime.calls, 1)

    def test_unknown_identity_returns_fixed_error(self) -> None:
        attempt_id = self._ready()

        response = self.client.post(
            f"/v1/attempts/{attempt_id}/terminal-capability",
            headers={"Authorization": "Bearer unknown-token-with-32-bytes-0001"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"code": "AUTHENTICATION_REQUIRED"})

    def _attempt_count(self) -> int:
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute("SELECT COUNT(*) FROM room_attempts").fetchone()
        return int(row[0])

    def test_enter_room_creates_a_safe_owned_attempt(self) -> None:
        response = self.client.post(
            "/v1/rooms/disk-full/attempts",
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
        self.assertEqual(response.json()["room_id"], "disk-full")
        self.assertEqual(response.json()["state"], "PROVISIONING")
        self.assertEqual(self.provisioner.keys, ["enter-room"])
        self.assertNotIn("sandbox_id", response.json())
        self.assertNotIn("generation", response.json())

    def test_enter_room_requires_an_idempotency_key(self) -> None:
        response = self.client.post(
            "/v1/rooms/disk-full/attempts",
            headers={"Authorization": "Bearer " + self.token},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"code": "INVALID_REQUEST"})
        self.assertEqual(self.provisioner.keys, [])

    def test_enter_room_reduces_provisioning_failure(self) -> None:
        self.provisioner.failure = RuntimeError("runtime detail must not escape")

        response = self.client.post(
            "/v1/rooms/disk-full/attempts",
            headers={
                "Authorization": "Bearer " + self.token,
                "Idempotency-Key": "failed-enter-room",
            },
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"code": "ENTRY_FAILED"})

    def test_enter_room_rejects_an_unreviewed_room_before_any_state(self) -> None:
        response = self.client.post(
            "/v1/rooms/room-1/attempts",
            headers={
                "Authorization": "Bearer " + self.token,
                "Idempotency-Key": "enter-unreviewed-room",
            },
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"code": "ROOM_UNAVAILABLE"})
        self.assertEqual(self.provisioner.keys, [])
        self.assertEqual(self._attempt_count(), 0)

    def test_enter_room_denies_a_reviewed_room_outside_the_users_scope(self) -> None:
        response = self.client.post(
            "/v1/rooms/disk-full/attempts",
            headers={
                "Authorization": "Bearer " + self.other_token,
                "Idempotency-Key": "enter-foreign-room",
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"code": "AUTHORIZATION_FAILED"})
        self.assertEqual(self.provisioner.keys, [])
        self.assertEqual(self._attempt_count(), 0)

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
