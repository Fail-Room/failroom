import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.scenario_runtime import ScenarioObservation
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

from failroom_control_plane.recovery import (
    RecoveryError,
    RecoveryVerificationService,
)


class RecordingRecoveryRuntime:
    def __init__(self, observation: ScenarioObservation | Exception) -> None:
        self.observation = observation
        self.calls: list[tuple[object, ...]] = []

    def verify(self, binding, runtime_operation_id, room_id, container_id):
        self.calls.append((binding, runtime_operation_id, room_id, container_id))
        if isinstance(self.observation, Exception):
            raise self.observation
        return self.observation


class RecoveryVerificationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 9, 17, tzinfo=UTC)
        database = Database(Path(self.temp.name) / "state.sqlite3", busy_timeout_ms=5000)
        database.initialize()
        self.backend = BackendStore(database)
        self.control = ControlPlaneStore(database)
        self.user = UserIdentity("alice", frozenset({"disk-full"}))
        self.other_user = UserIdentity("bob", frozenset({"disk-full"}))
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

    def _ready(self):
        attempt = self.backend.create(
            self.user,
            "disk-full",
            key="create",
            expires_at=self.now + timedelta(minutes=5),
            now=lambda: self.now,
        )
        accepted = self.control.accept(
            self.backend_identity, attempt.ref, key="accept", now=lambda: self.now
        )
        creating = self.control.transition(
            self.control_identity,
            attempt.ref,
            expected_version=accepted.version,
            state=ResourceState.CREATING,
            key="creating",
            now=lambda: self.now,
        )
        starting = self.control.transition(
            self.control_identity,
            attempt.ref,
            expected_version=creating.version,
            state=ResourceState.STARTING,
            container_id="container-1",
            key="starting",
            now=lambda: self.now,
        )
        self.control.transition(
            self.control_identity,
            attempt.ref,
            expected_version=starting.version,
            state=ResourceState.READY,
            evidence_digest="sha256:" + "a" * 64,
            key="ready",
            now=lambda: self.now,
        )
        self.backend.publish_ready(
            self.backend_identity,
            attempt.ref,
            expected_version=0,
            key="publish-ready",
            now=lambda: self.now,
        )
        return self.backend.inspect(self.user, attempt.attempt_id)

    def _service(self, runtime):
        return RecoveryVerificationService(
            self.backend,
            self.control,
            runtime,
            backend_identity=self.backend_identity,
            control_identity=self.control_identity,
            now=lambda: self.now,
        )

    def test_owned_request_resolves_only_after_trusted_recovery_evidence(self):
        attempt = self._ready()
        runtime = RecordingRecoveryRuntime(
            ScenarioObservation("sha256:" + "b" * 64)
        )

        status = self._service(runtime).verify(
            self.user, attempt.attempt_id, key="verify-recovery"
        )

        self.assertEqual(status.state, "RESOLVED")
        self.assertEqual(len(runtime.calls), 1)
        self.assertEqual(runtime.calls[0][0].attempt_id, attempt.attempt_id)
        resource = self.control.inspect(self.control_identity, attempt.ref)
        self.assertEqual(resource.state, "RESOLVED")
        self.assertNotEqual(resource.evidence_digest, "sha256:" + "b" * 64)

    def test_foreign_request_never_invokes_trusted_runtime(self):
        attempt = self._ready()
        runtime = RecordingRecoveryRuntime(
            ScenarioObservation("sha256:" + "b" * 64)
        )

        with self.assertRaises(RecoveryError) as raised:
            self._service(runtime).verify(
                self.other_user, attempt.attempt_id, key="foreign-request"
            )

        self.assertEqual(raised.exception.code, "NOT_AUTHORIZED")
        self.assertEqual(runtime.calls, [])

    def test_unverified_runtime_never_records_resolved(self):
        attempt = self._ready()
        runtime = RecordingRecoveryRuntime(DockerError("PROFILE_UNVERIFIED"))

        with self.assertRaises(RecoveryError) as raised:
            self._service(runtime).verify(
                self.user, attempt.attempt_id, key="recovery-not-verified"
            )

        self.assertEqual(raised.exception.code, "RECOVERY_NOT_VERIFIED")
        self.assertEqual(
            self.backend.inspect(self.user, attempt.attempt_id).state, "RUNNING"
        )
        self.assertEqual(
            self.control.inspect(self.control_identity, attempt.ref).state,
            ResourceState.RUNNING,
        )
        self.assertEqual(len(runtime.calls), 1)

    def test_resolved_retry_with_same_key_does_not_reinvoke_runtime(self):
        attempt = self._ready()
        runtime = RecordingRecoveryRuntime(
            ScenarioObservation("sha256:" + "b" * 64)
        )
        service = self._service(runtime)

        first = service.verify(self.user, attempt.attempt_id, key="recovery-retry")
        second = service.verify(self.user, attempt.attempt_id, key="recovery-retry")

        self.assertEqual(first.state, "RESOLVED")
        self.assertEqual(second.state, "RESOLVED")
        self.assertEqual(len(runtime.calls), 1)


if __name__ == "__main__":
    unittest.main()
