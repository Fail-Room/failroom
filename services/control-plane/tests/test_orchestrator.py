import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.docker_lifecycle import (
    ContainerObservation,
    CreatedContainer,
)
from failroom_sandbox.docker_profile import DockerBinding
from failroom_state import (
    Action,
    BackendStore,
    ControlPlaneStore,
    Database,
    Receipt,
    ResourceState,
    Role,
    ServiceIdentity,
    UserIdentity,
)

from failroom_control_plane.orchestrator import LifecycleError, LifecycleOrchestrator


class FakeSession:
    def __init__(self, runtime: "FakeRuntime") -> None:
        self.runtime = runtime

    def create_verified(self) -> CreatedContainer:
        self.runtime.calls.append("create:CREATING")
        if self.runtime.create_error is not None:
            error = self.runtime.create_error
            self.runtime.create_error = None
            raise error
        return CreatedContainer(f"{len(self.runtime.bindings):064x}", False)

    def start_verified(self, created: CreatedContainer) -> ContainerObservation:
        self.runtime.calls.append("start:STARTING")
        if self.runtime.start_error is not None:
            error = self.runtime.start_error
            self.runtime.start_error = None
            raise error
        return ContainerObservation(created.container_id, True, "sha256:" + "a" * 64)


class FakeDiskFullSession(FakeSession):
    def bootstrap_disk_full(
        self, created: CreatedContainer, started: ContainerObservation
    ) -> ContainerObservation:
        self.runtime.calls.append("bootstrap:STARTING")
        if self.runtime.bootstrap_error is not None:
            error = self.runtime.bootstrap_error
            self.runtime.bootstrap_error = None
            raise error
        return ContainerObservation(created.container_id, True, "sha256:" + "b" * 64)


class FakeRuntime:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.create_error: DockerError | None = None
        self.start_error: DockerError | None = None
        self.bootstrap_error: DockerError | None = None
        self.bootstrap_enabled = False
        self.bindings: list[DockerBinding] = []
        self.room_ids: list[str] = []

    @contextmanager
    def open(self, binding: DockerBinding, runtime_operation_id: str, room_id: str):
        self.bindings.append(binding)
        self.room_ids.append(room_id)
        self.calls.append("open")
        try:
            yield FakeDiskFullSession(self) if self.bootstrap_enabled else FakeSession(self)
        finally:
            self.calls.append("close")


class OrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.db = Database(self.path, busy_timeout_ms=5000)
        self.db.initialize()
        self.backend = BackendStore(self.db)
        self.control = ControlPlaneStore(self.db)
        self.runtime = FakeRuntime()
        self.orchestrator = LifecycleOrchestrator(
            self.backend, self.control, self.runtime
        )
        self.now = datetime(2026, 9, 8, tzinfo=UTC)
        self.deadline = self.now + timedelta(minutes=30)
        self.user = UserIdentity("alice", frozenset({"disk-full"}))
        self.backend_identity = ServiceIdentity(
            "backend", Role.BACKEND, frozenset({Action.CREATE, Action.PUBLISH})
        )
        self.control_identity = ServiceIdentity(
            "control",
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.TRANSITION}),
        )

    def create_attempt(self, key: str = "create") -> Receipt:
        return self.backend.create(
            self.user,
            "disk-full",
            key=key,
            expires_at=self.deadline,
            now=lambda: self.now,
        )

    def resource(self, receipt: Receipt):
        return self.control.inspect(self.control_identity, receipt.ref)

    def attempt(self, receipt: Receipt):
        return self.backend.inspect(self.user, receipt.attempt_id)

    def provision(self, receipt: Receipt):
        return self.orchestrator.provision(
            receipt,
            backend_identity=self.backend_identity,
            control_identity=self.control_identity,
            key="root-create",
            now=lambda: self.now,
        )

    def test_provision_persists_creating_and_starting_before_runtime_effects(
        self,
    ) -> None:
        receipt = self.create_attempt()
        self.provision(receipt)
        self.assertEqual(
            self.runtime.calls,
            ["open", "create:CREATING", "start:STARTING", "close"],
        )
        self.assertEqual(self.resource(receipt).state, ResourceState.READY)
        self.assertEqual(self.attempt(receipt).state, "READY")

    def test_optional_disk_full_bootstrap_runs_before_ready_publication(self):
        self.runtime.bootstrap_enabled = True
        receipt = self.create_attempt()

        self.provision(receipt)

        self.assertEqual(
            self.runtime.calls,
            [
                "open",
                "create:CREATING",
                "start:STARTING",
                "bootstrap:STARTING",
                "close",
            ],
        )
        self.assertEqual(self.resource(receipt).state, ResourceState.READY)
        self.assertEqual(self.attempt(receipt).state, "READY")
        self.assertEqual(self.runtime.room_ids, ["disk-full"])

    def test_bootstrap_failure_marks_failed_and_prevents_ready_publication(self):
        self.runtime.bootstrap_enabled = True
        self.runtime.bootstrap_error = DockerError("PROFILE_UNVERIFIED")
        receipt = self.create_attempt()

        with self.assertRaises(LifecycleError) as caught:
            self.provision(receipt)

        self.assertEqual(caught.exception.code, "START_FAILED")
        self.assertEqual(self.resource(receipt).state, ResourceState.FAILED)
        self.assertTrue(self.resource(receipt).destroy_intent)
        self.assertNotEqual(self.attempt(receipt).state, "READY")
        self.assertEqual(
            self.runtime.calls,
            [
                "open",
                "create:CREATING",
                "start:STARTING",
                "bootstrap:STARTING",
                "close",
            ],
        )

    def test_create_timeout_keeps_cleanup_intent_and_never_publishes_ready(self):
        self.runtime.create_error = DockerError("RUNTIME_UNAVAILABLE")
        receipt = self.create_attempt()
        with self.assertRaises(LifecycleError) as caught:
            self.provision(receipt)
        self.assertEqual(caught.exception.code, "RUNTIME_UNAVAILABLE")
        self.assertTrue(self.resource(receipt).destroy_intent)
        self.assertNotEqual(self.attempt(receipt).state, "READY")
        self.assertEqual(self.runtime.calls, ["open", "create:CREATING", "close"])

    def test_duplicate_root_key_reuses_existing_ready_resource(self) -> None:
        receipt = self.create_attempt()
        self.provision(receipt)
        calls = list(self.runtime.calls)
        self.provision(receipt)
        self.assertEqual(self.runtime.calls, calls)
        self.assertEqual(self.resource(receipt).state, ResourceState.READY)

    def test_profile_failure_maps_to_create_failed_without_publish(self) -> None:
        self.runtime.create_error = DockerError("PROFILE_UNVERIFIED")
        receipt = self.create_attempt()
        with self.assertRaises(LifecycleError) as caught:
            self.provision(receipt)
        self.assertEqual(caught.exception.code, "CREATE_FAILED")
        self.assertEqual(self.resource(receipt).state, ResourceState.FAILED)

    def test_ownership_failure_during_start_maps_to_start_failed(self) -> None:
        self.runtime.start_error = DockerError("OWNERSHIP_MISMATCH")
        receipt = self.create_attempt()
        with self.assertRaises(LifecycleError) as caught:
            self.provision(receipt)
        self.assertEqual(caught.exception.code, "START_FAILED")
        self.assertEqual(self.resource(receipt).state, ResourceState.FAILED)
        self.assertNotEqual(self.attempt(receipt).state, "READY")

    def test_reset_provisions_exact_candidate_after_old_resource_destruction(self):
        receipt = self.create_attempt()
        self.provision(receipt)
        attempt = self.attempt(receipt)
        resource = self.resource(receipt)
        candidate = self.backend.begin_reset(
            self.user,
            attempt.ref,
            key="begin-reset",
            now=lambda: self.now,
        )
        stopping = self.control.transition(
            self.control_identity,
            attempt.ref,
            expected_version=resource.version,
            state=ResourceState.STOPPING,
            key="stop-reset-old",
            now=lambda: self.now,
        )
        self.control.transition(
            self.control_identity,
            attempt.ref,
            expected_version=stopping.version,
            state=ResourceState.DESTROYED,
            key="destroy-reset-old",
            now=lambda: self.now,
            evidence_digest="sha256:" + "b" * 64,
        )

        self.orchestrator.provision(
            candidate,
            backend_identity=self.backend_identity,
            control_identity=self.control_identity,
            key="root-reset",
            now=lambda: self.now,
        )

        current = self.attempt(receipt)
        self.assertEqual(current.state, "READY")
        self.assertEqual(current.active_ref, candidate.ref)
        self.assertIsNone(current.candidate_ref)
        self.assertEqual(self.resource(candidate).state, ResourceState.READY)
        self.assertEqual(self.runtime.bindings[-1].sandbox_id, candidate.ref.sandbox_id)

    def test_reset_provisioning_failure_marks_attempt_failed(self) -> None:
        receipt = self.create_attempt()
        self.provision(receipt)
        attempt = self.attempt(receipt)
        resource = self.resource(receipt)
        candidate = self.backend.begin_reset(
            self.user,
            attempt.ref,
            key="begin-failing-reset",
            now=lambda: self.now,
        )
        stopping = self.control.transition(
            self.control_identity,
            attempt.ref,
            expected_version=resource.version,
            state=ResourceState.STOPPING,
            key="stop-failing-reset-old",
            now=lambda: self.now,
        )
        self.control.transition(
            self.control_identity,
            attempt.ref,
            expected_version=stopping.version,
            state=ResourceState.DESTROYED,
            key="destroy-failing-reset-old",
            now=lambda: self.now,
            evidence_digest="sha256:" + "b" * 64,
        )
        self.runtime.create_error = DockerError("RUNTIME_UNAVAILABLE")

        with self.assertRaises(LifecycleError) as caught:
            self.orchestrator.provision(
                candidate,
                backend_identity=self.backend_identity,
                control_identity=self.control_identity,
                key="root-failing-reset",
                now=lambda: self.now,
            )

        current = self.attempt(receipt)
        self.assertEqual(caught.exception.code, "RUNTIME_UNAVAILABLE")
        self.assertEqual(current.state, "FAILED")
        self.assertTrue(current.reset_intent)
        self.assertEqual(current.candidate_ref, candidate.ref)
        self.assertTrue(self.resource(candidate).destroy_intent)


if __name__ == "__main__":
    unittest.main()
