import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from failroom_sandbox.pty import PtyError, PtySession
from failroom_state import (
    Action,
    AttachmentLease,
    BackendStore,
    ControlPlaneStore,
    Database,
    ResourceRef,
    ResourceState,
    Role,
    ServiceIdentity,
    UserIdentity,
)

from failroom_control_plane.terminal import (
    ControlPlaneTerminalService,
    TerminalError,
    TerminalRuntime,
)


class RecordingSession:
    def __init__(self) -> None:
        self.closed = 0

    def read(self, maximum: int) -> bytes:
        return b""

    def write(self, data: bytes) -> None:
        return None

    def resize(self, rows: int, columns: int) -> None:
        return None

    def signal(self, value: int) -> None:
        return None

    def close(self) -> None:
        self.closed += 1


class RecordingRuntime:
    def __init__(self, session: PtySession | None = None) -> None:
        self.session = session or RecordingSession()
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.error: Exception | None = None

    def open(self, container_id: str, *, command: tuple[str, ...]) -> PtySession:
        self.calls.append((container_id, command))
        if self.error is not None:
            raise self.error
        return self.session


class TerminalServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 9, 9, tzinfo=UTC)
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
            "control",
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.TRANSITION}),
        )
        self.lease = self._ready_lease()

    def _ready_lease(self) -> AttachmentLease:
        receipt = self.backend.create(
            self.user,
            "room-1",
            key="create-" + uuid4().hex,
            expires_at=self.now + timedelta(minutes=5),
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
            container_id="c" * 64,
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
        return AttachmentLease(
            "lease-1",
            receipt.ref,
            "a" * 64,
            "b" * 64,
            0,
            self.now,
            self.now + timedelta(seconds=30),
            self.now,
        )

    def service(self, runtime: TerminalRuntime) -> ControlPlaneTerminalService:
        return ControlPlaneTerminalService(
            self.control,
            runtime,
            self.control_identity,
            lambda: self.now,
        )

    def test_attach_rejects_expired_lease_before_runtime_call(self) -> None:
        runtime = RecordingRuntime()
        expired = replace(self.lease, expires_at=self.now - timedelta(seconds=1))

        with self.assertRaises(TerminalError) as raised:
            self.service(runtime).attach(expired)

        self.assertEqual(raised.exception.code, "ATTACHMENT_DENIED")
        self.assertEqual(runtime.calls, [])

    def test_attach_uses_exact_container_binding_and_closes_session(self) -> None:
        session = RecordingSession()
        runtime = RecordingRuntime(session)

        attached = self.service(runtime).attach(self.lease)
        attached.close()
        attached.close()

        self.assertEqual(runtime.calls, [("c" * 64, ("/bin/bash",))])
        self.assertEqual(session.closed, 1)

    def test_attach_rejects_mismatched_resource_reference(self) -> None:
        runtime = RecordingRuntime()
        mismatched = replace(
            self.lease,
            ref=ResourceRef(
                self.lease.ref.attempt_id, "d" * 36, self.lease.ref.generation
            ),
        )

        with self.assertRaises(TerminalError) as raised:
            self.service(runtime).attach(mismatched)

        self.assertEqual(raised.exception.code, "ATTACHMENT_DENIED")
        self.assertEqual(runtime.calls, [])

    def test_attach_rejects_destroy_intent_before_runtime_call(self) -> None:
        runtime = RecordingRuntime()
        current = self.control.inspect(self.control_identity, self.lease.ref)
        self.control.transition(
            self.control_identity,
            self.lease.ref,
            expected_version=current.version,
            state=ResourceState.STOPPING,
            key="stopping-" + uuid4().hex,
            now=lambda: self.now,
        )

        with self.assertRaises(TerminalError) as raised:
            self.service(runtime).attach(self.lease)

        self.assertEqual(raised.exception.code, "ATTACHMENT_DENIED")
        self.assertEqual(runtime.calls, [])

    def test_runtime_failure_is_fixed_ptty_error(self) -> None:
        runtime = RecordingRuntime()
        runtime.error = PtyError("PTY_UNAVAILABLE")

        with self.assertRaises(TerminalError) as raised:
            self.service(runtime).attach(self.lease)

        self.assertEqual(raised.exception.code, "PTY_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
