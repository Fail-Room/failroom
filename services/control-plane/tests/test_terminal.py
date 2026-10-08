import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from failroom_sandbox.pty import PtyError, PtySession
from failroom_sandbox.terminal_gateway import GatewayAttachment
from failroom_state import (
    Action,
    AttachmentLease,
    BackendStore,
    CapabilityUse,
    ControlPlaneStore,
    Database,
    ResourceRef,
    ResourceState,
    Role,
    ServiceIdentity,
    UserIdentity,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from failroom_control_plane.terminal import (
    ControlPlaneTerminalService,
    TerminalError,
    TerminalRuntime,
)
from failroom_control_plane.websocket import WebSocketLimits, mount_terminal_route


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


class FailingCloseSession(RecordingSession):
    def close(self) -> None:
        super().close()
        raise OSError("close failed")


class StaticGateway:
    def __init__(self, attachment: GatewayAttachment) -> None:
        self.attachment = attachment

    def authorize_and_lease(
        self,
        token: str,
        *,
        gateway_session_id: str,
        idempotency_key: str,
        now,
    ) -> GatewayAttachment:
        return self.attachment


def _close_and_wait(socket) -> None:
    socket.send_json({"type": "close"})
    for _ in range(100):
        if socket.receive()["type"] == "websocket.close":
            return
    raise AssertionError("terminal close not observed")


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

    def service(
        self,
        runtime: TerminalRuntime,
        *,
        connection_limit: int = 4,
        session_limit: int = 1,
    ) -> ControlPlaneTerminalService:
        return ControlPlaneTerminalService(
            self.control,
            runtime,
            self.control_identity,
            lambda: self.now,
            connection_limit=connection_limit,
            session_limit=session_limit,
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

    def test_limits_must_be_positive_integers(self) -> None:
        for value in (0, -1, True, 1.0, "1", None):
            for field in ("connection_limit", "session_limit"):
                with self.subTest(field=field, value=value):
                    limits = {"connection_limit": 4, "session_limit": 1, field: value}
                    with self.assertRaises(TerminalError) as raised:
                        self.service(RecordingRuntime(), **limits)
                    self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")

    def test_session_limit_refuses_attach_until_a_session_closes(self) -> None:
        runtime = RecordingRuntime()
        service = self.service(runtime, session_limit=2)

        first = service.attach(self.lease)
        service.attach(self.lease)
        with self.assertRaises(TerminalError) as raised:
            service.attach(self.lease)
        self.assertEqual(raised.exception.code, "LIMIT_REACHED")
        self.assertEqual(len(runtime.calls), 2)

        first.close()
        first.close()
        service.attach(self.lease)
        with self.assertRaises(TerminalError):
            service.attach(self.lease)
        self.assertEqual(len(runtime.calls), 3)

    def test_failed_open_returns_its_session_slot(self) -> None:
        runtime = RecordingRuntime()
        runtime.error = PtyError("PTY_UNAVAILABLE")
        service = self.service(runtime)

        with self.assertRaises(TerminalError):
            service.attach(self.lease)
        runtime.error = None

        service.attach(self.lease)

    def test_failed_close_still_returns_its_session_slot(self) -> None:
        service = self.service(RecordingRuntime(FailingCloseSession()))

        attached = service.attach(self.lease)
        with self.assertRaises(OSError):
            attached.close()

        service.attach(self.lease)

    def test_connections_are_counted_per_sandbox_generation(self) -> None:
        service = self.service(RecordingRuntime(), connection_limit=2)
        newer = replace(
            self.lease,
            ref=replace(self.lease.ref, generation=self.lease.ref.generation + 1),
        )

        first = service.admit(self.lease)
        service.admit(self.lease)
        with self.assertRaises(TerminalError) as raised:
            service.admit(self.lease)
        self.assertEqual(raised.exception.code, "LIMIT_REACHED")
        service.admit(newer)

        first.release()
        first.release()
        service.admit(self.lease)
        with self.assertRaises(TerminalError):
            service.admit(self.lease)

    def test_admit_rejects_a_non_lease(self) -> None:
        with self.assertRaises(TerminalError) as raised:
            self.service(RecordingRuntime()).admit(self.lease.ref)

        self.assertEqual(raised.exception.code, "ATTACHMENT_DENIED")

    def test_concurrent_admissions_never_exceed_the_limit(self) -> None:
        service = self.service(RecordingRuntime(), connection_limit=3)
        barrier = threading.Barrier(16)
        results: list[str] = []
        lock = threading.Lock()

        def admit() -> None:
            barrier.wait()
            try:
                service.admit(self.lease)
                result = "admitted"
            except TerminalError as error:
                result = error.code
            with lock:
                results.append(result)

        threads = [threading.Thread(target=admit) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count("admitted"), 3)
        self.assertEqual(results.count("LIMIT_REACHED"), 13)

    def test_terminal_beyond_either_limit_is_closed_with_4429(self) -> None:
        authorize = {"type": "authorize", "capability": "capability"}
        consumed = CapabilityUse("a" * 64, self.lease.ref, 0, self.lease.expires_at)
        for connection_limit, session_limit in ((1, 4), (4, 1)):
            with self.subTest(connections=connection_limit, sessions=session_limit):
                runtime = RecordingRuntime()
                app = FastAPI()
                mount_terminal_route(
                    app,
                    gateway=StaticGateway(GatewayAttachment(consumed, self.lease)),
                    terminal=self.service(
                        runtime,
                        connection_limit=connection_limit,
                        session_limit=session_limit,
                    ),
                    limits=WebSocketLimits(
                        authorization_timeout_seconds=1,
                        max_frame_bytes=4096,
                        max_input_bytes=1024,
                        max_output_bytes=4096,
                        max_rows=100,
                        max_columns=200,
                        poll_interval_seconds=0.001,
                    ),
                    now=lambda: self.now,
                )
                client = TestClient(app)

                with client.websocket_connect("/v1/terminal") as first:
                    first.send_json(authorize)
                    self.assertEqual(first.receive_json(), {"type": "authorized"})
                    with client.websocket_connect("/v1/terminal") as second:
                        second.send_json(authorize)
                        with self.assertRaises(WebSocketDisconnect) as raised:
                            second.receive_json()
                    self.assertEqual(raised.exception.code, 4429)
                    _close_and_wait(first)
                with client.websocket_connect("/v1/terminal") as third:
                    third.send_json(authorize)
                    self.assertEqual(third.receive_json(), {"type": "authorized"})
                    _close_and_wait(third)

                self.assertEqual(len(runtime.calls), 2)


if __name__ == "__main__":
    unittest.main()
