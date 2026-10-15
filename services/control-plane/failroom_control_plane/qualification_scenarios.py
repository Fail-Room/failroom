"""Terminal scenario evidence for four qualification checks.

The scenarios drive the real terminal service with the Docker PTY runtime
against the collector's probe sandbox. A scratch SQLite database in a
temporary directory inside the collector's workspace binds one READY resource
to that sandbox, and the scenarios issue attachment leases for it directly:
they prove the terminal service's own limits and cleanup, while the gateway's
capability path is covered by its own tests. Nothing in the scratch database
outlives a run.
"""

import hashlib
import re
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import uuid4

from failroom_sandbox.docker_profile import StrictDockerProfile
from failroom_sandbox.fingerprints import configuration_digest
from failroom_sandbox.models import Check, Outcome
from failroom_sandbox.pty import PtyError
from failroom_sandbox.qualification_probe import (
    Judgement,
    ProbeOutputError,
    ProcessRecord,
    parse_process_list,
)
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

from .terminal import (
    ControlPlaneTerminalService,
    TerminalAdmission,
    TerminalError,
    TerminalRuntime,
    TerminalSession,
)
from .websocket import TerminalAttachmentProtocol

Clock = Callable[[], datetime]
ServiceFactory = Callable[[ControlPlaneStore], TerminalAttachmentProtocol]

# Scratch directories in the collector's workspace start with this prefix.
TERMINAL_PREFIX = "terminal-"
TERMINAL_CHECKS = (
    Check.TERMINAL_OUTPUT_LIMIT,
    Check.CONNECTION_LIMIT,
    Check.SESSION_LIMIT,
    Check.DISCONNECT_CLEANUP,
)
_ROOM = "disk-full"
_USER = UserIdentity("qualification", frozenset({_ROOM}))
_BACKEND = ServiceIdentity(
    "qualification-backend", Role.BACKEND, frozenset({Action.CREATE})
)
_CONTROL = ServiceIdentity(
    "qualification-control",
    Role.CONTROL_PLANE,
    frozenset({Action.INSPECT, Action.TRANSITION}),
)
_BINDING_LIFETIME = timedelta(minutes=10)
_LEASE_LIFETIME = timedelta(seconds=30)
_READ_BYTES = 65_536
_OUTPUT_SECONDS = 30.0
_MARKER_SECONDS = 10.0
_CLEANUP_SECONDS = 15.0
_POLL_SECONDS = 0.02
_SHELL_MARKER = re.compile(rb"\x1b\[32mFAILROOM_SHELL=([0-9]{1,10})\x1b\[0m")
_Evaluation = tuple[str, dict[str, object]]


@runtime_checkable
class ProcessLister(Protocol):
    def list_sandbox_processes(self, container_id: str) -> bytes: ...


class _Inconclusive(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _judge(check: Check, evaluate: Callable[[], _Evaluation]) -> Judgement:
    try:
        failure, facts = evaluate()
    except _Inconclusive as error:
        return Judgement(check, Outcome.UNVERIFIED, error.reason, MappingProxyType({}))
    except Exception:
        return Judgement(
            check, Outcome.UNVERIFIED, "SCENARIO_FAILED", MappingProxyType({})
        )
    if failure:
        return Judgement(check, Outcome.FAIL, failure, MappingProxyType(facts))
    return Judgement(check, Outcome.PASS, "", MappingProxyType(facts))


class TerminalScenarios:
    """Run the four terminal scenarios against one running sandbox."""

    def __init__(
        self,
        processes: ProcessLister,
        terminal: TerminalRuntime,
        profile: StrictDockerProfile,
        *,
        busy_timeout_ms: int,
        now: Clock,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        service_factory: ServiceFactory | None = None,
    ) -> None:
        self._processes = processes
        self._terminal = terminal
        self._profile = profile
        self._busy_timeout_ms = busy_timeout_ms
        self._now = now
        self._monotonic = monotonic
        self._sleep = sleep
        self._service_factory = service_factory or self._service

    def run(self, container_id: str, scratch: Path) -> dict[Check, Judgement]:
        with tempfile.TemporaryDirectory(
            prefix=TERMINAL_PREFIX, dir=scratch
        ) as directory:
            database = Database(
                Path(directory) / "terminal.sqlite3",
                busy_timeout_ms=self._busy_timeout_ms,
            )
            database.initialize()
            control = ControlPlaneStore(database)
            ref = self._bind(BackendStore(database), control, container_id)
            service = self._service_factory(control)
            scenarios: dict[Check, Callable[[], _Evaluation]] = {
                Check.TERMINAL_OUTPUT_LIMIT: lambda: self._output(service, ref),
                Check.CONNECTION_LIMIT: lambda: self._connections(service, ref),
                Check.SESSION_LIMIT: lambda: self._sessions(service, ref),
                Check.DISCONNECT_CLEANUP: lambda: self._disconnect(
                    service, ref, container_id
                ),
            }
            return {check: _judge(check, scenarios[check]) for check in TERMINAL_CHECKS}

    def _service(self, control: ControlPlaneStore) -> TerminalAttachmentProtocol:
        return ControlPlaneTerminalService(
            control,
            self._terminal,
            _CONTROL,
            self._now,
            connection_limit=self._profile.connection_limit,
            session_limit=self._profile.session_limit,
        )

    def _utc_now(self) -> datetime:
        return self._now().astimezone(UTC)

    def _bind(
        self, backend: BackendStore, control: ControlPlaneStore, container_id: str
    ) -> ResourceRef:
        """Record one READY resource for the probe sandbox in the scratch store."""
        receipt = backend.create(
            _USER,
            _ROOM,
            key=uuid4().hex,
            expires_at=self._utc_now() + _BINDING_LIFETIME,
            now=self._now,
        )
        accepted = control.accept(_BACKEND, receipt.ref, key=uuid4().hex, now=self._now)
        creating = control.transition(
            _CONTROL,
            receipt.ref,
            expected_version=accepted.version,
            state=ResourceState.CREATING,
            key=uuid4().hex,
            now=self._now,
        )
        starting = control.transition(
            _CONTROL,
            receipt.ref,
            expected_version=creating.version,
            state=ResourceState.STARTING,
            container_id=container_id,
            key=uuid4().hex,
            now=self._now,
        )
        control.transition(
            _CONTROL,
            receipt.ref,
            expected_version=starting.version,
            state=ResourceState.READY,
            evidence_digest=configuration_digest(
                {
                    "schema": "failroom.qualification-terminal-binding.v1",
                    "container_id": container_id,
                }
            ),
            key=uuid4().hex,
            now=self._now,
        )
        return receipt.ref

    def _lease(self, ref: ResourceRef) -> AttachmentLease:
        issued = self._utc_now()
        return AttachmentLease(
            uuid4().hex,
            ref,
            hashlib.sha256(uuid4().bytes).hexdigest(),
            hashlib.sha256(uuid4().bytes).hexdigest(),
            0,
            issued,
            issued + _LEASE_LIFETIME,
            issued,
        )

    def _attach(
        self, service: TerminalAttachmentProtocol, ref: ResourceRef
    ) -> TerminalSession:
        try:
            return service.attach(self._lease(ref))
        except TerminalError:
            raise _Inconclusive("ATTACH_FAILED") from None

    def _list(self, container_id: str) -> tuple[ProcessRecord, ...]:
        try:
            return parse_process_list(
                self._processes.list_sandbox_processes(container_id)
            )
        except ProbeOutputError:
            raise _Inconclusive("PROCESSES_UNREADABLE") from None

    def _output(
        self, service: TerminalAttachmentProtocol, ref: ResourceRef
    ) -> _Evaluation:
        limit = self._profile.terminal_output_limit_bytes
        session = self._attach(service, ref)
        received, stopped = 0, False
        try:
            session.write(f"head -c {2 * limit} /dev/zero | tr '\\0' x\n".encode())
            deadline = self._monotonic() + _OUTPUT_SECONDS
            while received <= limit and self._monotonic() < deadline:
                try:
                    data = session.read(min(_READ_BYTES, limit))
                except PtyError as error:
                    if error.code != "OUTPUT_LIMIT":
                        raise _Inconclusive("SESSION_FAILED") from None
                    stopped = True
                    break
                if data:
                    received += len(data)
                else:
                    self._sleep(_POLL_SECONDS)
        finally:
            session.close()
        facts: dict[str, object] = {
            "limit": limit,
            "received": received,
            "stopped": stopped,
        }
        if received > limit:
            return "OUTPUT_NOT_BOUNDED", facts
        if not stopped:
            raise _Inconclusive("OUTPUT_NOT_PRODUCED")
        return "", facts

    def _connections(
        self, service: TerminalAttachmentProtocol, ref: ResourceRef
    ) -> _Evaluation:
        limit = self._profile.connection_limit
        held: list[TerminalAdmission] = []

        def admit() -> str:
            try:
                held.append(service.admit(self._lease(ref)))
            except TerminalError as error:
                if error.code != "LIMIT_REACHED":
                    raise _Inconclusive("ADMISSION_FAILED") from None
                return error.code
            return ""

        try:
            return _limit_scenario(limit, admit, lambda: held.pop().release())
        finally:
            for admission in held:
                admission.release()

    def _sessions(
        self, service: TerminalAttachmentProtocol, ref: ResourceRef
    ) -> _Evaluation:
        limit = self._profile.session_limit
        held: list[TerminalSession] = []

        def attach() -> str:
            try:
                held.append(service.attach(self._lease(ref)))
            except TerminalError as error:
                if error.code != "LIMIT_REACHED":
                    raise _Inconclusive("ATTACH_FAILED") from None
                return error.code
            return ""

        try:
            return _limit_scenario(limit, attach, lambda: held.pop().close())
        finally:
            for session in held:
                session.close()

    def _disconnect(
        self,
        service: TerminalAttachmentProtocol,
        ref: ResourceRef,
        container_id: str,
    ) -> _Evaluation:
        session = self._attach(service, ref)
        closed = False
        remaining: list[ProcessRecord] = []
        try:
            session.write(
                b"sleep 1000 & (sleep 1001 &); "
                b"printf '\\033[32mFAILROOM_SHELL=%s\\033[0m\\n' $$\n"
            )
            shell = self._shell(session)
            members = [p for p in self._list(container_id) if p.session == shell]
            # The shell, its job and the job a subshell orphaned to PID 1.
            if len(members) < 3:
                raise _Inconclusive("SCENARIO_NOT_STARTED")
            session.close()
            closed = True
            deadline = self._monotonic() + _CLEANUP_SECONDS
            while True:
                remaining = [p for p in self._list(container_id) if p.session == shell]
                if not remaining or self._monotonic() >= deadline:
                    break
                self._sleep(_POLL_SECONDS * 10)
        finally:
            if not closed:
                session.close()
        facts: dict[str, object] = {
            "members": len(members),
            "remaining": [f"{p.pid}:{p.state}" for p in remaining],
        }
        return ("SESSION_PROCESSES_REMAIN" if remaining else ""), facts

    def _shell(self, session: TerminalSession) -> int:
        output = b""
        deadline = self._monotonic() + _MARKER_SECONDS
        while self._monotonic() < deadline and len(output) <= _READ_BYTES:
            try:
                data = session.read(
                    min(4096, self._profile.terminal_output_limit_bytes)
                )
            except PtyError:
                break
            output += data
            match = _SHELL_MARKER.search(output)
            if match:
                return int(match.group(1))
            if not data:
                self._sleep(_POLL_SECONDS)
        raise _Inconclusive("SHELL_NOT_REPORTED")


def _limit_scenario(
    limit: int, take: Callable[[], str], give_back: Callable[[], None]
) -> _Evaluation:
    """Take up to the limit, require the next take to be refused, then re-take."""
    facts: dict[str, object] = {"limit": limit}
    for taken in range(limit):
        if take():
            return "LIMIT_BELOW_PROFILE", {**facts, "taken": taken}
    if not take():
        return "LIMIT_NOT_ENFORCED", {**facts, "taken": limit + 1}
    give_back()
    if take():
        return "SLOT_NOT_RETURNED", facts
    return "", {**facts, "taken": limit, "refused": "LIMIT_REACHED"}
