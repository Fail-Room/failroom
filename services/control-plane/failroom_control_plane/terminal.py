"""Control-plane authority checks for one immediate terminal attachment."""

import threading
from collections.abc import Callable
from datetime import datetime
from typing import Protocol, runtime_checkable

from failroom_sandbox.pty import PtySession
from failroom_state import (
    Action,
    AttachmentLease,
    ControlPlaneStore,
    ResourceRef,
    ResourceState,
    Role,
    ServiceIdentity,
    StoreError,
)

Clock = Callable[[], datetime]
_COMMAND = ("/bin/bash",)


class TerminalError(Exception):
    """A fixed terminal attachment failure without resource details."""

    def __init__(self, code: str) -> None:
        if code not in {
            "ATTACHMENT_DENIED",
            "INVALID_CONFIGURATION",
            "LIMIT_REACHED",
            "PTY_UNAVAILABLE",
        }:
            code = "ATTACHMENT_DENIED"
        self.code = code
        super().__init__(code)


@runtime_checkable
class TerminalRuntime(Protocol):
    def open(self, container_id: str, *, command: tuple[str, ...]) -> PtySession: ...


class TerminalSession(Protocol):
    def read(self, maximum: int) -> bytes: ...

    def write(self, data: bytes) -> None: ...

    def resize(self, rows: int, columns: int) -> None: ...

    def signal(self, value: int) -> None: ...

    def close(self) -> None: ...


class TerminalAdmission(Protocol):
    def release(self) -> None: ...


class _Slot:
    """One counted holder; only its first release returns the slot."""

    def __init__(
        self, lock: threading.Lock, held: dict[ResourceRef, int], ref: ResourceRef
    ) -> None:
        self._lock = lock
        self._held = held
        self._ref = ref
        self._released = False

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
            remaining = self._held[self._ref] - 1
            if remaining:
                self._held[self._ref] = remaining
            else:
                del self._held[self._ref]


class _SandboxSlots:
    """Bound concurrent holders per exact sandbox generation in process memory."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._lock = threading.Lock()
        self._held: dict[ResourceRef, int] = {}

    def acquire(self, ref: ResourceRef) -> _Slot:
        with self._lock:
            held = self._held.get(ref, 0)
            if held >= self._limit:
                raise TerminalError("LIMIT_REACHED")
            self._held[ref] = held + 1
        return _Slot(self._lock, self._held, ref)


class _OwnedTerminalSession:
    def __init__(self, session: PtySession, slot: TerminalAdmission) -> None:
        self._session = session
        self._slot = slot
        self._closed = False

    def read(self, maximum: int) -> bytes:
        return self._session.read(maximum)

    def write(self, data: bytes) -> None:
        self._session.write(data)

    def resize(self, rows: int, columns: int) -> None:
        self._session.resize(rows, columns)

    def signal(self, value: int) -> None:
        self._session.signal(value)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._session.close()
        finally:
            self._slot.release()


class ControlPlaneTerminalService:
    """Bind a consumed attachment lease to the exact current PTY resource.

    Authorized connections and open sessions are counted per exact sandbox
    generation in this process's memory and bounded by the profile limits.
    """

    def __init__(
        self,
        control: ControlPlaneStore,
        runtime: TerminalRuntime,
        identity: ServiceIdentity,
        now: Clock,
        *,
        connection_limit: int,
        session_limit: int,
    ) -> None:
        if (
            type(control) is not ControlPlaneStore
            or not isinstance(runtime, TerminalRuntime)
            or type(identity) is not ServiceIdentity
            or identity.role is not Role.CONTROL_PLANE
            or Action.INSPECT not in identity.scopes
            or not callable(now)
            or type(connection_limit) is not int
            or connection_limit < 1
            or type(session_limit) is not int
            or session_limit < 1
        ):
            raise TerminalError("INVALID_CONFIGURATION")
        self._control = control
        self._runtime = runtime
        self._identity = identity
        self._now = now
        self._connections = _SandboxSlots(connection_limit)
        self._sessions = _SandboxSlots(session_limit)

    def admit(self, lease: AttachmentLease) -> TerminalAdmission:
        """Count one authorized connection against its sandbox generation."""
        if type(lease) is not AttachmentLease or type(lease.ref) is not ResourceRef:
            raise TerminalError("ATTACHMENT_DENIED")
        return self._connections.acquire(lease.ref)

    def attach(self, lease: AttachmentLease) -> TerminalSession:
        if type(lease) is not AttachmentLease:
            raise TerminalError("ATTACHMENT_DENIED")
        try:
            current = self._now()
            if type(current) is not datetime or current.tzinfo is None:
                raise TerminalError("ATTACHMENT_DENIED")
            if lease.expires_at <= current:
                raise TerminalError("ATTACHMENT_DENIED")
            resource = self._control.inspect(self._identity, lease.ref)
            if (
                resource.ref != lease.ref
                or current >= resource.expires_at
                or resource.state
                not in (ResourceState.READY.value, ResourceState.RUNNING.value)
                or resource.expiry_intent
                or resource.destroy_intent
                or type(resource.container_id) is not str
                or not resource.container_id
            ):
                raise TerminalError("ATTACHMENT_DENIED")
        except TerminalError:
            raise
        except (StoreError, TypeError, ValueError):
            raise TerminalError("ATTACHMENT_DENIED") from None
        slot = self._sessions.acquire(lease.ref)
        try:
            session = self._runtime.open(resource.container_id, command=_COMMAND)
        except Exception:
            slot.release()
            raise TerminalError("PTY_UNAVAILABLE") from None
        return _OwnedTerminalSession(session, slot)
