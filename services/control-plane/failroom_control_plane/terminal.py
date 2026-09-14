"""Control-plane authority checks for one immediate terminal attachment."""

from collections.abc import Callable
from datetime import datetime
from typing import Protocol, runtime_checkable

from failroom_sandbox.pty import PtyError, PtySession
from failroom_state import (
    Action,
    AttachmentLease,
    ControlPlaneStore,
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


class _OwnedTerminalSession:
    def __init__(self, session: PtySession) -> None:
        self._session = session
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
        self._session.close()


class ControlPlaneTerminalService:
    """Bind a consumed attachment lease to the exact current PTY resource."""

    def __init__(
        self,
        control: ControlPlaneStore,
        runtime: TerminalRuntime,
        identity: ServiceIdentity,
        now: Clock,
    ) -> None:
        if (
            type(control) is not ControlPlaneStore
            or not isinstance(runtime, TerminalRuntime)
            or type(identity) is not ServiceIdentity
            or identity.role is not Role.CONTROL_PLANE
            or Action.INSPECT not in identity.scopes
            or not callable(now)
        ):
            raise TerminalError("INVALID_CONFIGURATION")
        self._control = control
        self._runtime = runtime
        self._identity = identity
        self._now = now

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
        try:
            session = self._runtime.open(resource.container_id, command=_COMMAND)
        except PtyError:
            raise TerminalError("PTY_UNAVAILABLE") from None
        except Exception:
            raise TerminalError("PTY_UNAVAILABLE") from None
        return _OwnedTerminalSession(session)
