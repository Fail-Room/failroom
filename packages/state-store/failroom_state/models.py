"""Trusted in-process contexts, not HTTP authentication or signed credentials."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

type Clock = Callable[[], datetime]


class StoreError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Role(StrEnum):
    BACKEND = "backend"
    GATEWAY = "gateway"
    CONTROL_PLANE = "control-plane"


class Action(StrEnum):
    CREATE = "create"
    INSPECT = "inspect"
    TRANSITION = "transition"
    PUBLISH = "publish"
    CONSUME = "consume"
    ATTACH = "attach"
    EXPIRE = "expire"
    RECONCILE = "reconcile"


class ResourceState(StrEnum):
    REQUESTED = "REQUESTED"
    CREATING = "CREATING"
    STARTING = "STARTING"
    READY = "READY"
    RUNNING = "RUNNING"
    RESOLVED = "RESOLVED"
    STOPPING = "STOPPING"
    FAILED = "FAILED"
    DESTROYED = "DESTROYED"


@dataclass(frozen=True)
class UserIdentity:
    user_id: str
    authorized_room_ids: frozenset[str]


@dataclass(frozen=True)
class ServiceIdentity:
    service_id: str
    role: Role
    scopes: frozenset[Action]


@dataclass(frozen=True)
class ResourceRef:
    attempt_id: str
    sandbox_id: str
    generation: int


@dataclass(frozen=True)
class Receipt:
    operation_id: str
    ref: ResourceRef
    state: str
    version: int

    @property
    def attempt_id(self) -> str:
        return self.ref.attempt_id


@dataclass(frozen=True)
class Attempt:
    ref: ResourceRef
    room_id: str
    state: str
    active_sandbox_id: str | None
    active_generation: int | None
    candidate_sandbox_id: str | None
    candidate_generation: int | None
    session_epoch: int
    version: int
    expires_at: datetime
    provisioning_intent: bool
    reset_intent: bool
    expiry_intent: bool
    destroy_intent: bool

    @property
    def attempt_id(self) -> str:
        return self.ref.attempt_id

    @property
    def generation(self) -> int:
        return self.ref.generation

    @property
    def active_ref(self) -> ResourceRef | None:
        if self.active_sandbox_id is None or self.active_generation is None:
            return None
        return ResourceRef(
            self.ref.attempt_id, self.active_sandbox_id, self.active_generation
        )

    @property
    def candidate_ref(self) -> ResourceRef | None:
        if self.candidate_sandbox_id is None or self.candidate_generation is None:
            return None
        return ResourceRef(
            self.ref.attempt_id, self.candidate_sandbox_id, self.candidate_generation
        )


@dataclass(frozen=True)
class Resource:
    ref: ResourceRef
    state: str
    version: int
    container_id: str | None
    runtime_operation_id: str | None
    expires_at: datetime
    expiry_intent: bool
    destroy_intent: bool
    evidence_digest: str | None
    cleanup_evidence_digest: str | None


@dataclass(frozen=True)
class CleanupTask(Receipt):
    expiry_intent: bool
    retry_count: int


@dataclass(frozen=True)
class CapabilityClaims:
    """Claims from an already signature-verified capability, never raw input."""

    jti: str
    user_id: str
    ref: ResourceRef
    session_epoch: int
    expires_at: datetime
    scope: str


@dataclass(frozen=True)
class CapabilityUse:
    """The backend's non-secret receipt after atomically consuming a capability."""

    jti_hash: str
    ref: ResourceRef
    session_epoch: int
    expires_at: datetime


@dataclass(frozen=True)
class AttachmentLease:
    """A consumed, short-lived lease for one immediate PTY attachment."""

    lease_id: str
    ref: ResourceRef
    jti_hash: str
    gateway_session_hash: str
    session_epoch: int
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime
