"""Immutable, internal qualification records produced by trusted verifiers."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Check(StrEnum):
    """Every member is mandatory; callers cannot reduce the required set."""

    UNPRIVILEGED_IDENTITY = "unprivileged_identity"
    SYSCALL_RESTRICTIONS = "syscall_restrictions"
    FILESYSTEM_ISOLATION = "filesystem_isolation"
    PROCESS_ISOLATION = "process_isolation"
    HOST_ACCESS_ABSENCE = "host_access_absence"
    NETWORK_ISOLATION = "network_isolation"
    CPU_LIMIT = "cpu_limit"
    MEMORY_AND_SWAP_LIMIT = "memory_and_swap_limit"
    PID_LIMIT = "pid_limit"
    STORAGE_LIMIT = "storage_limit"
    IO_LIMIT = "io_limit"
    FILE_DESCRIPTOR_LIMIT = "file_descriptor_limit"
    TERMINAL_OUTPUT_LIMIT = "terminal_output_limit"
    CONNECTION_LIMIT = "connection_limit"
    SESSION_LIMIT = "session_limit"
    ABSOLUTE_TTL = "absolute_ttl"
    DISCONNECT_CLEANUP = "disconnect_cleanup"
    RESTART_CLEANUP = "restart_cleanup"


class Outcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNVERIFIED = "UNVERIFIED"


class DenialCode(StrEnum):
    EVALUATION_INVALID = "EVALUATION_INVALID"
    CONTEXT_INVALID = "CONTEXT_INVALID"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    REPORT_MISSING = "REPORT_MISSING"
    REPORT_INVALID = "REPORT_INVALID"
    CHECK_MISSING = "CHECK_MISSING"
    CHECK_FAILED = "CHECK_FAILED"
    CHECK_UNVERIFIED = "CHECK_UNVERIFIED"
    EVIDENCE_EXPIRED = "EVIDENCE_EXPIRED"
    EVIDENCE_FUTURE = "EVIDENCE_FUTURE"


@dataclass(frozen=True)
class RuntimeIdentity:
    engine_id: str
    host_boot_id: str
    daemon_epoch: str
    configuration_digest: str


@dataclass(frozen=True)
class QualificationContext:
    runtime: RuntimeIdentity
    image_digest: str
    profile_digest: str


@dataclass(frozen=True)
class CheckResult:
    check: Check
    outcome: Outcome
    observed_at: datetime
    evidence_digest: str


@dataclass(frozen=True)
class QualificationReport:
    context: QualificationContext
    results: tuple[CheckResult, ...]


@dataclass(frozen=True)
class Denial:
    code: DenialCode
    check: Check | None = None


@dataclass(frozen=True)
class QualificationDecision:
    denials: tuple[Denial, ...]

    @property
    def allowed(self) -> bool:
        return not self.denials
