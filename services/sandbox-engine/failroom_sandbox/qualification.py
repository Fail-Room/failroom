"""Fail-closed evaluation of trusted profile evidence, without side effects.

Inputs must be assembled by the trusted control plane, never deserialized from
learner requests. Artifact hashes bind references, not authenticity. This gate
does not replace current ownership, generation, lifecycle, or attachment checks.
"""

import re
from datetime import UTC, datetime, timedelta

from .models import (
    Check,
    CheckResult,
    Denial,
    DenialCode,
    Outcome,
    QualificationContext,
    QualificationDecision,
    QualificationReport,
    RuntimeIdentity,
)

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


def _digest_valid(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _identity_valid(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 256
        and value.strip() == value
        and all(33 <= ord(char) <= 126 for char in value)
    )


def _context_valid(context: object) -> bool:
    if type(context) is not QualificationContext:
        return False
    runtime = context.runtime
    return (
        type(runtime) is RuntimeIdentity
        and _identity_valid(runtime.engine_id)
        and _identity_valid(runtime.host_boot_id)
        and _identity_valid(runtime.daemon_epoch)
        and _digest_valid(runtime.configuration_digest)
        and _digest_valid(context.image_digest)
        and _digest_valid(context.profile_digest)
    )


def _as_utc(value: object) -> datetime | None:
    if type(value) is not datetime:
        return None
    try:
        if value.utcoffset() is None:
            return None
        return value.astimezone(UTC)
    except Exception:
        # A timezone provider may fail or overflow. Do not expose its details.
        return None


def _deny(code: DenialCode) -> QualificationDecision:
    return QualificationDecision((Denial(code),))


def evaluate_qualification(
    context: QualificationContext,
    report: QualificationReport | None,
    *,
    now: datetime,
    max_age: timedelta,
) -> QualificationDecision:
    """Require every check to match, pass, and have age in [0, max_age).

    `now` and `max_age` are explicit trusted inputs. No evidence is refreshed,
    runtime created, or mutable authorization returned by this function.
    """
    now_utc = _as_utc(now)
    if now_utc is None or type(max_age) is not timedelta or max_age <= timedelta(0):
        return _deny(DenialCode.EVALUATION_INVALID)
    if not _context_valid(context):
        return _deny(DenialCode.CONTEXT_INVALID)
    if report is None:
        return _deny(DenialCode.REPORT_MISSING)
    if (
        type(report) is not QualificationReport
        or not _context_valid(report.context)
        or type(report.results) is not tuple
    ):
        return _deny(DenialCode.REPORT_INVALID)
    if context != report.context:
        return _deny(DenialCode.CONTEXT_MISMATCH)

    results: dict[Check, tuple[CheckResult, datetime]] = {}
    for result in report.results:
        if (
            type(result) is not CheckResult
            or type(result.check) is not Check
            or type(result.outcome) is not Outcome
            or not _digest_valid(result.evidence_digest)
            or result.check in results
        ):
            return _deny(DenialCode.REPORT_INVALID)
        observed_utc = _as_utc(result.observed_at)
        if observed_utc is None:
            return _deny(DenialCode.REPORT_INVALID)
        results[result.check] = (result, observed_utc)

    denials: list[Denial] = []
    for check in Check:
        entry = results.get(check)
        if entry is None:
            denials.append(Denial(DenialCode.CHECK_MISSING, check))
            continue
        result, observed_utc = entry
        if result.outcome is Outcome.FAIL:
            denials.append(Denial(DenialCode.CHECK_FAILED, check))
        elif result.outcome is Outcome.UNVERIFIED:
            denials.append(Denial(DenialCode.CHECK_UNVERIFIED, check))
        age = now_utc - observed_utc
        if age < timedelta(0):
            denials.append(Denial(DenialCode.EVIDENCE_FUTURE, check))
        elif age >= max_age:
            denials.append(Denial(DenialCode.EVIDENCE_EXPIRED, check))
    return QualificationDecision(tuple(denials))


class ProfileNotQualified(RuntimeError):
    """Safe error details contain only code-owned enum values."""

    code = "SANDBOX_PROFILE_UNVERIFIED"

    def __init__(self, decision: QualificationDecision) -> None:
        self.decision = decision
        reasons = ",".join(
            f"{denial.code.value}:{denial.check.value if denial.check else '-'}"
            for denial in decision.denials
        )
        super().__init__(f"{self.code}: {reasons}")


def require_qualified_profile(
    context: QualificationContext,
    report: QualificationReport | None,
    *,
    now: datetime,
    max_age: timedelta,
) -> None:
    """Raise before a trusted caller proceeds to other creation prerequisites."""
    decision = evaluate_qualification(context, report, now=now, max_age=max_age)
    if not decision.allowed:
        raise ProfileNotQualified(decision)
