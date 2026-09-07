import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo

from failroom_sandbox.fingerprints import configuration_digest
from failroom_sandbox.models import (
    Check,
    CheckResult,
    DenialCode,
    Outcome,
    QualificationContext,
    QualificationReport,
    RuntimeIdentity,
)
from failroom_sandbox.qualification import (
    ProfileNotQualified,
    evaluate_qualification,
    require_qualified_profile,
)

NOW = datetime(2026, 9, 7, 1, 0, tzinfo=UTC)
MAX_AGE = timedelta(minutes=5)
SHA = "sha256:" + "a" * 64
OTHER_SHA = "sha256:" + "b" * 64


class RepeatedHour(tzinfo):
    """Model the two occurrences of a fall-back hour without a tzdata dependency."""

    def utcoffset(self, dt):
        return timedelta(hours=-5 if dt.fold else -4)


class InvalidOffset(tzinfo):
    def utcoffset(self, dt):
        return timedelta(hours=24)


class BrokenOffset(tzinfo):
    def utcoffset(self, dt):
        raise RuntimeError("private-time-provider-value")


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.context = QualificationContext(
            runtime=RuntimeIdentity("engine-1", "boot-1", "daemon-1", SHA),
            image_digest=SHA,
            profile_digest=SHA,
        )
        self.results = tuple(
            CheckResult(check, Outcome.PASS, NOW - timedelta(seconds=1), SHA)
            for check in Check
        )
        self.report = QualificationReport(self.context, self.results)

    def evaluate(self, report, **kwargs):
        return evaluate_qualification(
            kwargs.pop("context", self.context),
            report,
            now=kwargs.pop("now", NOW),
            max_age=kwargs.pop("max_age", MAX_AGE),
        )

    def assert_denied(self, report, code, **kwargs):
        decision = self.evaluate(report, **kwargs)
        self.assertFalse(decision.allowed)
        self.assertIn(code, {denial.code for denial in decision.denials})
        return decision

    def test_all_checks_pass_for_current_context(self):
        self.assertTrue(self.evaluate(self.report).allowed)

    def test_no_report_is_not_permission(self):
        self.assert_denied(None, DenialCode.REPORT_MISSING)

    def test_every_check_is_mandatory(self):
        for check in Check:
            with self.subTest(check=check):
                report = replace(
                    self.report,
                    results=tuple(r for r in self.results if r.check is not check),
                )
                decision = self.assert_denied(report, DenialCode.CHECK_MISSING)
                self.assertEqual(decision.denials[0].check, check)

    def test_empty_report_cannot_pass(self):
        decision = self.assert_denied(
            replace(self.report, results=()), DenialCode.CHECK_MISSING
        )
        self.assertEqual({d.check for d in decision.denials}, set(Check))

    def test_failure_and_unverified_each_deny(self):
        for check in Check:
            for outcome, code in (
                (Outcome.FAIL, DenialCode.CHECK_FAILED),
                (Outcome.UNVERIFIED, DenialCode.CHECK_UNVERIFIED),
            ):
                with self.subTest(check=check, outcome=outcome):
                    report = replace(
                        self.report,
                        results=tuple(
                            replace(r, outcome=outcome) if r.check is check else r
                            for r in self.results
                        ),
                    )
                    self.assert_denied(report, code)

    def test_duplicate_or_conflicting_results_deny(self):
        for extra in (self.results[0], replace(self.results[0], outcome=Outcome.FAIL)):
            with self.subTest(extra=extra):
                self.assert_denied(
                    replace(self.report, results=self.results + (extra,)),
                    DenialCode.REPORT_INVALID,
                )

    def test_malformed_results_deny_without_coercion(self):
        for invalid in (
            None,
            {"outcome": "PASS"},
            replace(self.results[0], check="new_unknown_check"),
            replace(self.results[0], check=self.results[0].check.value),
            replace(self.results[0], outcome="PASS"),
            replace(self.results[0], outcome=True),
            replace(self.results[0], evidence_digest=""),
            replace(self.results[0], evidence_digest="/private/token"),
            replace(self.results[0], observed_at="2026-09-07"),
            replace(self.results[0], observed_at=NOW.replace(tzinfo=None)),
        ):
            with self.subTest(invalid=invalid):
                self.assert_denied(
                    replace(self.report, results=(invalid,) + self.results[1:]),
                    DenialCode.REPORT_INVALID,
                )

    def test_mutable_or_untyped_reports_deny(self):
        for report in ({}, True, replace(self.report, results=list(self.results))):
            with self.subTest(report_type=type(report)):
                self.assert_denied(report, DenialCode.REPORT_INVALID)

    def test_each_runtime_identity_change_invalidates_report(self):
        for field, value in (
            ("engine_id", "engine-2"),
            ("host_boot_id", "boot-2"),
            ("daemon_epoch", "daemon-2"),
            ("configuration_digest", OTHER_SHA),
        ):
            with self.subTest(field=field):
                context = replace(
                    self.context,
                    runtime=replace(self.context.runtime, **{field: value}),
                )
                self.assert_denied(
                    self.report, DenialCode.CONTEXT_MISMATCH, context=context
                )

    def test_changed_image_or_profile_invalidates_report(self):
        for field in ("image_digest", "profile_digest"):
            with self.subTest(field=field):
                self.assert_denied(
                    self.report,
                    DenialCode.CONTEXT_MISMATCH,
                    context=replace(self.context, **{field: OTHER_SHA}),
                )

    def test_configuration_change_is_denied_through_guard(self):
        profile = {"limits": {"pids": 32}, "network": "none"}
        context = replace(self.context, profile_digest=configuration_digest(profile))
        report = replace(self.report, context=context)
        require_qualified_profile(context, report, now=NOW, max_age=MAX_AGE)
        profile["limits"]["pids"] = 64
        changed = replace(context, profile_digest=configuration_digest(profile))
        with self.assertRaises(ProfileNotQualified) as caught:
            require_qualified_profile(changed, report, now=NOW, max_age=MAX_AGE)
        self.assertEqual(
            caught.exception.decision.denials[0].code, DenialCode.CONTEXT_MISMATCH
        )

    def test_invalid_context_does_not_pass_even_when_report_matches(self):
        bad_contexts = [
            None,
            {},
            replace(self.context, image_digest="ubuntu:24.04"),
            replace(self.context, profile_digest="sha256:" + "z" * 64),
            replace(self.context, runtime=None),
        ]
        for field in ("engine_id", "host_boot_id", "daemon_epoch"):
            for value in (None, "", " ", "bad\nidentity", "x" * 257):
                bad_contexts.append(
                    replace(
                        self.context,
                        runtime=replace(self.context.runtime, **{field: value}),
                    )
                )
        bad_contexts.append(
            replace(
                self.context,
                runtime=replace(self.context.runtime, configuration_digest="bad"),
            )
        )
        for context in bad_contexts:
            with self.subTest(context=context):
                self.assert_denied(
                    replace(self.report, context=context),
                    DenialCode.CONTEXT_INVALID,
                    context=context,
                )

    def test_invalid_evidence_context_denies(self):
        self.assert_denied(
            replace(self.report, context=None), DenialCode.REPORT_INVALID
        )

    def test_any_result_expires_at_exact_age_boundary(self):
        for age in (MAX_AGE, MAX_AGE + timedelta(microseconds=1)):
            with self.subTest(age=age):
                report = replace(
                    self.report,
                    results=(replace(self.results[0], observed_at=NOW - age),)
                    + self.results[1:],
                )
                self.assert_denied(report, DenialCode.EVIDENCE_EXPIRED)

    def test_evidence_before_boundary_is_valid(self):
        results = tuple(
            replace(r, observed_at=NOW - MAX_AGE + timedelta(microseconds=1))
            for r in self.results
        )
        self.assertTrue(self.evaluate(replace(self.report, results=results)).allowed)

    def test_future_evidence_is_rejected(self):
        report = replace(
            self.report,
            results=(
                replace(self.results[0], observed_at=NOW + timedelta(microseconds=1)),
            )
            + self.results[1:],
        )
        self.assert_denied(report, DenialCode.EVIDENCE_FUTURE)

    def test_observed_at_now_is_valid(self):
        results = tuple(replace(r, observed_at=NOW) for r in self.results)
        self.assertTrue(self.evaluate(replace(self.report, results=results)).allowed)

    def test_equivalent_timezone_is_valid(self):
        now = NOW.astimezone(timezone(timedelta(hours=9)))
        self.assertTrue(self.evaluate(self.report, now=now).allowed)

    def test_bad_clock_or_age_policy_denies(self):
        for kwargs in (
            {"now": NOW.replace(tzinfo=None)},
            {"now": None},
            {"now": "2026-09-07"},
            {"max_age": timedelta(0)},
            {"max_age": timedelta(seconds=-1)},
            {"max_age": float("inf")},
            {"max_age": True},
        ):
            with self.subTest(kwargs=kwargs):
                self.assert_denied(self.report, DenialCode.EVALUATION_INVALID, **kwargs)

    def test_fall_back_hour_uses_elapsed_time_not_wall_time(self):
        zone = RepeatedHour()
        for observed_fold, now_fold, code in (
            (0, 1, DenialCode.EVIDENCE_EXPIRED),
            (1, 0, DenialCode.EVIDENCE_FUTURE),
        ):
            with self.subTest(observed_fold=observed_fold):
                observed = datetime(2026, 11, 1, 1, 0, tzinfo=zone, fold=observed_fold)
                now = datetime(2026, 11, 1, 1, 1, tzinfo=zone, fold=now_fold)
                report = replace(
                    self.report,
                    results=tuple(
                        replace(r, observed_at=observed) for r in self.results
                    ),
                )
                self.assert_denied(report, code, now=now)

    def test_invalid_timezone_returns_fixed_denial(self):
        for zone in (InvalidOffset(), BrokenOffset()):
            with self.subTest(zone_type=type(zone)):
                invalid = NOW.replace(tzinfo=zone)
                self.assert_denied(
                    self.report, DenialCode.EVALUATION_INVALID, now=invalid
                )
                report = replace(
                    self.report,
                    results=(replace(self.results[0], observed_at=invalid),)
                    + self.results[1:],
                )
                self.assert_denied(report, DenialCode.REPORT_INVALID)

    def test_out_of_range_utc_normalization_returns_fixed_denial(self):
        invalid = datetime.min.replace(tzinfo=timezone(timedelta(hours=1)))
        self.assert_denied(self.report, DenialCode.EVALUATION_INVALID, now=invalid)

    def test_evaluation_is_deterministic_and_does_not_refresh_evidence(self):
        original = self.report
        first = self.evaluate(original)
        self.assertEqual(first, self.evaluate(original))
        self.assertIs(self.report, original)
        self.assert_denied(original, DenialCode.EVIDENCE_EXPIRED, now=NOW + MAX_AGE)

    def test_reordering_results_does_not_change_denials(self):
        results = tuple(replace(r, outcome=Outcome.FAIL) for r in self.results)
        forward = self.evaluate(replace(self.report, results=results))
        backward = self.evaluate(replace(self.report, results=tuple(reversed(results))))
        self.assertEqual(forward, backward)

    def test_records_are_frozen(self):
        for record, field in (
            (self.report, "context"),
            (self.context, "image_digest"),
            (self.context.runtime, "engine_id"),
            (self.results[0], "outcome"),
            (self.evaluate(self.report), "denials"),
        ):
            with self.subTest(record=type(record)):
                with self.assertRaises(FrozenInstanceError):
                    setattr(record, field, None)

    def test_guard_raises_before_following_work(self):
        reached = False
        with self.assertRaises(ProfileNotQualified) as caught:
            require_qualified_profile(self.context, None, now=NOW, max_age=MAX_AGE)
            reached = True
        self.assertFalse(reached)
        self.assertEqual(caught.exception.code, "SANDBOX_PROFILE_UNVERIFIED")
        self.assertEqual(caught.exception.decision, self.evaluate(None))

    def test_guard_returns_none_only_for_qualified_report(self):
        self.assertIsNone(
            require_qualified_profile(
                self.context, self.report, now=NOW, max_age=MAX_AGE
            )
        )

    def test_errors_do_not_echo_context_or_evidence(self):
        secret = "/private/credential-do-not-log"
        report = replace(
            self.report,
            results=(replace(self.results[0], evidence_digest=secret),)
            + self.results[1:],
        )
        with self.assertRaises(ProfileNotQualified) as caught:
            require_qualified_profile(self.context, report, now=NOW, max_age=MAX_AGE)
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, repr(caught.exception.decision))


if __name__ == "__main__":
    unittest.main()
