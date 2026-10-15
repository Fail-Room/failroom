import tempfile
import unittest
from pathlib import Path

from failroom_sandbox.models import Check, Outcome
from failroom_sandbox.pty import PtyError
from test_qualification_collector import (
    NOW,
    Clock,
    FakeTerminalRuntime,
    ProcessTable,
    profile,
)

from failroom_control_plane.qualification_scenarios import (
    TERMINAL_CHECKS,
    TerminalScenarios,
    _limit_scenario,
)
from failroom_control_plane.terminal import TerminalError


class Admission:
    def __init__(self, service: "FakeService") -> None:
        self.service = service
        self.released = False

    def release(self) -> None:
        if not self.released:
            self.released = True
            if self.service.return_admissions:
                self.service.admitted -= 1


class ServiceSession:
    def __init__(self, service: "FakeService", session) -> None:
        self.service = service
        self.session = session
        self.closed = False

    def read(self, maximum: int) -> bytes:
        return self.session.read(maximum)

    def write(self, data: bytes) -> None:
        self.session.write(data)

    def resize(self, rows: int, columns: int) -> None:
        self.session.resize(rows, columns)

    def signal(self, value: int) -> None:
        self.session.signal(value)

    def close(self) -> None:
        self.session.close()
        if not self.closed:
            self.closed = True
            self.service.attached -= 1


class FakeService:
    """Counts connections and sessions apart, refusing at a count or never."""

    def __init__(
        self, runtime: FakeTerminalRuntime, *, refuse_at=None, return_admissions=True
    ) -> None:
        self.runtime = runtime
        self.refuse_at = refuse_at
        self.return_admissions = return_admissions
        self.admitted = 0
        self.attached = 0

    def admit(self, lease) -> Admission:
        if self.refuse_at is not None and self.admitted >= self.refuse_at:
            raise TerminalError("LIMIT_REACHED")
        self.admitted += 1
        return Admission(self)

    def attach(self, lease) -> ServiceSession:
        if self.refuse_at is not None and self.attached >= self.refuse_at:
            raise TerminalError("LIMIT_REACHED")
        self.attached += 1
        return ServiceSession(self, self.runtime.open("c" * 64, command=("/bin/bash",)))


class LimitScenarioTests(unittest.TestCase):
    def test_outcomes_follow_where_the_limit_takes_effect(self) -> None:
        def run(refuse_at, *, returns=True):
            held = []

            def take():
                if refuse_at is not None and len(held) >= refuse_at:
                    return "LIMIT_REACHED"
                held.append(object())
                return ""

            def give_back():
                if returns:
                    held.pop()

            return _limit_scenario(3, take, give_back)

        self.assertEqual(
            run(3), ("", {"limit": 3, "taken": 3, "refused": "LIMIT_REACHED"})
        )
        self.assertEqual(run(None), ("LIMIT_NOT_ENFORCED", {"limit": 3, "taken": 4}))
        self.assertEqual(run(2), ("LIMIT_BELOW_PROFILE", {"limit": 3, "taken": 2}))
        self.assertEqual(run(3, returns=False), ("SLOT_NOT_RETURNED", {"limit": 3}))


class TerminalScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.scratch = Path(temp.name)
        self.profile = profile()
        self.processes = ProcessTable()
        self.runtime = FakeTerminalRuntime(
            self.processes, self.profile.terminal_output_limit_bytes
        )
        self.clock = Clock()

    def run_scenarios(self, *, service_factory=None):
        return TerminalScenarios(
            self.processes,
            self.runtime,
            self.profile,
            scratch=self.scratch,
            busy_timeout_ms=5000,
            now=lambda: NOW,
            monotonic=self.clock.monotonic,
            sleep=self.clock.sleep,
            service_factory=service_factory,
        ).run("c" * 64)

    def assert_result(self, results, check, outcome, reason):
        self.assertEqual(
            (results[check].outcome, results[check].reason), (outcome, reason)
        )

    def test_well_behaved_terminal_passes_and_leaves_no_scratch(self) -> None:
        results = self.run_scenarios()

        self.assertEqual(tuple(results), TERMINAL_CHECKS)
        for check in TERMINAL_CHECKS:
            with self.subTest(check=check):
                self.assert_result(results, check, Outcome.PASS, "")
        self.assertEqual(
            dict(results[Check.TERMINAL_OUTPUT_LIMIT].facts),
            {"limit": 4096, "received": 4096, "stopped": True},
        )
        for check in (Check.CONNECTION_LIMIT, Check.SESSION_LIMIT):
            self.assertEqual(
                dict(results[check].facts),
                {"limit": 2, "taken": 2, "refused": "LIMIT_REACHED"},
            )
        self.assertEqual(
            dict(results[Check.DISCONNECT_CLEANUP].facts),
            {"members": 3, "remaining": []},
        )
        # Output, two sessions and a re-attach, and the disconnect shell.
        self.assertEqual(self.runtime.opened, [("c" * 64, ("/bin/bash",))] * 5)
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertEqual(self.processes.sessions, {})

    def test_unbounded_output_fails(self) -> None:
        self.runtime.enforce_output = False

        results = self.run_scenarios()

        self.assert_result(
            results, Check.TERMINAL_OUTPUT_LIMIT, Outcome.FAIL, "OUTPUT_NOT_BOUNDED"
        )

    def test_missing_output_is_unverified(self) -> None:
        self.runtime.produce_output = False

        results = self.run_scenarios()

        self.assert_result(
            results,
            Check.TERMINAL_OUTPUT_LIMIT,
            Outcome.UNVERIFIED,
            "OUTPUT_NOT_PRODUCED",
        )

    def test_processes_left_after_disconnect_fail(self) -> None:
        self.processes.keep_after_close = True

        results = self.run_scenarios()

        self.assert_result(
            results,
            Check.DISCONNECT_CLEANUP,
            Outcome.FAIL,
            "SESSION_PROCESSES_REMAIN",
        )
        self.assertEqual(
            results[Check.DISCONNECT_CLEANUP].facts["remaining"],
            ["42:S", "43:S", "44:S"],
        )
        self.assertGreaterEqual(self.clock.value, 15)

    def test_disconnect_scenario_needs_a_reported_running_session(self) -> None:
        cases = (
            ("report_shell", False, "SHELL_NOT_REPORTED"),
            ("members", 2, "SCENARIO_NOT_STARTED"),
        )
        for attribute, value, reason in cases:
            with self.subTest(reason=reason):
                self.setUp()
                setattr(self.runtime, attribute, value)
                results = self.run_scenarios()
                self.assert_result(
                    results, Check.DISCONNECT_CLEANUP, Outcome.UNVERIFIED, reason
                )

    def test_unreadable_process_listing_is_unverified(self) -> None:
        self.processes.malformed = True

        results = self.run_scenarios()

        self.assert_result(
            results,
            Check.DISCONNECT_CLEANUP,
            Outcome.UNVERIFIED,
            "PROCESSES_UNREADABLE",
        )

    def test_pty_failure_leaves_terminal_scenarios_unverified(self) -> None:
        self.runtime.open_error = PtyError("PTY_UNAVAILABLE")

        results = self.run_scenarios()

        for check in (
            Check.TERMINAL_OUTPUT_LIMIT,
            Check.SESSION_LIMIT,
            Check.DISCONNECT_CLEANUP,
        ):
            with self.subTest(check=check):
                self.assert_result(results, check, Outcome.UNVERIFIED, "ATTACH_FAILED")
        # Admission opens no PTY.
        self.assert_result(results, Check.CONNECTION_LIMIT, Outcome.PASS, "")

    def test_limit_scenarios_fail_a_service_that_misapplies_the_limit(self) -> None:
        both = (Check.CONNECTION_LIMIT, Check.SESSION_LIMIT)
        cases = (
            ({}, {check: "LIMIT_NOT_ENFORCED" for check in both}),
            ({"refuse_at": 1}, {check: "LIMIT_BELOW_PROFILE" for check in both}),
            (
                {"refuse_at": 2, "return_admissions": False},
                {Check.CONNECTION_LIMIT: "SLOT_NOT_RETURNED", Check.SESSION_LIMIT: ""},
            ),
        )
        for options, reasons in cases:
            with self.subTest(options=options):
                self.setUp()
                results = self.run_scenarios(
                    service_factory=lambda control, options=options: FakeService(
                        self.runtime, **options
                    )
                )
                for check, reason in reasons.items():
                    outcome = Outcome.FAIL if reason else Outcome.PASS
                    self.assert_result(results, check, outcome, reason)

    def test_unexpected_errors_leave_a_scenario_unverified(self) -> None:
        class Broken(FakeService):
            def attach(self, lease):
                raise RuntimeError("provider detail")

        results = self.run_scenarios(
            service_factory=lambda control: Broken(self.runtime, refuse_at=2)
        )

        self.assert_result(
            results,
            Check.TERMINAL_OUTPUT_LIMIT,
            Outcome.UNVERIFIED,
            "SCENARIO_FAILED",
        )
        self.assertEqual(dict(results[Check.TERMINAL_OUTPUT_LIMIT].facts), {})


if __name__ == "__main__":
    unittest.main()
