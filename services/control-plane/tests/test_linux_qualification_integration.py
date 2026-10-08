"""Opt-in proof of report-only qualification collection on a trusted Linux host."""

import os
import subprocess
import sys
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from failroom_sandbox.docker_cli import DockerCli
from failroom_sandbox.docker_lifecycle import (
    ContainerLifetime,
    DockerDiagnosticLifecycle,
)
from failroom_sandbox.docker_profile import DockerBinding
from failroom_sandbox.models import Check, DenialCode, Outcome
from failroom_sandbox.qualification import evaluate_qualification
from failroom_sandbox.qualification_probe import (
    CONTAINER_CHECKS,
    judge_container_checks,
    parse_probe_output,
)
from failroom_sandbox.seccomp import SeccompPolicyStore
from test_linux_docker_integration import _profile_from_environment, _required

from failroom_control_plane.qualification_collector import (
    QUALIFICATION_ATTEMPT,
    QualificationCollector,
)

_SCENARIO_CHECKS = tuple(check for check in Check if check not in CONTAINER_CHECKS)


def _now() -> datetime:
    return datetime.now(UTC)


@unittest.skipUnless(
    os.environ.get("FAILROOM_DOCKER_INTEGRATION") == "1",
    "UNVERIFIED: opt-in required",
)
@unittest.skipUnless(
    sys.platform == "linux", "UNVERIFIED: trusted Linux controller required"
)
class LinuxQualificationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = _profile_from_environment()
        self.context = _required("FAILROOM_DOCKER_CONTEXT")
        self.timeout = float(_required("FAILROOM_DOCKER_TIMEOUT_SECONDS"))
        self.cli = DockerCli(
            context=self.context,
            timeout=self.timeout,
            max_output_bytes=int(_required("FAILROOM_DOCKER_MAX_OUTPUT_BYTES")),
        )
        self.lifecycle = DockerDiagnosticLifecycle(
            self.cli,
            SeccompPolicyStore(
                Path(_required("FAILROOM_SECCOMP_STORE")),
                max_bytes=int(_required("FAILROOM_SECCOMP_MAX_BYTES")),
            ),
        )
        self.max_age = timedelta(
            seconds=int(_required("FAILROOM_QUALIFICATION_MAX_AGE_SECONDS"))
        )

    def collector(self) -> QualificationCollector:
        return QualificationCollector(
            self.cli, self.lifecycle, self.profile, max_age=self.max_age, now=_now
        )

    def collector_sandboxes(self) -> tuple[str, ...]:
        return self.cli.list_containers(
            (
                "label=failroom.kind=diagnostic",
                "label=failroom.attempt_id=" + QUALIFICATION_ATTEMPT,
            )
        )

    def test_container_checks_pass_and_scenarios_stay_unverified(self) -> None:
        collection = self.collector().collect()
        report = collection.report

        for result in report.results:
            with self.subTest(check=result.check):
                if result.check in CONTAINER_CHECKS:
                    self.assertIs(result.outcome, Outcome.PASS)
                    self.assertNotIn(result.check, collection.reasons)
                else:
                    self.assertIs(result.outcome, Outcome.UNVERIFIED)
                    self.assertEqual(collection.reasons[result.check], "NOT_COLLECTED")
        decision = evaluate_qualification(
            report.context, report, now=_now(), max_age=self.max_age
        )
        self.assertEqual(
            {(denial.code, denial.check) for denial in decision.denials},
            {(DenialCode.CHECK_UNVERIFIED, check) for check in _SCENARIO_CHECKS},
        )
        self.assertEqual(
            report.context.image_digest,
            self.cli.inspect_image(self.profile.image)["Id"],
        )
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as boot:
            boot_id = boot.read().strip()
        # Docker Desktop runs the daemon in its own VM; a native engine shares
        # the controller's kernel.
        self.assertRegex(report.context.runtime.host_boot_id, r"^[0-9a-f-]{36}$")
        if "Docker Desktop" not in str(self.cli.engine_identity().configuration):
            self.assertEqual(report.context.runtime.host_boot_id, boot_id)
        self.assertEqual(self.collector_sandboxes(), ())

    def test_stopped_leftover_from_a_crashed_collection_is_removed(self) -> None:
        binding = DockerBinding(
            QUALIFICATION_ATTEMPT, "probe-leftover-" + uuid4().hex[:12], 1
        )
        operation = uuid4().hex
        # A two-second lifetime: PID 1 exits on its own, as after a crash.
        created = self.lifecycle.create_diagnostic(
            self.profile,
            binding,
            operation,
            lifetime=ContainerLifetime(_now() + timedelta(seconds=13), _now),
        )
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                data = self.cli.inspect_container(created.container_id)
                if data is not None and data["State"]["Running"] is False:
                    break
                time.sleep(0.5)
            self.assertIs(data["State"]["Running"], False)

            self.collector().collect()

            self.assertIsNone(self.cli.inspect_container(created.container_id))
        finally:
            self.lifecycle.destroy(
                binding, created.container_id, operation_id=operation
            )
        self.assertEqual(self.collector_sandboxes(), ())

    def test_container_outside_the_profile_fails_the_checks_it_violates(self) -> None:
        """A writable, networked container with default capabilities."""
        name = "failroom-qualification-negative-" + uuid4().hex[:12]
        docker = ("docker", "--context", self.context, "container")
        created = subprocess.run(
            (
                *docker,
                "create",
                "--name",
                name,
                "--label",
                "failroom.kind=qualification-negative",
                "--init",
                "--user",
                f"{self.profile.uid}:{self.profile.gid}",
                "--entrypoint",
                "/bin/sleep",
                "--pull",
                "never",
                self.profile.image,
                "120",
            ),
            capture_output=True,
            text=True,
            check=True,
            timeout=self.timeout,
        )
        container_id = created.stdout.strip()
        try:
            subprocess.run(
                (*docker, "start", container_id),
                capture_output=True,
                check=True,
                timeout=self.timeout,
            )
            observation = parse_probe_output(
                self.cli.run_qualification_probe(container_id)
            )
            data = self.cli.inspect_container(container_id)
            self.assertIsNotNone(data)
            judgements = {
                judgement.check: judgement
                for judgement in judge_container_checks(
                    observation, data, self.profile, lifetime_seconds=120
                )
            }
        finally:
            subprocess.run(
                (*docker, "rm", "--force", container_id),
                capture_output=True,
                check=False,
                timeout=self.timeout,
            )
        expected = {
            Check.UNPRIVILEGED_IDENTITY: "CAPABILITIES_PRESENT",
            Check.FILESYSTEM_ISOLATION: "UNEXPECTED_MOUNT",
            Check.NETWORK_ISOLATION: "INTERFACE_PRESENT",
            Check.PID_LIMIT: "PID_LIMIT_MISMATCH",
        }
        for check, reason in expected.items():
            with self.subTest(check=check):
                self.assertIs(judgements[check].outcome, Outcome.FAIL)
                self.assertEqual(judgements[check].reason, reason)
        self.assertIs(judgements[Check.STORAGE_LIMIT].outcome, Outcome.UNVERIFIED)


if __name__ == "__main__":
    unittest.main()
