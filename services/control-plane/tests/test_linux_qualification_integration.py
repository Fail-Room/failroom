"""Opt-in proof of report-only qualification collection on a trusted Linux host."""

import json
import os
import subprocess
import sys
import tempfile
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
from failroom_sandbox.models import Check, Outcome
from failroom_sandbox.pty import DockerPtyRuntime
from failroom_sandbox.qualification import evaluate_qualification
from failroom_sandbox.qualification_probe import (
    judge_container_checks,
    parse_probe_output,
)
from failroom_sandbox.seccomp import SeccompPolicyStore
from test_linux_docker_integration import (
    _database_directory,
    _profile_from_environment,
    _required,
)
from test_linux_terminal_integration import _terminal_limits

from failroom_control_plane.qualification_collector import (
    QUALIFICATION_ATTEMPT_PREFIX,
    QualificationCollector,
    QualificationError,
    qualification_attempt,
)
from failroom_control_plane.qualification_restart import (
    RESTART_DIRECTORY,
    RestartScenario,
)
from failroom_control_plane.qualification_workspace import (
    ID_NAME,
    LOCK_NAME,
    WORKSPACE_NAME,
    LockedWorkspace,
    workspace_id,
)
from failroom_control_plane.runtime_docker import (
    DockerCleanupRuntime,
    DockerProvisioningRuntime,
)


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
        self.scratch = _database_directory()
        self.pty_limits, _ = _terminal_limits()

    def collector(self) -> QualificationCollector:
        return QualificationCollector(
            self.cli,
            self.lifecycle,
            self.profile,
            max_age=self.max_age,
            now=_now,
            terminal=DockerPtyRuntime(context=self.context, limits=self.pty_limits),
            provisioning=DockerProvisioningRuntime(self.lifecycle, self.profile),
            cleanup=DockerCleanupRuntime(self.lifecycle),
            workspace=LockedWorkspace(self.scratch),
            busy_timeout_ms=int(_required("FAILROOM_DATABASE_BUSY_TIMEOUT_MS")),
        )

    def workspace_entries(self) -> list[str]:
        return sorted(entry.name for entry in (self.scratch / WORKSPACE_NAME).iterdir())

    def sandboxes(self, *labels: str) -> tuple[str, ...]:
        return self.cli.list_containers(("label=failroom.kind=diagnostic", *labels))

    def attempt(self) -> str:
        """This workspace's attempt label; reading it creates the ID once."""
        with LockedWorkspace(self.scratch).hold() as workspace:
            return qualification_attempt(workspace_id(workspace))

    def collector_sandboxes(self) -> tuple[str, ...]:
        return self.sandboxes("label=failroom.attempt_id=" + self.attempt())

    def assert_every_check_passes(self, collection) -> None:
        report = collection.report
        for result in report.results:
            with self.subTest(check=result.check):
                self.assertIs(result.outcome, Outcome.PASS)
        self.assertEqual(dict(collection.reasons), {})
        decision = evaluate_qualification(
            report.context, report, now=_now(), max_age=self.max_age
        )
        self.assertTrue(decision.allowed)

    def test_every_check_passes_on_the_strict_profile(self) -> None:
        before = set(self.sandboxes())
        collection = self.collector().collect()
        report = collection.report

        self.assert_every_check_passes(collection)
        # Neither the Room sandbox nor any scratch state outlives the collection.
        self.assertEqual(set(self.sandboxes()), before)
        self.assertEqual(self.workspace_entries(), [LOCK_NAME, ID_NAME])
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

    def test_sandboxes_left_by_a_crashed_collection_are_removed(self) -> None:
        leftovers = []
        # The first was created but never started, as after a crash between
        # the two: Docker removes a sandbox only once its PID 1 has run. The
        # second still runs when the next collection starts.
        for name, start in (("probe-created-", False), ("sentinel-running-", True)):
            binding = DockerBinding(self.attempt(), name + uuid4().hex[:12], 1)
            operation = uuid4().hex
            lifetime = ContainerLifetime(_now() + timedelta(seconds=120), _now)
            if start:
                container_id = self.lifecycle.create_diagnostic(
                    self.profile, binding, operation, lifetime=lifetime
                ).container_id
            else:
                with self.lifecycle.prepare(
                    self.profile, binding, operation, lifetime=lifetime
                ) as prepared:
                    container_id = prepared.create_verified().container_id
            leftovers.append((binding, container_id, operation))
        try:
            created = self.cli.inspect_container(leftovers[0][1])
            self.assertEqual(created["State"]["Status"], "created")
            running = self.cli.inspect_container(leftovers[1][1])
            self.assertIs(running["State"]["Running"], True)

            self.collector().collect()

            for _, container_id, _ in leftovers:
                self.assertIsNone(self.cli.inspect_container(container_id))
        finally:
            for binding, container_id, operation in leftovers:
                self.lifecycle.destroy(binding, container_id, operation_id=operation)
        self.assertEqual(self.collector_sandboxes(), ())

    def test_room_sandbox_left_by_a_crashed_collection_is_recovered(self) -> None:
        restart = RestartScenario(
            self.cli,
            self.lifecycle,
            DockerProvisioningRuntime(self.lifecycle, self.profile),
            DockerCleanupRuntime(self.lifecycle),
            busy_timeout_ms=int(_required("FAILROOM_DATABASE_BUSY_TIMEOUT_MS")),
            now=_now,
        )
        with LockedWorkspace(self.scratch).hold() as workspace:
            self.assertIsNone(restart.begin(workspace))
            binding = json.loads(
                (workspace / RESTART_DIRECTORY / "binding.json").read_bytes()
            )
        # Releasing the lock is what the kernel does when the collector dies.
        labels = (
            "label=failroom.attempt_id=" + binding["attempt_id"],
            "label=failroom.sandbox_id=" + binding["sandbox_id"],
        )
        self.assertEqual(len(self.sandboxes(*labels)), 1)
        try:
            collection = self.collector().collect()

            self.assertEqual(self.sandboxes(*labels), ())
            self.assertEqual(self.workspace_entries(), [LOCK_NAME, ID_NAME])
            self.assert_every_check_passes(collection)
        finally:
            for container_id in self.sandboxes(*labels):
                self.lifecycle.destroy(
                    DockerBinding(binding["attempt_id"], binding["sandbox_id"], 1),
                    container_id,
                )

    def test_sandbox_of_another_workspace_is_left_alone(self) -> None:
        # A running sandbox of another database directory's collection.
        other = tempfile.TemporaryDirectory(dir=self.scratch)
        self.addCleanup(other.cleanup)
        with LockedWorkspace(Path(other.name)).hold() as workspace:
            attempt = qualification_attempt(workspace_id(workspace))
        self.assertNotEqual(attempt, self.attempt())
        self.assertTrue(attempt.startswith(QUALIFICATION_ATTEMPT_PREFIX))
        binding = DockerBinding(attempt, "sentinel-" + uuid4().hex, 1)
        operation = uuid4().hex
        created = self.lifecycle.create_diagnostic(
            self.profile,
            binding,
            operation,
            lifetime=ContainerLifetime(_now() + timedelta(seconds=120), _now),
        )
        try:
            self.collector().collect()

            data = self.cli.inspect_container(created.container_id)
            self.assertIsNotNone(data)
            self.assertIs(data["State"]["Running"], True)
        finally:
            self.lifecycle.destroy(
                binding, created.container_id, operation_id=operation
            )

    def test_a_second_collection_is_refused_while_one_holds_the_workspace(
        self,
    ) -> None:
        before = set(self.sandboxes())
        with LockedWorkspace(self.scratch).hold():
            with self.assertRaises(QualificationError) as raised:
                self.collector().collect()

        self.assertEqual(raised.exception.code, "COLLECTION_IN_PROGRESS")
        self.assertEqual(set(self.sandboxes()), before)

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
