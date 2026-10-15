import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.models import DenialCode
from failroom_state import (
    Action,
    BackendStore,
    ControlPlaneStore,
    Database,
    DockerCleanupWorker,
    Role,
    ServiceIdentity,
    UserIdentity,
)
from test_qualification_collector import STARTED_AT, Harness

from failroom_control_plane.entry import EntryError, RoomEntryService
from failroom_control_plane.maintenance import LifecycleMaintenanceService
from failroom_control_plane.orchestrator import LifecycleOrchestrator
from failroom_control_plane.qualification_collector import QualificationError
from failroom_control_plane.qualification_gate import (
    GatedProvisioningRuntime,
    QualificationGate,
)
from failroom_control_plane.qualification_workspace import WorkspaceError
from failroom_control_plane.room_scenarios import RoomScenarioRegistry

MAX_AGE = timedelta(hours=1)


class QualificationGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(self)
        self.docker = self.harness.docker
        self.lifecycle = self.harness.lifecycle
        self.workspace = self.harness.workspace
        self.gate = self.make_gate()
        self.addCleanup(self.gate.close)

    def make_gate(self, **changes) -> QualificationGate:
        harness = self.harness
        arguments = {
            "workspace": harness.workspace,
            "collector": lambda workspace: harness.collector(workspace=workspace),
            "max_age": MAX_AGE,
            "now": harness.clock.now,
            **changes,
        }
        return QualificationGate(
            harness.docker, harness.lifecycle, harness.profile, **arguments
        )

    def sentinel_id(self) -> str:
        return self.lifecycle.created[0][3]

    def denials(self) -> set:
        return {denial.code for denial in self.gate.decide().denials}

    def assert_refused(self) -> None:
        with self.assertRaises(DockerError) as raised:
            self.gate.require()
        self.assertEqual(raised.exception.code, "PROFILE_UNVERIFIED")

    def test_start_collects_once_and_keeps_the_sentinel_until_close(self) -> None:
        self.assertEqual(self.gate.start(), "QUALIFICATION_PASSED")

        self.gate.require()
        sentinel = self.sentinel_id()
        # Only the sentinel outlives the collection; the workspace stays held.
        self.assertEqual(list(self.docker.containers), [sentinel])
        self.assertEqual((self.workspace.holds, self.workspace.releases), (1, 0))

        self.gate.close()

        self.assertEqual(self.docker.containers, {})
        self.assertEqual(self.lifecycle.destroyed[-1][1], sentinel)
        self.assertEqual(self.workspace.releases, 1)
        self.assert_refused()
        self.gate.close()
        self.assertEqual(self.workspace.releases, 1)

    def test_allocation_is_refused_once_the_runtime_differs(self) -> None:
        def stopped():
            self.docker.containers[self.sentinel_id()]["State"]["Running"] = False

        def restarted():
            state = self.docker.containers[self.sentinel_id()]["State"]
            state["StartedAt"] = STARTED_AT.replace("10:14:00", "10:15:00")

        cases = {
            "sentinel removed": (
                lambda: self.docker.containers.pop(self.sentinel_id()),
                DenialCode.CONTEXT_INVALID,
            ),
            "sentinel stopped": (stopped, DenialCode.CONTEXT_INVALID),
            "daemon restarted": (restarted, DenialCode.CONTEXT_MISMATCH),
            "engine replaced": (
                lambda: setattr(
                    self.docker,
                    "engine",
                    self.docker.engine.__class__(
                        "engine-2", self.docker.engine.configuration
                    ),
                ),
                DenialCode.CONTEXT_MISMATCH,
            ),
            "host rebooted": (
                lambda: setattr(
                    self.docker, "boot_id", "11111111-2222-4333-8444-555555555555"
                ),
                DenialCode.CONTEXT_MISMATCH,
            ),
            "I/O device moved": (
                lambda: setattr(self.docker, "io_device", "8:48"),
                DenialCode.CONTEXT_MISMATCH,
            ),
            "image rebuilt": (
                lambda: setattr(self.docker, "image_id", "sha256:" + "0" * 64),
                DenialCode.CONTEXT_MISMATCH,
            ),
        }
        for name, (change, code) in cases.items():
            with self.subTest(case=name):
                self.setUp()
                self.assertEqual(self.gate.start(), "QUALIFICATION_PASSED")
                change()

                self.assert_refused()
                self.assertEqual(self.denials(), {code})

    def test_report_is_refused_once_it_is_as_old_as_its_validity(self) -> None:
        self.gate.start()
        self.harness.clock.sleep(MAX_AGE.total_seconds() - 60)
        self.gate.require()

        self.harness.clock.sleep(60)

        self.assert_refused()
        self.assertEqual(self.denials(), {DenialCode.EVIDENCE_EXPIRED})

    def test_a_report_that_does_not_pass_refuses_allocation(self) -> None:
        self.lifecycle.lifetime_end = (False, 0, 15.5)

        self.assertEqual(
            self.gate.start(), "QUALIFICATION_DENIED CHECK_FAILED:absolute_ttl"
        )

        self.assert_refused()
        self.gate.close()
        self.assertEqual(self.docker.containers, {})

    def test_failed_start_serves_with_allocation_refused(self) -> None:
        cases = {
            "workspace held elsewhere": (
                lambda: setattr(
                    self.workspace, "error", WorkspaceError("COLLECTION_IN_PROGRESS")
                ),
                "QUALIFICATION_UNAVAILABLE COLLECTION_IN_PROGRESS",
            ),
            "collection failed": (
                lambda: setattr(self.docker, "probe_output", b"probe=1\nend=1\n"),
                "QUALIFICATION_UNAVAILABLE RUNTIME_UNAVAILABLE",
            ),
        }
        for name, (break_it, status) in cases.items():
            with self.subTest(case=name):
                self.setUp()
                break_it()

                self.assertEqual(self.gate.start(), status)

                self.assert_refused()
                self.assertEqual(self.denials(), {DenialCode.REPORT_MISSING})
                self.assertEqual(self.docker.containers, {})
                self.gate.close()

    def test_invalid_configuration_is_rejected(self) -> None:
        harness = self.harness
        cases = (
            {"workspace": object()},
            {"collector": None},
            {"max_age": timedelta(seconds=59)},
            {"max_age": 3600},
            {"now": None},
        )
        for changes in cases:
            with (
                self.subTest(changes=changes),
                self.assertRaises(QualificationError) as raised,
            ):
                self.make_gate(**changes)
            self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")
        for arguments in (
            (object(), harness.lifecycle, harness.profile),
            (harness.docker, object(), harness.profile),
            (harness.docker, harness.lifecycle, object()),
        ):
            with self.assertRaises(QualificationError):
                QualificationGate(
                    *arguments,
                    workspace=harness.workspace,
                    collector=harness.collector,
                    max_age=MAX_AGE,
                    now=harness.clock.now,
                )


class QualificationRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(self)
        self.docker = self.harness.docker
        self.lifecycle = self.harness.lifecycle
        self.clock = self.harness.clock
        self.gate = self.make_gate(
            lambda workspace: self.harness.collector(workspace=workspace)
        )

    def make_gate(self, collector) -> QualificationGate:
        gate = QualificationGate(
            self.docker,
            self.lifecycle,
            self.harness.profile,
            workspace=self.harness.workspace,
            collector=collector,
            max_age=MAX_AGE,
            now=self.clock.now,
        )
        self.addCleanup(gate.close)
        return gate

    def sentinels(self) -> list[str]:
        """Sentinel containers still in the inventory, oldest first."""
        return [
            cid
            for binding, _, _, cid in self.lifecycle.created
            if binding.sandbox_id.startswith("sentinel-")
            and cid in self.docker.containers
        ]

    def test_refresh_swaps_in_a_new_report_and_sentinel(self) -> None:
        self.assertEqual(self.gate.start(), "QUALIFICATION_PASSED")
        (old,) = self.sentinels()
        self.assertFalse(self.gate.refresh_due())
        self.clock.sleep(MAX_AGE.total_seconds() / 2)
        self.assertTrue(self.gate.refresh_due())
        before = len(self.lifecycle.destroyed)

        self.assertEqual(self.gate.refresh(), "QUALIFICATION_PASSED")

        (new,) = self.sentinels()
        self.assertNotEqual(new, old)
        destroyed = [cid for _, cid, _ in self.lifecycle.destroyed[before:]]
        # The new collection's sweep kept the sentinel in use until the swap.
        self.assertEqual(destroyed[-1], old)
        self.assertNotIn(old, destroyed[:-1])
        self.gate.require()
        self.assertFalse(self.gate.refresh_due())
        self.assertEqual(
            (self.harness.workspace.holds, self.harness.workspace.releases), (1, 0)
        )

    def test_a_refresh_that_fails_keeps_the_current_report_until_it_expires(
        self,
    ) -> None:
        self.gate.start()
        (old,) = self.sentinels()
        self.clock.sleep(MAX_AGE.total_seconds() / 2)
        self.docker.probe_output = b"probe=1\nend=1\n"

        self.assertEqual(
            self.gate.refresh(), "QUALIFICATION_UNAVAILABLE RUNTIME_UNAVAILABLE"
        )

        self.assertEqual(self.sentinels(), [old])
        self.gate.require()
        self.assertTrue(self.gate.refresh_due())
        self.clock.sleep(MAX_AGE.total_seconds() / 2)
        with self.assertRaises(DockerError):
            self.gate.require()

    def test_a_refreshed_report_that_fails_refuses_allocation(self) -> None:
        self.gate.start()
        self.clock.sleep(MAX_AGE.total_seconds() / 2)
        self.harness.cleanup.remove = False

        self.assertEqual(
            self.gate.refresh(), "QUALIFICATION_DENIED CHECK_FAILED:restart_cleanup"
        )

        with self.assertRaises(DockerError):
            self.gate.require()
        self.assertTrue(self.gate.refresh_due())
        self.assertEqual(len(self.sentinels()), 1)

    def test_refresh_is_due_without_a_usable_report(self) -> None:
        self.assertTrue(self.gate.refresh_due())
        self.gate.start()
        self.assertFalse(self.gate.refresh_due())

        self.docker.containers.pop(self.sentinels()[0])

        self.assertTrue(self.gate.refresh_due())

    def test_a_workspace_held_elsewhere_is_tried_again(self) -> None:
        self.harness.workspace.error = WorkspaceError("COLLECTION_IN_PROGRESS")
        self.assertEqual(
            self.gate.start(), "QUALIFICATION_UNAVAILABLE COLLECTION_IN_PROGRESS"
        )
        self.assertTrue(self.gate.refresh_due())

        self.harness.workspace.error = None

        self.assertEqual(self.gate.refresh(), "QUALIFICATION_PASSED")
        self.gate.require()
        self.assertEqual(self.harness.workspace.holds, 1)

    def test_close_waits_for_a_running_refresh(self) -> None:
        started, release = threading.Event(), threading.Event()
        harness = self.harness

        class Blocking:
            def __init__(self, workspace) -> None:
                self.inner = harness.collector(workspace=workspace)

            def collect(self, **options):
                if options.get("keep"):
                    started.set()
                    release.wait(5)
                return self.inner.collect(**options)

        gate = self.make_gate(Blocking)
        gate.start()
        statuses: list[str] = []
        refresh = threading.Thread(target=lambda: statuses.append(gate.refresh()))
        refresh.start()
        self.assertTrue(started.wait(5))

        closing = threading.Thread(target=gate.close)
        closing.start()
        closing.join(0.2)
        self.assertTrue(closing.is_alive())
        release.set()
        refresh.join(5)
        closing.join(5)

        self.assertFalse(closing.is_alive())
        self.assertEqual(statuses, ["QUALIFICATION_PASSED"])
        # The refresh retired the old sentinel and closing removed the new one.
        self.assertEqual(self.docker.containers, {})
        self.assertEqual(harness.workspace.releases, 1)
        self.assertEqual(
            gate.refresh(), "QUALIFICATION_UNAVAILABLE RUNTIME_UNAVAILABLE"
        )


class Gate:
    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed
        self.asked = 0

    def require(self) -> None:
        self.asked += 1
        if not self.allowed:
            raise DockerError("PROFILE_UNVERIFIED")


class GatedProvisioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(self)
        self.rooms = self.harness.rooms

    def test_gate_is_asked_before_the_room_is_opened(self) -> None:
        arguments = ("binding", "operation", "disk-full")
        refused = GatedProvisioningRuntime(self.rooms, Gate(False))
        with self.assertRaises(DockerError):
            refused.open(*arguments, lifetime="lifetime")
        self.assertEqual(self.rooms.opened, [])

        gate = Gate(True)
        with GatedProvisioningRuntime(self.rooms, gate).open(
            *arguments, lifetime="lifetime"
        ):
            pass
        self.assertEqual(gate.asked, 1)
        self.assertEqual(self.rooms.opened, [(*arguments, "lifetime")])

    def test_refused_room_fails_entry_without_docker_and_is_cleaned_up(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        database = Database(Path(temp.name) / "state.sqlite3", busy_timeout_ms=5000)
        database.initialize()
        backend, control = BackendStore(database), ControlPlaneStore(database)
        backend_identity = ServiceIdentity(
            "backend",
            Role.BACKEND,
            frozenset({Action.CREATE, Action.EXPIRE, Action.PUBLISH, Action.RECONCILE}),
        )
        control_identity = ServiceIdentity(
            "control",
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.RECONCILE, Action.TRANSITION}),
        )
        user = UserIdentity("learner", frozenset({"disk-full"}))
        clock = self.harness.clock
        entry = RoomEntryService(
            backend,
            LifecycleOrchestrator(
                backend, control, GatedProvisioningRuntime(self.rooms, Gate(False))
            ),
            backend_identity=backend_identity,
            control_identity=control_identity,
            attempt_ttl=timedelta(minutes=5),
            now=clock.now,
            rooms=RoomScenarioRegistry(),
        )

        with self.assertRaises(EntryError) as raised:
            entry.enter(user, "disk-full", key="enter")

        self.assertEqual(raised.exception.code, "ENTRY_FAILED")
        self.assertEqual(self.rooms.opened, [])
        LifecycleMaintenanceService(
            backend,
            DockerCleanupWorker(
                control,
                backend,
                self.harness.cleanup,
                retry_delay=timedelta(seconds=1),
            ),
            control_identity=control_identity,
            backend_identity=backend_identity,
            limit=10,
            now=clock.now,
        ).run_once()
        (target,) = self.harness.cleanup.targets
        attempt = backend.inspect(user, target.ref.attempt_id)
        self.assertEqual(attempt.state, "DESTROYED")
        self.assertIsNone(target.container_id)
        self.assertEqual(self.harness.docker.containers, {})


if __name__ == "__main__":
    unittest.main()
