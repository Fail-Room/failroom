import json
import tempfile
import unittest
from pathlib import Path

from failroom_sandbox.docker_cli import DockerError
from failroom_sandbox.models import Check, Outcome
from failroom_state import RuntimeCleanupError
from test_qualification_collector import Harness

from failroom_control_plane.qualification_restart import (
    RESTART_DIRECTORY,
    RestartCleanupError,
)


class RestartScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(self)
        self.docker = self.harness.docker
        self.rooms = self.harness.rooms
        self.cleanup = self.harness.cleanup
        self.workspace = self.harness.scratch
        self.directory = self.workspace / RESTART_DIRECTORY

    def begin(self):
        return self.harness.restart().begin(self.workspace)

    def finish(self, started=None):
        # A new scenario object: the restart must rely on the files alone.
        return self.harness.restart().finish(self.workspace, started)

    def binding(self) -> dict:
        return json.loads((self.directory / "binding.json").read_bytes())

    def assert_judgement(self, judgement, outcome, reason) -> None:
        self.assertIs(judgement.check, Check.RESTART_CLEANUP)
        self.assertEqual((judgement.outcome, judgement.reason), (outcome, reason))

    def test_abandoned_sandbox_removed_by_the_restart_passes(self) -> None:
        self.assertIsNone(self.begin())
        ((container_id, data),) = self.docker.containers.items()
        self.assertIs(data["State"]["Running"], True)
        binding = self.binding()
        labels = data["Config"]["Labels"]
        self.assertEqual(
            binding,
            {
                "attempt_id": labels["failroom.attempt_id"],
                "generation": 1,
                "sandbox_id": labels["failroom.sandbox_id"],
            },
        )

        judgement = self.finish()

        self.assert_judgement(judgement, Outcome.PASS, "")
        self.assertEqual(
            dict(judgement.facts),
            {
                "passes": 1,
                "failed_passes": 0,
                "attempt": "DESTROYED",
                "resource": "DESTROYED",
            },
        )
        (target,) = self.cleanup.targets
        self.assertEqual(target.container_id, container_id)
        self.assertGreaterEqual(self.harness.clock.value, 20)
        self.assertEqual(self.docker.containers, {})
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_sandbox_the_restart_leaves_fails_and_is_destroyed_directly(self) -> None:
        self.cleanup.remove = False
        self.begin()

        judgement = self.finish()

        self.assert_judgement(judgement, Outcome.FAIL, "CONTAINER_REMAINS")
        ((binding, container_id, operation_id),) = self.harness.lifecycle.destroyed
        self.assertEqual(binding.attempt_id, self.cleanup.targets[0].ref.attempt_id)
        self.assertEqual((container_id, operation_id), (None, None))
        self.assertEqual(self.docker.containers, {})
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_removal_the_store_never_records_fails(self) -> None:
        self.cleanup.error = RuntimeCleanupError("CLEANUP_INCOMPLETE")
        self.begin()

        judgement = self.finish()

        self.assert_judgement(judgement, Outcome.FAIL, "CLEANUP_NOT_RECORDED")
        self.assertNotEqual(judgement.facts["resource"], "DESTROYED")
        self.assertGreater(judgement.facts["passes"], 1)
        self.assertEqual(self.docker.containers, {})

    def test_room_that_never_ran_is_unverified_and_still_cleaned(self) -> None:
        cases = {
            "create": ("create_error", DockerError("RUNTIME_UNAVAILABLE"), 0),
            "start": ("start_error", DockerError("START_FAILED"), 1),
        }
        for name, (attribute, error, created) in cases.items():
            with self.subTest(phase=name):
                self.setUp()
                setattr(self.rooms, attribute, error)

                started = self.begin()

                self.assert_judgement(
                    started, Outcome.UNVERIFIED, "SANDBOX_NOT_PROVISIONED"
                )
                self.assertEqual(len(self.docker.containers), created)
                self.assertIs(self.finish(started), started)
                self.assertEqual(self.docker.containers, {})
                self.assertEqual(list(self.workspace.iterdir()), [])

    def test_unreadable_store_still_proves_the_sandbox_absent(self) -> None:
        self.begin()
        for path in self.directory.glob("restart.sqlite3*"):
            path.unlink()

        judgement = self.finish()

        self.assert_judgement(judgement, Outcome.FAIL, "CONTAINER_REMAINS")
        self.assertEqual(judgement.facts["attempt"], "UNREADABLE")
        self.assertEqual(self.docker.containers, {})
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_state_without_a_binding_made_no_docker_call(self) -> None:
        self.directory.mkdir()
        (self.directory / "restart.sqlite3").write_bytes(b"")
        (self.directory / "binding.json.tmp").write_bytes(b"{")

        self.assertIsNone(self.harness.restart().recover(self.workspace))

        self.assertEqual(self.docker.filters, [])
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.assertIsNone(self.harness.restart().recover(self.workspace))

    def test_state_is_kept_while_absence_cannot_be_shown(self) -> None:
        cases = {
            "malformed binding": lambda: (self.directory / "binding.json").write_bytes(
                b'{"attempt_id": "x"}'
            ),
            "inventory unavailable": lambda: setattr(
                self.docker, "list_error", DockerError("RUNTIME_UNAVAILABLE")
            ),
            "removal refused": lambda: (
                setattr(self.cleanup, "remove", False),
                setattr(self.harness.lifecycle, "refuse_rooms", True),
            ),
        }
        for name, break_it in cases.items():
            with self.subTest(case=name):
                self.setUp()
                self.begin()
                break_it()

                with self.assertRaises(RestartCleanupError):
                    self.finish()

                self.assertTrue((self.directory / "binding.json").is_file())

    def test_binding_must_name_exact_identifiers(self) -> None:
        valid = {
            "attempt_id": "3f0b7d5e-8a51-4c8f-9e0b-2d4c6a8e1f35",
            "generation": 1,
            "sandbox_id": "6c1e9a7b-2f43-4d5e-8a9b-0c1d2e3f4a5b",
        }
        cases = (
            {**valid, "attempt_id": "qualification"},
            {**valid, "sandbox_id": "6C1E9A7B-2F43-4D5E-8A9B-0C1D2E3F4A5B"},
            {**valid, "generation": 0},
            {**valid, "generation": True},
            {**valid, "extra": 1},
            {key: value for key, value in valid.items() if key != "generation"},
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.setUp()
                self.directory.mkdir()
                (self.directory / "binding.json").write_bytes(
                    json.dumps(payload).encode()
                )
                with self.assertRaises(RestartCleanupError):
                    self.harness.restart().recover(self.workspace)
                self.assertEqual(self.docker.filters, [])

        self.setUp()
        self.directory.mkdir()
        (self.directory / "binding.json").write_bytes(b" " * 513)
        with self.assertRaises(RestartCleanupError):
            self.harness.restart().recover(self.workspace)

    def test_begin_refuses_state_it_did_not_recover(self) -> None:
        self.directory.mkdir()

        with self.assertRaises(FileExistsError):
            self.begin()

        self.assertEqual(self.rooms.opened, [])


class EmptyWorkspaceTests(unittest.TestCase):
    def test_nothing_to_recover(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            harness = Harness(self)
            self.assertIsNone(harness.restart().recover(Path(name)))
            self.assertEqual(harness.docker.filters, [])


if __name__ == "__main__":
    unittest.main()
