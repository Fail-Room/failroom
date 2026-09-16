import unittest
from dataclasses import FrozenInstanceError

from failroom_sandbox.scenario import (
    DISK_FULL_FILLER_PATH,
    DiskFullScenario,
    ScenarioError,
    parse_disk_full_scenario,
)


class DiskFullScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace_bytes = 67_108_864
        self.declaration = {
            "version": "disk-full-v1",
            "filler_bytes": 60_000_000,
            "recovery_free_bytes": 8_000_000,
        }

    def test_parses_the_fixed_minimal_declaration(self) -> None:
        scenario = parse_disk_full_scenario(
            self.declaration, workspace_bytes=self.workspace_bytes
        )

        self.assertEqual(
            scenario,
            DiskFullScenario(
                filler_path=DISK_FULL_FILLER_PATH,
                filler_bytes=60_000_000,
                recovery_free_bytes=8_000_000,
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            scenario.filler_bytes = 1

    def test_rejects_executable_or_unbounded_declaration_fields(self) -> None:
        invalid = (
            {**self.declaration, "command": "rm -rf /"},
            {**self.declaration, "filler_path": "/tmp/fill"},
            {**self.declaration, "filler_bytes": 0},
            {**self.declaration, "filler_bytes": self.workspace_bytes},
            {**self.declaration, "recovery_free_bytes": 0},
            {**self.declaration, "recovery_free_bytes": self.workspace_bytes},
            {"version": "disk-full-v1", "filler_bytes": 60_000_000},
            {**self.declaration, "version": "disk-full-v2"},
        )

        for declaration in invalid:
            with self.subTest(declaration=declaration):
                with self.assertRaisesRegex(ScenarioError, "^INVALID_SCENARIO$"):
                    parse_disk_full_scenario(
                        declaration, workspace_bytes=self.workspace_bytes
                    )


if __name__ == "__main__":
    unittest.main()
