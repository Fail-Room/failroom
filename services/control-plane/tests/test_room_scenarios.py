import unittest

from failroom_sandbox.scenario import DiskFullScenario

from failroom_control_plane.room_scenarios import RoomScenarioRegistry


class RoomScenarioRegistryTests(unittest.TestCase):
    def test_resolves_only_the_fixed_disk_full_room(self) -> None:
        registry = RoomScenarioRegistry()

        scenario = registry.resolve("disk-full", workspace_bytes=67_108_864)

        self.assertEqual(
            scenario,
            DiskFullScenario(
                filler_path="/workspace/.failroom-disk-full",
                filler_bytes=60_000_000,
                recovery_free_bytes=8_000_000,
                target_working_set_bytes=8_000_000,
                target_ready_timeout_seconds=5,
            ),
        )
        self.assertIsNone(registry.resolve("room-1", workspace_bytes=67_108_864))

    def test_reports_only_reviewed_room_ids(self) -> None:
        registry = RoomScenarioRegistry()

        self.assertTrue(registry.is_reviewed("disk-full"))
        for room_id in ("room-1", "", "DISK-FULL", "disk-full ", "disk_full", None, 1):
            with self.subTest(room_id=room_id):
                self.assertFalse(registry.is_reviewed(room_id))

    def test_rejects_an_insufficient_workspace_without_fallback(self) -> None:
        registry = RoomScenarioRegistry()

        with self.assertRaisesRegex(ValueError, "^INVALID_SCENARIO$"):
            registry.resolve("disk-full", workspace_bytes=60_000_000)


if __name__ == "__main__":
    unittest.main()
