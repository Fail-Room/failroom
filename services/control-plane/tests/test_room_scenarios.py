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
            ),
        )
        self.assertIsNone(registry.resolve("room-1", workspace_bytes=67_108_864))

    def test_rejects_an_insufficient_workspace_without_fallback(self) -> None:
        registry = RoomScenarioRegistry()

        with self.assertRaisesRegex(ValueError, "^INVALID_SCENARIO$"):
            registry.resolve("disk-full", workspace_bytes=60_000_000)


if __name__ == "__main__":
    unittest.main()
