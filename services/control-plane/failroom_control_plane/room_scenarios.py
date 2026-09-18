"""Trusted, data-only Room-to-scenario selection."""

from failroom_sandbox.scenario import DiskFullScenario, parse_disk_full_scenario

__all__ = ("RoomScenarioRegistry",)


_DISK_FULL_DECLARATION = {
    "version": "disk-full-v1",
    "filler_bytes": 60_000_000,
    "recovery_free_bytes": 8_000_000,
    "target_working_set_bytes": 8_000_000,
}


class RoomScenarioRegistry:
    """Resolve only reviewed Room IDs to declarative trusted scenarios."""

    def resolve(
        self, room_id: str, *, workspace_bytes: int
    ) -> DiskFullScenario | None:
        if room_id != "disk-full":
            return None
        return parse_disk_full_scenario(
            _DISK_FULL_DECLARATION, workspace_bytes=workspace_bytes
        )
