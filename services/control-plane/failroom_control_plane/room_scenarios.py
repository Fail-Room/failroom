"""Trusted, data-only Room-to-scenario selection."""

from typing import Final

from failroom_sandbox.scenario import (
    DISK_FULL_TARGET_READY_TIMEOUT_SECONDS,
    DiskFullScenario,
    parse_disk_full_scenario,
)

__all__ = ("RoomScenarioRegistry",)


_DISK_FULL_ROOM_ID: Final = "disk-full"
# A Room is a reviewed scenario; IDs without one are not enterable Rooms.
_REVIEWED_ROOM_IDS: Final = frozenset({_DISK_FULL_ROOM_ID})
_DISK_FULL_DECLARATION = {
    "version": "disk-full-v1",
    "filler_bytes": 60_000_000,
    "recovery_free_bytes": 8_000_000,
    "target_working_set_bytes": 8_000_000,
    "target_ready_timeout_seconds": DISK_FULL_TARGET_READY_TIMEOUT_SECONDS,
}


class RoomScenarioRegistry:
    """Resolve only reviewed Room IDs to declarative trusted scenarios."""

    def is_reviewed(self, room_id: object) -> bool:
        """Report whether an ID names a reviewed Room, without parsing it."""
        return type(room_id) is str and room_id in _REVIEWED_ROOM_IDS

    def resolve(self, room_id: str, *, workspace_bytes: int) -> DiskFullScenario | None:
        if room_id != _DISK_FULL_ROOM_ID:
            return None
        return parse_disk_full_scenario(
            _DISK_FULL_DECLARATION, workspace_bytes=workspace_bytes
        )
