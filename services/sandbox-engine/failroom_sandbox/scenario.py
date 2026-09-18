"""Narrow declarative contracts for trusted sandbox scenario bootstrap."""

from dataclasses import dataclass
from typing import Final

__all__ = (
    "DISK_FULL_FILLER_PATH",
    "DISK_FULL_TARGET_WORKING_SET_BYTES",
    "DiskFullScenario",
    "ScenarioError",
    "parse_disk_full_scenario",
)

DISK_FULL_FILLER_PATH: Final = "/workspace/.failroom-disk-full"
DISK_FULL_TARGET_WORKING_SET_BYTES: Final = 8_000_000
_VERSION: Final = "disk-full-v1"
_FIELDS: Final = frozenset(
    {"version", "filler_bytes", "recovery_free_bytes", "target_working_set_bytes"}
)


class ScenarioError(ValueError):
    """Fixed scenario declaration denial without untrusted field details."""

    def __init__(self) -> None:
        super().__init__("INVALID_SCENARIO")


@dataclass(frozen=True)
class DiskFullScenario:
    """Validated fixed-path storage exhaustion contract for one sandbox."""

    filler_path: str
    filler_bytes: int
    recovery_free_bytes: int
    target_working_set_bytes: int


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def parse_disk_full_scenario(
    declaration: object, *, workspace_bytes: int
) -> DiskFullScenario:
    """Accept only a bounded, data-only Disk Full scenario declaration."""

    if type(declaration) is not dict or not _positive(workspace_bytes):
        raise ScenarioError()
    if set(declaration) != _FIELDS or declaration.get("version") != _VERSION:
        raise ScenarioError()
    filler_value = declaration.get("filler_bytes")
    recovery_value = declaration.get("recovery_free_bytes")
    target_working_set_value = declaration.get("target_working_set_bytes")
    if (
        type(filler_value) is not int
        or type(recovery_value) is not int
        or type(target_working_set_value) is not int
        or not _positive(filler_value)
        or not _positive(recovery_value)
        or not _positive(target_working_set_value)
    ):
        raise ScenarioError()
    filler_bytes = int(filler_value)
    recovery_free_bytes = int(recovery_value)
    target_working_set_bytes = int(target_working_set_value)
    if (
        filler_bytes <= 0
        or recovery_free_bytes <= 0
        or filler_bytes >= workspace_bytes
        or recovery_free_bytes >= workspace_bytes
        or target_working_set_bytes >= workspace_bytes
        or target_working_set_bytes != DISK_FULL_TARGET_WORKING_SET_BYTES
        or target_working_set_bytes > recovery_free_bytes
        or filler_bytes + recovery_free_bytes < workspace_bytes
    ):
        raise ScenarioError()
    return DiskFullScenario(
        DISK_FULL_FILLER_PATH,
        filler_bytes,
        recovery_free_bytes,
        target_working_set_bytes,
    )
