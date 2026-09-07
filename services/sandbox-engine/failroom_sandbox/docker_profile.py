"""Compile a fail-closed Docker create profile without invoking Docker.

The trusted control plane owns these values. This module validates explicit,
immutable configuration and returns argv tokens only; it does not allocate,
inspect, or mutate a Docker resource.
"""

import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal

from .fingerprints import configuration_digest

__all__ = (
    "StrictDockerProfile",
    "DockerBinding",
    "ProfileConfigurationError",
    "compile_create_argv",
    "profile_fingerprint",
)

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"@sha256:[0-9a-f]{64}"
)
_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9_.-]{0,61}[a-z0-9])?")
_ABSOLUTE_PATH = re.compile(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+")


class ProfileConfigurationError(ValueError):
    """A safe, code-owned rejection of a Docker profile or binding."""


@dataclass(frozen=True)
class DockerBinding:
    """Backend-preallocated identifiers bound to one Docker create operation."""

    attempt_id: str
    sandbox_id: str
    generation: int

    def __post_init__(self) -> None:
        _validate_binding(self)


@dataclass(frozen=True)
class StrictDockerProfile:
    """Every profile value that affects isolation or bounded execution is explicit."""

    image: str
    uid: int
    gid: int
    seccomp_path: str
    seccomp_digest: str
    cpu_limit: Decimal
    memory_limit_bytes: int
    memory_swap_limit_bytes: int
    pids_limit: int
    workspace_tmpfs_bytes: int
    temp_tmpfs_bytes: int
    shm_size_bytes: int
    fd_limit: int
    io_device_path: str
    io_read_bps: int
    io_write_bps: int
    terminal_output_limit_bytes: int
    connection_limit: int
    session_limit: int
    absolute_ttl_seconds: int

    def __post_init__(self) -> None:
        _validate_profile(self)


def _is_positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _is_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _is_absolute_path(value: object) -> bool:
    return (
        type(value) is str
        and _ABSOLUTE_PATH.fullmatch(value) is not None
        and all(component not in (".", "..") for component in value.split("/")[1:])
    )


def _is_image(value: object) -> bool:
    return type(value) is str and _IMAGE.fullmatch(value) is not None


def _is_cpu_limit(value: object) -> bool:
    return _cpu_nanocpus(value) is not None


def _cpu_nanocpus(value: object) -> int | None:
    """Convert exactly without Decimal context rounding or exponent expansion."""
    if type(value) is not Decimal or not value.is_finite():
        return None
    sign, digits, exponent = value.as_tuple()
    if sign or not isinstance(exponent, int):
        return None
    significant = len(digits)
    while significant and digits[significant - 1] == 0:
        significant -= 1
        exponent += 1
    shift = exponent + 9
    if not significant or shift < 0 or significant + shift > 19:
        return None
    coefficient = 0
    for digit in digits[:significant]:
        coefficient = coefficient * 10 + digit
    nanocpus = coefficient
    for _ in range(shift):
        nanocpus *= 10
    if not 10_000_000 <= nanocpus <= 9_223_372_036_854_775_807:
        return None
    return nanocpus


def _cpu_argv(value: Decimal) -> str:
    nanocpus = _cpu_nanocpus(value)
    if nanocpus is None:
        raise ProfileConfigurationError("INVALID_DOCKER_PROFILE")
    whole, fractional = divmod(nanocpus, 1_000_000_000)
    if not fractional:
        return str(whole)
    return str(whole) + "." + f"{fractional:09d}".rstrip("0")


def _validate_binding(binding: object) -> None:
    if (
        type(binding) is not DockerBinding
        or not _is_identifier(binding.attempt_id)
        or not _is_identifier(binding.sandbox_id)
        or not _is_positive_int(binding.generation)
    ):
        raise ProfileConfigurationError("INVALID_DOCKER_BINDING")


def _validate_profile(profile: object) -> None:
    if type(profile) is not StrictDockerProfile:
        raise ProfileConfigurationError("INVALID_DOCKER_PROFILE")
    if not (
        _is_image(profile.image)
        and _is_positive_int(profile.uid)
        and _is_positive_int(profile.gid)
        and _is_absolute_path(profile.seccomp_path)
        and _is_sha256(profile.seccomp_digest)
        and _is_cpu_limit(profile.cpu_limit)
        and _is_positive_int(profile.memory_limit_bytes)
        and _is_positive_int(profile.memory_swap_limit_bytes)
        and profile.memory_limit_bytes == profile.memory_swap_limit_bytes
        and _is_positive_int(profile.pids_limit)
        and _is_positive_int(profile.workspace_tmpfs_bytes)
        and _is_positive_int(profile.temp_tmpfs_bytes)
        and _is_positive_int(profile.shm_size_bytes)
        and _is_positive_int(profile.fd_limit)
        and _is_absolute_path(profile.io_device_path)
        and _is_positive_int(profile.io_read_bps)
        and _is_positive_int(profile.io_write_bps)
        and _is_positive_int(profile.terminal_output_limit_bytes)
        and _is_positive_int(profile.connection_limit)
        and _is_positive_int(profile.session_limit)
        and _is_positive_int(profile.absolute_ttl_seconds)
    ):
        raise ProfileConfigurationError("INVALID_DOCKER_PROFILE")


def _validate_operation_id(operation_id: object) -> None:
    if not _is_identifier(operation_id):
        raise ProfileConfigurationError("INVALID_DOCKER_OPERATION")


def _profile_configuration(profile: StrictDockerProfile) -> dict[str, object]:
    """Return every profile field and fixed Docker setting for fingerprinting."""
    return {
        "schema": "failroom.strict-docker-profile.v1",
        "image": profile.image,
        "identity": {"uid": profile.uid, "gid": profile.gid},
        "seccomp": {"path": profile.seccomp_path, "digest": profile.seccomp_digest},
        "docker": {
            "network": "none",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_options": [
                "no-new-privileges",
                "seccomp=" + profile.seccomp_path,
            ],
            "pid_namespace": "",
            "ipc_namespace": "private",
            "cgroup_namespace": "private",
            "restart": "no",
            "log_driver": "none",
            "runtime": "runc",
            "entrypoint": "/bin/sleep",
            "healthcheck_disabled": True,
            "pull_policy": "never",
            "memory_limit_bytes": profile.memory_limit_bytes,
            "memory_swap_limit_bytes": profile.memory_swap_limit_bytes,
            "pids_limit": profile.pids_limit,
            "cpu_limit": _cpu_argv(profile.cpu_limit),
            "tmpfs": {
                "workspace": {
                    "path": "/workspace",
                    "size_bytes": profile.workspace_tmpfs_bytes,
                    "options": ["rw", "nosuid", "nodev", "noexec"],
                },
                "temp": {
                    "path": "/tmp",
                    "size_bytes": profile.temp_tmpfs_bytes,
                    "options": ["rw", "nosuid", "nodev", "noexec"],
                },
            },
            "shm_size_bytes": profile.shm_size_bytes,
            "ulimits": {
                "nofile": {"soft": profile.fd_limit, "hard": profile.fd_limit},
                "core": {"soft": 0, "hard": 0},
            },
            "io": {
                "device_path": profile.io_device_path,
                "read_bps": profile.io_read_bps,
                "write_bps": profile.io_write_bps,
            },
            "command": ["60"],
        },
        "terminal_output_limit_bytes": profile.terminal_output_limit_bytes,
        "connection_limit": profile.connection_limit,
        "session_limit": profile.session_limit,
        "absolute_ttl_seconds": profile.absolute_ttl_seconds,
    }


def profile_fingerprint(profile: StrictDockerProfile) -> str:
    """Fingerprint the complete immutable profile using the shared canonical hash."""
    _validate_profile(profile)
    return configuration_digest(_profile_configuration(profile))


def _container_name(binding: DockerBinding, operation_id: str) -> str:
    canonical_binding = "\x00".join(
        (
            binding.attempt_id,
            binding.sandbox_id,
            str(binding.generation),
            operation_id,
        )
    )
    return (
        "failroom-diagnostic-"
        + hashlib.sha256(canonical_binding.encode("ascii")).hexdigest()
    )


def compile_create_argv(
    profile: StrictDockerProfile,
    binding: DockerBinding,
    operation_id: str,
) -> tuple[str, ...]:
    """Build fixed Docker CLI argv without executing the command.

    Binding and operation identifiers are independently validated before being
    incorporated into labels or the deterministic container name.
    """
    _validate_profile(profile)
    _validate_binding(binding)
    _validate_operation_id(operation_id)
    return (
        "docker",
        "container",
        "create",
        "--name",
        _container_name(binding, operation_id),
        "--label",
        "failroom.kind=diagnostic",
        "--label",
        "failroom.attempt_id=" + binding.attempt_id,
        "--label",
        "failroom.sandbox_id=" + binding.sandbox_id,
        "--label",
        "failroom.generation=" + str(binding.generation),
        "--label",
        "failroom.operation_id=" + operation_id,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        "seccomp=" + profile.seccomp_path,
        "--pid",
        "",
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--restart",
        "no",
        "--log-driver",
        "none",
        "--runtime",
        "runc",
        "--entrypoint",
        "/bin/sleep",
        "--no-healthcheck",
        "--pull",
        "never",
        "--user",
        str(profile.uid) + ":" + str(profile.gid),
        "--memory",
        str(profile.memory_limit_bytes),
        "--memory-swap",
        str(profile.memory_swap_limit_bytes),
        "--pids-limit",
        str(profile.pids_limit),
        "--cpus",
        _cpu_argv(profile.cpu_limit),
        "--tmpfs",
        "/workspace:rw,size="
        + str(profile.workspace_tmpfs_bytes)
        + ",nosuid,nodev,noexec",
        "--tmpfs",
        "/tmp:rw,size=" + str(profile.temp_tmpfs_bytes) + ",nosuid,nodev,noexec",
        "--shm-size",
        str(profile.shm_size_bytes),
        "--ulimit",
        "nofile=" + str(profile.fd_limit) + ":" + str(profile.fd_limit),
        "--ulimit",
        "core=0:0",
        "--device-read-bps",
        profile.io_device_path + ":" + str(profile.io_read_bps),
        "--device-write-bps",
        profile.io_device_path + ":" + str(profile.io_write_bps),
        profile.image,
        "60",
    )
