"""Operator diagnostic lifecycle only; this module never admits learner Rooms."""

import hashlib
import json
import re
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from .docker_cli import DockerCli, DockerError
from .docker_profile import (
    DockerBinding,
    StrictDockerProfile,
    _cpu_nanocpus,
    compile_create_argv,
    profile_fingerprint,
)
from .fingerprints import configuration_digest
from .models import QualificationContext, QualificationReport
from .qualification import require_qualified_profile


class PolicyStore(Protocol):
    def pin(
        self, source_path: str, expected_digest: str
    ) -> AbstractContextManager[str]: ...


@dataclass(frozen=True)
class ContainerObservation:
    container_id: str
    running: bool
    evidence_digest: str


@dataclass(frozen=True)
class CreatedContainer:
    container_id: str
    running: bool


def _object(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise DockerError("INVALID_DOCKER_RESPONSE")
    return value


def _empty(value: object) -> bool:
    return value is None or value == {} or value == []


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _json_document(raw: bytes | str) -> object:
    return json.loads(
        raw,
        object_pairs_hook=_unique_json_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
    )


def _seccomp_option_matches(option: str, pinned_path: str) -> bool:
    if option == "seccomp=" + pinned_path:
        return True
    prefix = "seccomp="
    if not option.startswith(prefix):
        return False
    try:
        with open(pinned_path, "rb") as policy_file:
            expected = _json_document(policy_file.read())
        observed = _json_document(option.removeprefix(prefix))
    except (OSError, ValueError, UnicodeError, RecursionError):
        return False
    return type(expected) is dict and type(observed) is dict and observed == expected


def _labels(binding: DockerBinding) -> dict[str, str]:
    # Revalidate a trusted input before constructing Docker selectors.
    DockerBinding(binding.attempt_id, binding.sandbox_id, binding.generation)
    return {
        "failroom.kind": "diagnostic",
        "failroom.attempt_id": binding.attempt_id,
        "failroom.sandbox_id": binding.sandbox_id,
        "failroom.generation": str(binding.generation),
    }


def _owned(
    data: dict[str, object],
    binding: DockerBinding,
    cid: str,
    operation_id: str | None = None,
) -> None:
    labels = _object(_object(data.get("Config")).get("Labels"))
    operation = labels.get("failroom.operation_id")
    if (
        data.get("Id") != cid
        or type(operation) is not str
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9_.-]{0,61}[a-z0-9])?", operation) is None
        or any(labels.get(key) != value for key, value in _labels(binding).items())
        or (operation_id is not None and operation != operation_id)
    ):
        raise DockerError("OWNERSHIP_MISMATCH")
    # Bind the create operation label to the deterministic resource name as well.
    digest = hashlib.sha256(
        "\x00".join(
            (binding.attempt_id, binding.sandbox_id, str(binding.generation), operation)
        ).encode("ascii")
    ).hexdigest()
    if data.get("Name") != "/failroom-diagnostic-" + digest:
        raise DockerError("OWNERSHIP_MISMATCH")


def _cleanable_mounts(data: dict[str, object]) -> set[str]:
    config, host = _object(data.get("Config")), _object(data.get("HostConfig"))
    if "Volumes" not in config or not _empty(config["Volumes"]):
        raise DockerError("CLEANUP_INCOMPLETE")
    for key in ("Binds", "VolumesFrom"):
        if key not in host or not _empty(host[key]):
            raise DockerError("CLEANUP_INCOMPLETE")
    # Docker Desktop omits the nullable HostConfig.Mounts field when it is
    # empty; a present non-empty value remains forbidden.
    if "Mounts" in host and not _empty(host["Mounts"]):
        raise DockerError("CLEANUP_INCOMPLETE")
    mounts = data.get("Mounts")
    if type(mounts) is not list:
        raise DockerError("CLEANUP_INCOMPLETE")
    destinations: set[str] = set()
    for raw in mounts:
        mount = _object(raw)
        dest = mount.get("Destination")
        if (
            mount.get("Type") != "tmpfs"
            or dest not in ("/workspace", "/tmp")
            or mount.get("Source") not in ("", None)
            or dest in destinations
        ):
            raise DockerError("CLEANUP_INCOMPLETE")
        destinations.add(str(dest))
    if not destinations:
        # Docker Desktop omits tmpfs entries from the top-level Mounts list.
        # HostConfig.Tmpfs remains the authoritative daemon response for these
        # anonymous in-memory mounts when no host-backed mount fields are set.
        tmpfs = host.get("Tmpfs")
        if (
            type(tmpfs) is dict
            and set(tmpfs) == {"/workspace", "/tmp"}
            and all(type(value) is str for value in tmpfs.values())
        ):
            destinations = set(tmpfs)
    return destinations


def _safe_mounts(data: dict[str, object]) -> None:
    if _cleanable_mounts(data) != {"/workspace", "/tmp"}:
        raise DockerError("CLEANUP_INCOMPLETE")


def _verify_profile(
    data: dict[str, object],
    profile: StrictDockerProfile,
    image: dict[str, object],
    pinned_seccomp_path: str,
) -> None:
    _safe_mounts(data)
    host, config = _object(data.get("HostConfig")), _object(data.get("Config"))
    nanocpus = _cpu_nanocpus(profile.cpu_limit)
    if nanocpus is None:
        raise DockerError("PROFILE_UNVERIFIED")
    expected: dict[str, object] = {
        "Privileged": False,
        "ReadonlyRootfs": True,
        "NetworkMode": "none",
        "CapDrop": ["ALL"],
        "PidMode": "",
        "IpcMode": "private",
        "CgroupnsMode": "private",
        "Runtime": "runc",
        "PublishAllPorts": False,
        "Memory": profile.memory_limit_bytes,
        "MemorySwap": profile.memory_swap_limit_bytes,
        "NanoCpus": nanocpus,
        "PidsLimit": profile.pids_limit,
        "ShmSize": profile.shm_size_bytes,
        "Tmpfs": {
            "/workspace": f"rw,size={profile.workspace_tmpfs_bytes},nosuid,nodev,noexec",
            "/tmp": f"rw,size={profile.temp_tmpfs_bytes},nosuid,nodev,noexec",
        },
        "BlkioDeviceReadBps": [
            {"Path": profile.io_device_path, "Rate": profile.io_read_bps}
        ],
        "BlkioDeviceWriteBps": [
            {"Path": profile.io_device_path, "Rate": profile.io_write_bps}
        ],
    }
    for key, value in expected.items():
        if type(host.get(key)) is not type(value) or host[key] != value:
            raise DockerError("PROFILE_UNVERIFIED")
    for key in (
        "CapAdd",
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "PortBindings",
        "Links",
    ):
        if key not in host or not _empty(host[key]):
            raise DockerError("PROFILE_UNVERIFIED")
    if (
        data.get("Image") != image["Id"]
        or config.get("Image") != profile.image
        or config.get("User") != f"{profile.uid}:{profile.gid}"
        or config.get("Entrypoint") != ["/bin/sleep"]
        or config.get("Cmd") != ["60"]
        or _object(config.get("Healthcheck")).get("Test") != ["NONE"]
        or config.get("Env") != _object(image.get("Config")).get("Env")
        or _object(host.get("RestartPolicy")).get("Name") != "no"
        or _object(host.get("LogConfig")).get("Type") != "none"
    ):
        raise DockerError("PROFILE_UNVERIFIED")
    ulimits = host.get("Ulimits")
    if type(ulimits) is not list or sorted(
        ulimits, key=lambda x: str(_object(x).get("Name"))
    ) != [
        {"Name": "core", "Soft": 0, "Hard": 0},
        {"Name": "nofile", "Soft": profile.fd_limit, "Hard": profile.fd_limit},
    ]:
        raise DockerError("PROFILE_UNVERIFIED")
    options = host.get("SecurityOpt")
    if (
        type(options) is not list
        or len(options) != 2
        or any(type(option) is not str for option in options)
        or options.count("no-new-privileges") != 1
        or len([option for option in options if option != "no-new-privileges"]) != 1
        or not _seccomp_option_matches(
            next(option for option in options if option != "no-new-privileges"),
            pinned_seccomp_path,
        )
    ):
        raise DockerError("PROFILE_UNVERIFIED")


def _verified_image(cli: DockerCli, profile: StrictDockerProfile) -> dict[str, object]:
    image = cli.inspect_image(profile.image)
    image_config = _object(image.get("Config"))
    digests = image.get("RepoDigests")
    volumes = image_config.get("Volumes")
    if (
        image.get("Os") != "linux"
        or type(image.get("Id")) is not str
        or re.fullmatch(r"sha256:[a-f0-9]{64}", str(image["Id"])) is None
        or type(digests) is not list
        or profile.image not in digests
        or ("Volumes" in image_config and (not _empty(volumes) or volumes == []))
        or "Env" not in image_config
    ):
        raise DockerError("IMAGE_UNVERIFIED")
    return image


class PreparedDockerOperation:
    def __init__(
        self,
        lifecycle: "DockerDiagnosticLifecycle",
        profile: StrictDockerProfile,
        binding: DockerBinding,
        operation_id: str,
        image: dict[str, object],
        pinned: str,
    ) -> None:
        self._lifecycle = lifecycle
        self._profile = profile
        self._binding = binding
        self._operation_id = operation_id
        self._image = image
        self._pinned = pinned
        self._argv = tuple(
            "seccomp=" + pinned if arg == "seccomp=" + profile.seccomp_path else arg
            for arg in compile_create_argv(profile, binding, operation_id)
        )
        self._cleanup_id: str | None = None

    def create_verified(self) -> CreatedContainer:
        name = self._argv[4]
        data = self._lifecycle._cli.inspect_container(name)
        if data is None:
            cid = self._lifecycle._cli.create(self._argv)
            self._cleanup_id = cid
            data = self._lifecycle._cli.inspect_container(cid)
            if data is None:
                raise DockerError("PROFILE_UNVERIFIED")
        else:
            raw_cid = data.get("Id")
            if type(raw_cid) is not str:
                raise DockerError("OWNERSHIP_MISMATCH")
            cid = raw_cid
        _owned(data, self._binding, cid, self._operation_id)
        _verify_profile(data, self._profile, self._image, self._pinned)
        state = _object(data.get("State"))
        if state.get("Running") is not True and state.get("Status") != "created":
            raise DockerError("PROFILE_UNVERIFIED")
        return CreatedContainer(cid, state.get("Running") is True)

    def start_verified(self, created: CreatedContainer) -> ContainerObservation:
        data = self._lifecycle._inspect_exact_created(self, created.container_id)
        if not created.running:
            try:
                self._lifecycle._cli.start(created.container_id)
            except DockerError:
                # A daemon may have started the container before the response
                # was lost. Reconcile exact ownership before retrying anything.
                data = self._lifecycle._inspect_exact_created(
                    self, created.container_id
                )
            else:
                data = self._lifecycle._inspect_exact_created(
                    self, created.container_id
                )
        if _object(data.get("State")).get("Running") is not True:
            raise DockerError("PROFILE_UNVERIFIED")
        return ContainerObservation(
            created.container_id,
            True,
            self._lifecycle._running_evidence(self, data),
        )

    def cleanup_after_failure(self) -> None:
        if self._cleanup_id is None:
            return
        try:
            self._lifecycle.destroy(
                self._binding, self._cleanup_id, operation_id=self._operation_id
            )
        except DockerError:
            pass


class DockerDiagnosticLifecycle:
    """Called only by a trusted operator/controller with preallocated identifiers.

    Labels locate resources; they are not authentication. No HTTP or learner
    caller may use this primitive directly. A failed create must retain its
    binding for reconciliation because a timed-out daemon call may finish later.
    """

    def __init__(self, cli: DockerCli, policies: PolicyStore) -> None:
        self._cli = cli
        self._policies = policies

    def _inspect_exact_created(
        self, operation: PreparedDockerOperation, cid: str
    ) -> dict[str, object]:
        data = self._cli.inspect_container(cid)
        if data is None:
            raise DockerError("PROFILE_UNVERIFIED")
        _owned(data, operation._binding, cid, operation._operation_id)
        _verify_profile(data, operation._profile, operation._image, operation._pinned)
        return data

    def _running_evidence(
        self, operation: PreparedDockerOperation, data: dict[str, object]
    ) -> str:
        return configuration_digest(
            {
                "schema": "failroom.diagnostic-running.v1",
                "context": self._cli.context,
                "labels": {
                    **_labels(operation._binding),
                    "failroom.operation_id": operation._operation_id,
                },
                "image_id": operation._image["Id"],
                "profile": profile_fingerprint(operation._profile),
                "container_id": data["Id"],
                "running": True,
            }
        )

    @contextmanager
    def prepare(
        self,
        profile: StrictDockerProfile,
        binding: DockerBinding,
        operation_id: str,
    ) -> Iterator[PreparedDockerOperation]:
        image = _verified_image(self._cli, profile)
        with self._policies.pin(profile.seccomp_path, profile.seccomp_digest) as pinned:
            operation = PreparedDockerOperation(
                self, profile, binding, operation_id, image, pinned
            )
            try:
                yield operation
            except Exception:
                operation.cleanup_after_failure()
                raise

    def create_diagnostic(
        self, profile: StrictDockerProfile, binding: DockerBinding, operation_id: str
    ) -> ContainerObservation:
        with self.prepare(profile, binding, operation_id) as operation:
            return operation.start_verified(operation.create_verified())

    def destroy(
        self,
        binding: DockerBinding,
        container_id: str | None,
        *,
        operation_id: str | None = None,
    ) -> str:
        labels = _labels(binding)
        if operation_id is not None:
            if (
                type(operation_id) is not str
                or re.fullmatch(r"[a-z0-9](?:[a-z0-9_.-]{0,61}[a-z0-9])?", operation_id)
                is None
            ):
                raise DockerError("INVALID_DOCKER_REQUEST")
            labels["failroom.operation_id"] = operation_id
        filters = tuple("label=" + key + "=" + value for key, value in labels.items())
        candidates = self._cli.list_containers(filters)
        if len(candidates) > 1 or (
            container_id is not None and any(cid != container_id for cid in candidates)
        ):
            raise DockerError("OWNERSHIP_MISMATCH")
        cid = container_id or (candidates[0] if candidates else None)
        if cid is not None:
            data = self._cli.inspect_container(cid)
            if data is not None:
                _owned(data, binding, cid, operation_id)
                # Stop owned execution before surfacing unexpected mounts; never
                # remove or adopt volumes whose origin was not proven.
                if _object(data.get("State")).get("Running") is True:
                    self._cli.stop(cid)
                    data = self._cli.inspect_container(cid)
                if data is not None:
                    _owned(data, binding, cid, operation_id)
                    _cleanable_mounts(data)
                    self._cli.remove(cid)
                if self._cli.inspect_container(cid) is not None:
                    raise DockerError("CLEANUP_INCOMPLETE")
        if self._cli.list_containers(filters):
            raise DockerError("CLEANUP_INCOMPLETE")
        return configuration_digest(
            {
                "schema": "failroom.diagnostic-absence.v1",
                "context": self._cli.context,
                "binding": _labels(binding),
                "containers": [],
                "external_mounts": [],
            }
        )

    def create_qualified(
        self,
        profile: StrictDockerProfile,
        binding: DockerBinding,
        operation_id: str,
        *,
        context: QualificationContext,
        report: QualificationReport | None,
        now: datetime,
        max_age: timedelta,
    ) -> None:
        require_qualified_profile(context, report, now=now, max_age=max_age)
        # This diagnostic slice has no authenticated learner allocation path,
        # independent TTL enforcer or final-image qualification collector yet.
        raise DockerError("LEARNER_CREATION_DISABLED")
