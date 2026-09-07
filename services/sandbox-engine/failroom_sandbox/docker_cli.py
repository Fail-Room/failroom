"""Bounded, trusted-only Docker CLI transport. No learner command interface."""

import json
import math
import re
import subprocess
import threading
from dataclasses import dataclass
from typing import BinaryIO, Protocol, cast


class DockerError(RuntimeError):
    def __init__(self, code: str) -> None:
        if code not in {
            "RUNTIME_UNAVAILABLE",
            "INVALID_DOCKER_REQUEST",
            "INVALID_DOCKER_RESPONSE",
            "IMAGE_UNVERIFIED",
            "PROFILE_UNVERIFIED",
            "OWNERSHIP_MISMATCH",
            "CLEANUP_INCOMPLETE",
            "LEARNER_CREATION_DISABLED",
        }:
            code = "RUNTIME_UNAVAILABLE"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class Runner(Protocol):
    def __call__(
        self, argv: tuple[str, ...], *, timeout: float, max_output_bytes: int
    ) -> ProcessResult: ...


def _run_process(
    argv: tuple[str, ...], *, timeout: float, max_output_bytes: int
) -> ProcessResult:
    """Drain both pipes concurrently; kill at a shared byte cap or deadline.

    Unlike capture_output/communicate, retained memory never exceeds the cap.
    Killing a timed-out CLI does not cancel a daemon operation; lifecycle callers
    must reconcile the preallocated diagnostic name after ambiguous failures.
    """
    chunks: list[bytearray] = [bytearray(), bytearray()]
    lock = threading.Lock()
    overflow = threading.Event()
    process = subprocess.Popen(
        argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    def drain(pipe: BinaryIO, index: int) -> None:
        try:
            while data := pipe.read(4096):
                with lock:
                    remaining = max_output_bytes - sum(map(len, chunks))
                    chunks[index].extend(data[: max(0, remaining)])
                    if len(data) > remaining:
                        overflow.set()
                        process.kill()
                        return
        except OSError:
            overflow.set()
        finally:
            pipe.close()

    assert process.stdout is not None and process.stderr is not None
    threads = [
        threading.Thread(target=drain, args=(pipe, index), daemon=True)
        for index, pipe in enumerate((process.stdout, process.stderr))
    ]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise DockerError("RUNTIME_UNAVAILABLE") from None
    finally:
        for thread in threads:
            thread.join(timeout=1)
    if overflow.is_set() or any(thread.is_alive() for thread in threads):
        raise DockerError("RUNTIME_UNAVAILABLE")
    return ProcessResult(process.returncode, bytes(chunks[0]), bytes(chunks[1]))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _one_object(data: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if type(value) is not list or len(value) != 1 or type(value[0]) is not dict:
            raise ValueError
        return cast(dict[str, object], value[0])
    except (ValueError, UnicodeError, RecursionError):
        raise DockerError("INVALID_DOCKER_RESPONSE") from None


def _container_selector(value: str) -> None:
    if (
        type(value) is not str
        or re.fullmatch(r"(?:[a-f0-9]{64}|failroom-diagnostic-[a-f0-9]{64})", value)
        is None
    ):
        raise DockerError("INVALID_DOCKER_REQUEST")


class DockerCli:
    """Explicit context, time and memory bounds; argv never goes through a shell."""

    def __init__(
        self,
        *,
        context: str,
        timeout: float,
        max_output_bytes: int,
        runner: Runner = _run_process,
    ) -> None:
        if (
            type(context) is not str
            or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", context) is None
            or type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
            or type(max_output_bytes) is not int
            or not 0 < max_output_bytes <= 1048576
        ):
            raise DockerError("INVALID_DOCKER_REQUEST")
        self.context = context
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._runner = runner

    def _call(
        self, args: tuple[str, ...], *, allow_failure: bool = False
    ) -> ProcessResult:
        try:
            result = self._runner(
                ("docker", "--context", self.context, *args),
                timeout=self._timeout,
                max_output_bytes=self._max_output_bytes,
            )
        except Exception:
            raise DockerError("RUNTIME_UNAVAILABLE") from None
        if (
            type(result) is not ProcessResult
            or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes
            or type(result.returncode) is not int
            or len(result.stdout) + len(result.stderr) > self._max_output_bytes
        ):
            raise DockerError("INVALID_DOCKER_RESPONSE")
        if not allow_failure and (result.returncode != 0 or result.stderr):
            raise DockerError("RUNTIME_UNAVAILABLE")
        return result

    def inspect_image(self, image: str) -> dict[str, object]:
        if (
            type(image) is not str
            or re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}", image)
            is None
        ):
            raise DockerError("INVALID_DOCKER_REQUEST")
        return _one_object(self._call(("image", "inspect", image)).stdout)

    def inspect_container(self, selector: str) -> dict[str, object] | None:
        _container_selector(selector)
        result = self._call(("container", "inspect", selector), allow_failure=True)
        if result.returncode == 0:
            if result.stderr:
                raise DockerError("INVALID_DOCKER_RESPONSE")
            return _one_object(result.stdout)
        # Do not infer absence from localized stderr or a daemon connection error.
        filter_value = (
            "id=" + selector if len(selector) == 64 else "name=^/" + selector + "$"
        )
        if self.list_containers((filter_value,)):
            raise DockerError("RUNTIME_UNAVAILABLE")
        return None

    def list_containers(self, filters: tuple[str, ...]) -> tuple[str, ...]:
        args: tuple[str, ...] = ("container", "ls", "--all", "--quiet", "--no-trunc")
        for value in filters:
            args += ("--filter", value)
        data = self._call(args).stdout
        try:
            ids = tuple(data.decode("ascii").splitlines())
        except UnicodeError:
            raise DockerError("INVALID_DOCKER_RESPONSE") from None
        if any(re.fullmatch(r"[a-f0-9]{64}", cid) is None for cid in ids) or len(
            set(ids)
        ) != len(ids):
            raise DockerError("INVALID_DOCKER_RESPONSE")
        return ids

    def create(self, argv: tuple[str, ...]) -> str:
        if argv[:3] != ("docker", "container", "create"):
            raise DockerError("INVALID_DOCKER_REQUEST")
        data = self._call(argv[1:]).stdout
        try:
            cid = data.decode("ascii").strip()
        except UnicodeError:
            raise DockerError("INVALID_DOCKER_RESPONSE") from None
        if re.fullmatch(r"[a-f0-9]{64}", cid) is None:
            raise DockerError("INVALID_DOCKER_RESPONSE")
        return cid

    def start(self, cid: str) -> None:
        _container_selector(cid)
        self._call(("container", "start", cid))

    def stop(self, cid: str) -> None:
        _container_selector(cid)
        self._call(("container", "stop", "--time", "1", cid))

    def remove(self, cid: str) -> None:
        _container_selector(cid)
        self._call(("container", "rm", cid))
