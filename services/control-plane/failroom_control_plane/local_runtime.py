"""Fail-closed local-only composition settings for the trusted control plane."""

import asyncio
import hashlib
import math
import os
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Self

from failroom_api import (
    BackendCapabilityAuthority,
    BearerCredential,
    BearerIdentityVerifier,
    CapabilityCodec,
)
from failroom_sandbox.docker_lifecycle import DockerDiagnosticLifecycle
from failroom_sandbox.docker_profile import StrictDockerProfile
from failroom_sandbox.pty import DockerPtyRuntime, PtyLimits
from failroom_sandbox.terminal_gateway import TerminalGatewayAuthority
from failroom_state import (
    Action,
    BackendStore,
    Clock,
    ControlPlaneStore,
    Database,
    DockerCleanupWorker,
    Role,
    ServiceIdentity,
    UserIdentity,
)
from fastapi import FastAPI
from starlette.types import Lifespan

from .config import ConfigurationError, ControllerConfig
from .entry import RoomEntryService
from .http import create_app
from .lifecycle import RoomLifecycleService
from .maintenance import LifecycleMaintenanceService, MaintenanceError
from .orchestrator import LifecycleOrchestrator
from .reset import RoomResetService
from .runtime_docker import DockerCleanupRuntime, DockerProvisioningRuntime
from .terminal import ControlPlaneTerminalService
from .websocket import WebSocketLimits


class LocalRuntimeError(RuntimeError):
    """Fixed local runtime setup failures without configuration details."""

    def __init__(self, code: str = "INVALID_CONFIGURATION") -> None:
        self.code = code if code == "RUNTIME_UNAVAILABLE" else "INVALID_CONFIGURATION"
        super().__init__(self.code)


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if type(value) is not str or not value:
        raise LocalRuntimeError()
    return value


def _integer(environment: Mapping[str, str], name: str) -> int:
    try:
        return int(_required(environment, name))
    except ValueError:
        raise LocalRuntimeError() from None


def _seconds(environment: Mapping[str, str], name: str) -> timedelta:
    value = _integer(environment, name)
    if not 1 <= value <= 3_600:
        raise LocalRuntimeError()
    return timedelta(seconds=value)


def _decimal(environment: Mapping[str, str], name: str) -> Decimal:
    try:
        value = Decimal(_required(environment, name))
    except (InvalidOperation, ValueError):
        raise LocalRuntimeError() from None
    if not value.is_finite():
        raise LocalRuntimeError()
    return value


def _float(environment: Mapping[str, str], name: str) -> float:
    try:
        value = float(_required(environment, name))
    except ValueError:
        raise LocalRuntimeError() from None
    if not math.isfinite(value):
        raise LocalRuntimeError()
    return value


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class LocalRuntimeConfig:
    bind_host: str
    bind_port: int
    controller: ControllerConfig
    database_busy_timeout_ms: int
    bearer_token_digest: str
    local_identity: UserIdentity
    bearer_expires_at: datetime
    capability_secret: bytes
    capability_lifetime: timedelta
    lease_duration: timedelta
    pty_limits: PtyLimits
    websocket_limits: WebSocketLimits
    maintenance_interval: timedelta
    maintenance_limit: int

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        now: Clock | None = None,
    ) -> Self:
        values = os.environ if environment is None else environment
        try:
            clock: Clock = _utc_now if now is None else now
            if not callable(clock):
                raise LocalRuntimeError()
            host = _required(values, "FAILROOM_LOCAL_BIND_HOST")
            if host not in {"127.0.0.1", "::1"}:
                raise LocalRuntimeError()
            port = _integer(values, "FAILROOM_LOCAL_BIND_PORT")
            if not 1 <= port <= 65_535:
                raise LocalRuntimeError()
            token = _required(values, "FAILROOM_LOCAL_BEARER_TOKEN").encode("ascii")
            if not 32 <= len(token) <= 4_096:
                raise LocalRuntimeError()
            user_id = _required(values, "FAILROOM_LOCAL_USER_ID")
            scopes = frozenset(
                _required(values, "FAILROOM_LOCAL_ROOM_SCOPES").split(",")
            )
            if not scopes or "" in scopes:
                raise LocalRuntimeError()
            expires_at = datetime.fromisoformat(
                _required(values, "FAILROOM_LOCAL_TOKEN_EXPIRES_AT")
            )
            if expires_at.tzinfo is None:
                raise LocalRuntimeError()
            current_time = clock()
            if not isinstance(current_time, datetime) or current_time.tzinfo is None:
                raise LocalRuntimeError()
            if expires_at.astimezone(UTC) <= current_time.astimezone(UTC):
                raise LocalRuntimeError()
            profile = StrictDockerProfile(
                image=_required(values, "FAILROOM_DOCKER_IMAGE"),
                uid=_integer(values, "FAILROOM_DOCKER_UID"),
                gid=_integer(values, "FAILROOM_DOCKER_GID"),
                seccomp_path=_required(values, "FAILROOM_SECCOMP_PATH"),
                seccomp_digest=_required(values, "FAILROOM_SECCOMP_DIGEST"),
                cpu_limit=_decimal(values, "FAILROOM_CPU_LIMIT"),
                memory_limit_bytes=_integer(values, "FAILROOM_MEMORY_BYTES"),
                memory_swap_limit_bytes=_integer(values, "FAILROOM_MEMORY_SWAP_BYTES"),
                pids_limit=_integer(values, "FAILROOM_PIDS_LIMIT"),
                workspace_tmpfs_bytes=_integer(
                    values, "FAILROOM_WORKSPACE_TMPFS_BYTES"
                ),
                temp_tmpfs_bytes=_integer(values, "FAILROOM_TEMP_TMPFS_BYTES"),
                shm_size_bytes=_integer(values, "FAILROOM_SHM_BYTES"),
                fd_limit=_integer(values, "FAILROOM_FD_LIMIT"),
                io_device_path=_required(values, "FAILROOM_IO_DEVICE"),
                io_read_bps=_integer(values, "FAILROOM_IO_READ_BPS"),
                io_write_bps=_integer(values, "FAILROOM_IO_WRITE_BPS"),
                terminal_output_limit_bytes=_integer(
                    values, "FAILROOM_TERMINAL_OUTPUT_BYTES"
                ),
                connection_limit=_integer(values, "FAILROOM_CONNECTION_LIMIT"),
                session_limit=_integer(values, "FAILROOM_SESSION_LIMIT"),
                absolute_ttl_seconds=_integer(values, "FAILROOM_ABSOLUTE_TTL_SECONDS"),
            )
            cleanup_retry = _seconds(values, "FAILROOM_CLEANUP_RETRY_SECONDS")
            controller = ControllerConfig(
                database_path=Path(_required(values, "FAILROOM_DATABASE_PATH")),
                docker_context=_required(values, "FAILROOM_DOCKER_CONTEXT"),
                docker_timeout_seconds=_float(
                    values, "FAILROOM_DOCKER_TIMEOUT_SECONDS"
                ),
                docker_max_output_bytes=_integer(
                    values, "FAILROOM_DOCKER_MAX_OUTPUT_BYTES"
                ),
                seccomp_store=Path(_required(values, "FAILROOM_SECCOMP_STORE")),
                seccomp_max_bytes=_integer(values, "FAILROOM_SECCOMP_MAX_BYTES"),
                profile=profile,
                cleanup_retry_delay=cleanup_retry,
            )
            busy_timeout = _integer(values, "FAILROOM_DATABASE_BUSY_TIMEOUT_MS")
            if busy_timeout < 1:
                raise LocalRuntimeError()
            pty_limits = PtyLimits(
                input_bytes=_integer(values, "FAILROOM_TERMINAL_INPUT_BYTES"),
                output_bytes=profile.terminal_output_limit_bytes,
                session_seconds=_integer(values, "FAILROOM_TERMINAL_SESSION_SECONDS"),
                rows=_integer(values, "FAILROOM_TERMINAL_ROWS"),
                columns=_integer(values, "FAILROOM_TERMINAL_COLUMNS"),
            )
            websocket_limits = WebSocketLimits(
                authorization_timeout_seconds=_integer(
                    values, "FAILROOM_TERMINAL_AUTH_TIMEOUT_SECONDS"
                ),
                max_frame_bytes=_integer(values, "FAILROOM_TERMINAL_FRAME_BYTES"),
                max_input_bytes=pty_limits.input_bytes,
                max_output_bytes=profile.terminal_output_limit_bytes,
                max_rows=pty_limits.rows,
                max_columns=pty_limits.columns,
                poll_interval_seconds=_float(
                    values, "FAILROOM_TERMINAL_POLL_INTERVAL_SECONDS"
                ),
            )
            secret = _required(values, "FAILROOM_CAPABILITY_SECRET").encode("ascii")
            if len(secret) < 32:
                raise LocalRuntimeError()
            maintenance_limit = _integer(values, "FAILROOM_MAINTENANCE_LIMIT")
            if not 1 <= maintenance_limit <= 1_000:
                raise LocalRuntimeError()
            return cls(
                bind_host=host,
                bind_port=port,
                controller=controller,
                database_busy_timeout_ms=busy_timeout,
                bearer_token_digest=hashlib.sha256(token).hexdigest(),
                local_identity=UserIdentity(user_id, scopes),
                bearer_expires_at=expires_at.astimezone(UTC),
                capability_secret=secret,
                capability_lifetime=_seconds(
                    values, "FAILROOM_CAPABILITY_LIFETIME_SECONDS"
                ),
                lease_duration=_seconds(values, "FAILROOM_TERMINAL_LEASE_SECONDS"),
                pty_limits=pty_limits,
                websocket_limits=websocket_limits,
                maintenance_interval=_seconds(
                    values, "FAILROOM_MAINTENANCE_INTERVAL_SECONDS"
                ),
                maintenance_limit=maintenance_limit,
            )
        except (ConfigurationError, LocalRuntimeError, ValueError, UnicodeError):
            raise LocalRuntimeError() from None


@dataclass(frozen=True)
class LocalRuntime:
    app: FastAPI
    maintenance: LifecycleMaintenanceService
    backend_identity: ServiceIdentity
    control_identity: ServiceIdentity
    gateway_identity: ServiceIdentity


async def _maintenance_loop(
    maintenance: LifecycleMaintenanceService, interval: timedelta
) -> None:
    while True:
        await asyncio.sleep(interval.total_seconds())
        try:
            await asyncio.to_thread(maintenance.run_once)
        except MaintenanceError:
            pass


@asynccontextmanager
async def local_lifespan(
    maintenance: LifecycleMaintenanceService, *, interval: timedelta
) -> AsyncIterator[None]:
    if interval <= timedelta(0):
        raise LocalRuntimeError()
    try:
        await asyncio.to_thread(maintenance.run_once)
    except MaintenanceError:
        raise LocalRuntimeError("RUNTIME_UNAVAILABLE") from None
    task = asyncio.create_task(_maintenance_loop(maintenance, interval))
    try:
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        try:
            await asyncio.to_thread(maintenance.run_once)
        except MaintenanceError:
            pass


def _application_lifespan(
    maintenance: LifecycleMaintenanceService, *, interval: timedelta
) -> Lifespan[FastAPI]:
    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        async with local_lifespan(maintenance, interval=interval):
            yield

    return lifespan


def build_runtime(config: LocalRuntimeConfig, *, now: Clock) -> LocalRuntime:
    if type(config) is not LocalRuntimeConfig or not callable(now):
        raise LocalRuntimeError()
    try:
        database = Database(
            config.controller.database_path,
            busy_timeout_ms=config.database_busy_timeout_ms,
        )
        database.initialize()
        backend, control = BackendStore(database), ControlPlaneStore(database)
        backend_identity = ServiceIdentity(
            "local-backend",
            Role.BACKEND,
            frozenset({Action.CREATE, Action.EXPIRE, Action.PUBLISH, Action.RECONCILE}),
        )
        control_identity = ServiceIdentity(
            "local-control-plane",
            Role.CONTROL_PLANE,
            frozenset({Action.INSPECT, Action.RECONCILE, Action.TRANSITION}),
        )
        gateway_identity = ServiceIdentity(
            "local-gateway", Role.GATEWAY, frozenset({Action.ATTACH, Action.CONSUME})
        )
        docker_lifecycle = DockerDiagnosticLifecycle(
            config.controller.docker_cli(), config.controller.seccomp_policy_store()
        )
        provisioning = DockerProvisioningRuntime(
            docker_lifecycle, config.controller.profile
        )
        cleanup = DockerCleanupRuntime(docker_lifecycle)
        orchestrator = LifecycleOrchestrator(backend, control, provisioning)
        cleanup_worker = DockerCleanupWorker(
            control, backend, cleanup, retry_delay=config.controller.cleanup_retry_delay
        )
        entry = RoomEntryService(
            backend,
            orchestrator,
            backend_identity=backend_identity,
            control_identity=control_identity,
            attempt_ttl=timedelta(
                seconds=config.controller.profile.absolute_ttl_seconds
            ),
            now=now,
        )
        lifecycle = RoomLifecycleService(
            backend,
            cleanup_worker,
            control_identity=control_identity,
            backend_identity=backend_identity,
            cleanup_limit=config.maintenance_limit,
            now=now,
        )
        maintenance = LifecycleMaintenanceService(
            backend,
            cleanup_worker,
            control_identity=control_identity,
            backend_identity=backend_identity,
            limit=config.maintenance_limit,
            now=now,
            reset_provisioner=orchestrator,
        )
        verifier = BearerIdentityVerifier(
            {
                config.bearer_token_digest: BearerCredential(
                    config.local_identity, config.bearer_expires_at
                )
            },
            now=now,
        )
        authority = BackendCapabilityAuthority(
            backend,
            CapabilityCodec(
                config.capability_secret, max_lifetime=config.capability_lifetime
            ),
        )
        gateway = TerminalGatewayAuthority(
            authority, control, gateway_identity, lease_duration=config.lease_duration
        )
        terminal = ControlPlaneTerminalService(
            control,
            DockerPtyRuntime(
                context=config.controller.docker_context, limits=config.pty_limits
            ),
            control_identity,
            now,
        )
        app = create_app(
            authority=authority,
            verifier=verifier,
            now=now,
            gateway=gateway,
            terminal=terminal,
            terminal_limits=config.websocket_limits,
            lifecycle=lifecycle,
            entry=entry,
            reset=RoomResetService(backend, now=now),
            lifespan=_application_lifespan(
                maintenance, interval=config.maintenance_interval
            ),
        )
        return LocalRuntime(
            app, maintenance, backend_identity, control_identity, gateway_identity
        )
    except Exception:
        raise LocalRuntimeError("RUNTIME_UNAVAILABLE") from None
