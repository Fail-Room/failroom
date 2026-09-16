"""Trusted in-process composition for the Failroom control plane."""

from .config import ConfigurationError, ControllerConfig
from .lifecycle import CleanupWorker, RoomLifecycleService, RoomStatus
from .local_runtime import (
    LocalRuntime,
    LocalRuntimeConfig,
    LocalRuntimeError,
    build_runtime,
)
from .maintenance import (
    LifecycleMaintenanceService,
    MaintenanceError,
    MaintenanceRun,
)
from .orchestrator import (
    LifecycleError,
    LifecycleOrchestrator,
    ProvisioningRequest,
    ProvisioningRuntime,
    ProvisioningSession,
    phase_key,
)
from .reset import ResetError, RoomResetService
from .runtime_docker import DockerCleanupRuntime, DockerProvisioningRuntime
from .terminal import (
    ControlPlaneTerminalService,
    TerminalError,
    TerminalRuntime,
    TerminalSession,
)
from .websocket import TerminalGatewayProtocol, WebSocketLimits, serve_terminal

__all__ = (
    "ConfigurationError",
    "ControllerConfig",
    "DockerCleanupRuntime",
    "DockerProvisioningRuntime",
    "CleanupWorker",
    "LifecycleError",
    "LifecycleMaintenanceService",
    "LifecycleOrchestrator",
    "LocalRuntime",
    "LocalRuntimeConfig",
    "LocalRuntimeError",
    "MaintenanceError",
    "MaintenanceRun",
    "ProvisioningRequest",
    "ProvisioningRuntime",
    "ProvisioningSession",
    "phase_key",
    "ControlPlaneTerminalService",
    "RoomLifecycleService",
    "RoomResetService",
    "RoomStatus",
    "ResetError",
    "TerminalError",
    "TerminalRuntime",
    "TerminalSession",
    "TerminalGatewayProtocol",
    "WebSocketLimits",
    "build_runtime",
    "serve_terminal",
)
