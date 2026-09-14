"""Trusted in-process composition for the Failroom control plane."""

from .config import ConfigurationError, ControllerConfig
from .lifecycle import CleanupWorker, RoomLifecycleService, RoomStatus
from .orchestrator import (
    LifecycleError,
    LifecycleOrchestrator,
    ProvisioningRequest,
    ProvisioningRuntime,
    ProvisioningSession,
    phase_key,
)
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
    "LifecycleOrchestrator",
    "ProvisioningRequest",
    "ProvisioningRuntime",
    "ProvisioningSession",
    "phase_key",
    "ControlPlaneTerminalService",
    "RoomLifecycleService",
    "RoomStatus",
    "TerminalError",
    "TerminalRuntime",
    "TerminalSession",
    "TerminalGatewayProtocol",
    "WebSocketLimits",
    "serve_terminal",
)
