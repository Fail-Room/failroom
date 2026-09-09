"""Trusted in-process composition for the Failroom control plane."""

from .config import ConfigurationError, ControllerConfig
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
    "LifecycleError",
    "LifecycleOrchestrator",
    "ProvisioningRequest",
    "ProvisioningRuntime",
    "ProvisioningSession",
    "phase_key",
    "ControlPlaneTerminalService",
    "TerminalError",
    "TerminalRuntime",
    "TerminalSession",
    "TerminalGatewayProtocol",
    "WebSocketLimits",
    "serve_terminal",
)
