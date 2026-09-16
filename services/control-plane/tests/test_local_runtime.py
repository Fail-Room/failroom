import hashlib
import os
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import failroom_control_plane
from failroom_control_plane.local_runtime import (
    LocalRuntime,
    LocalRuntimeConfig,
    LocalRuntimeError,
    build_runtime,
    local_lifespan,
)
from failroom_control_plane.maintenance import (
    LifecycleMaintenanceService,
    MaintenanceError,
)


class LocalRuntimeConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.environment = {
            "FAILROOM_LOCAL_BIND_HOST": "127.0.0.1",
            "FAILROOM_LOCAL_BIND_PORT": "8765",
            "FAILROOM_LOCAL_BEARER_TOKEN": "x" * 32,
            "FAILROOM_LOCAL_USER_ID": "local-user",
            "FAILROOM_LOCAL_ROOM_SCOPES": "disk-full",
            "FAILROOM_LOCAL_TOKEN_EXPIRES_AT": "2030-01-01T00:00:00+00:00",
            "FAILROOM_DATABASE_PATH": str(root / "state.sqlite3"),
            "FAILROOM_DATABASE_BUSY_TIMEOUT_MS": "5000",
            "FAILROOM_DOCKER_CONTEXT": "desktop-wsl",
            "FAILROOM_DOCKER_TIMEOUT_SECONDS": "20",
            "FAILROOM_DOCKER_MAX_OUTPUT_BYTES": "65536",
            "FAILROOM_SECCOMP_STORE": str(root / "seccomp-store"),
            "FAILROOM_SECCOMP_MAX_BYTES": "1048576",
            "FAILROOM_DOCKER_IMAGE": "ubuntu@sha256:"
            "33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
            "FAILROOM_DOCKER_UID": "1000",
            "FAILROOM_DOCKER_GID": "1000",
            "FAILROOM_SECCOMP_PATH": str(root / "seccomp-default.json"),
            "FAILROOM_SECCOMP_DIGEST": "sha256:" + "a" * 64,
            "FAILROOM_CPU_LIMIT": "1",
            "FAILROOM_MEMORY_BYTES": "536870912",
            "FAILROOM_MEMORY_SWAP_BYTES": "536870912",
            "FAILROOM_PIDS_LIMIT": "128",
            "FAILROOM_WORKSPACE_TMPFS_BYTES": "67108864",
            "FAILROOM_TEMP_TMPFS_BYTES": "67108864",
            "FAILROOM_SHM_BYTES": "67108864",
            "FAILROOM_FD_LIMIT": "1024",
            "FAILROOM_IO_DEVICE": "/dev/sdf",
            "FAILROOM_IO_READ_BPS": "1048576",
            "FAILROOM_IO_WRITE_BPS": "1048576",
            "FAILROOM_TERMINAL_OUTPUT_BYTES": "1048576",
            "FAILROOM_CONNECTION_LIMIT": "1",
            "FAILROOM_SESSION_LIMIT": "1",
            "FAILROOM_ABSOLUTE_TTL_SECONDS": "300",
            "FAILROOM_CAPABILITY_SECRET": "y" * 32,
            "FAILROOM_CAPABILITY_LIFETIME_SECONDS": "60",
            "FAILROOM_TERMINAL_INPUT_BYTES": "4096",
            "FAILROOM_TERMINAL_SESSION_SECONDS": "60",
            "FAILROOM_TERMINAL_ROWS": "30",
            "FAILROOM_TERMINAL_COLUMNS": "120",
            "FAILROOM_TERMINAL_LEASE_SECONDS": "30",
            "FAILROOM_TERMINAL_AUTH_TIMEOUT_SECONDS": "5",
            "FAILROOM_TERMINAL_FRAME_BYTES": "4096",
            "FAILROOM_TERMINAL_POLL_INTERVAL_SECONDS": "0.01",
            "FAILROOM_MAINTENANCE_INTERVAL_SECONDS": "10",
            "FAILROOM_MAINTENANCE_LIMIT": "10",
            "FAILROOM_CLEANUP_RETRY_SECONDS": "10",
        }

    def test_rejects_missing_bearer_token(self) -> None:
        environment = dict(self.environment)
        environment.pop("FAILROOM_LOCAL_BEARER_TOKEN")
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(LocalRuntimeError) as raised:
                LocalRuntimeConfig.from_environment()
        self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")

    def test_rejects_non_loopback_host(self) -> None:
        environment = dict(self.environment)
        environment["FAILROOM_LOCAL_BIND_HOST"] = "0.0.0.0"
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(LocalRuntimeError) as raised:
                LocalRuntimeConfig.from_environment()
        self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")

    def test_rejects_expired_bearer_token_before_listener_starts(self) -> None:
        environment = dict(self.environment)
        environment["FAILROOM_LOCAL_TOKEN_EXPIRES_AT"] = "2030-01-01T00:00:00+00:00"

        with self.assertRaises(LocalRuntimeError) as raised:
            LocalRuntimeConfig.from_environment(
                environment,
                now=lambda: datetime(2030, 1, 1, tzinfo=UTC),
            )

        self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")

    def test_keeps_only_bearer_digest(self) -> None:
        with patch.dict(os.environ, self.environment, clear=True):
            config = LocalRuntimeConfig.from_environment()
        token = self.environment["FAILROOM_LOCAL_BEARER_TOKEN"]
        self.assertEqual(
            config.bearer_token_digest,
            hashlib.sha256(token.encode("ascii")).hexdigest(),
        )
        self.assertNotIn(token, repr(config))

    def test_builds_distinct_service_identities(self) -> None:
        with patch.dict(os.environ, self.environment, clear=True):
            config = LocalRuntimeConfig.from_environment()
        with patch("failroom_control_plane.local_runtime.preflight_runtime"):
            runtime = build_runtime(
                config, now=lambda: datetime(2026, 9, 15, tzinfo=UTC)
            )
        self.assertEqual(
            {
                runtime.backend_identity.service_id,
                runtime.control_identity.service_id,
                runtime.gateway_identity.service_id,
            },
            {"local-backend", "local-control-plane", "local-gateway"},
        )

    def test_public_package_exports_local_runtime_interfaces(self) -> None:
        self.assertIs(failroom_control_plane.LocalRuntime, LocalRuntime)
        self.assertIs(failroom_control_plane.LocalRuntimeConfig, LocalRuntimeConfig)
        self.assertIs(failroom_control_plane.LocalRuntimeError, LocalRuntimeError)
        self.assertIs(failroom_control_plane.build_runtime, build_runtime)

    def test_runtime_app_runs_maintenance_at_listener_boundaries(self) -> None:
        with patch.dict(os.environ, self.environment, clear=True):
            config = LocalRuntimeConfig.from_environment()
        with (
            patch("failroom_control_plane.local_runtime.preflight_runtime"),
            patch.object(
                LifecycleMaintenanceService, "run_once", autospec=True
            ) as run_once,
        ):
            runtime = build_runtime(
                config, now=lambda: datetime(2026, 9, 15, tzinfo=UTC)
            )
            with TestClient(runtime.app):
                self.assertEqual(run_once.call_count, 1)
        self.assertEqual(run_once.call_count, 2)

    def test_preflight_verifies_image_before_pinning_seccomp_policy(self) -> None:
        from failroom_control_plane.local_runtime import preflight_runtime

        with patch.dict(os.environ, self.environment, clear=True):
            config = LocalRuntimeConfig.from_environment()
        events: list[str] = []

        class Docker:
            def inspect_image(self, image: str) -> dict[str, object]:
                events.append("image:" + image)
                return {"Id": "sha256:" + "b" * 64}

        class Policies:
            @contextmanager
            def pin(self, source_path: str, expected_digest: str):
                events.append("pin:" + source_path + ":" + expected_digest)
                yield "/trusted/pinned-policy.json"

        preflight_runtime(config, docker=Docker(), policies=Policies())

        self.assertEqual(
            events,
            [
                "image:" + config.controller.profile.image,
                "pin:"
                + config.controller.profile.seccomp_path
                + ":"
                + config.controller.profile.seccomp_digest,
            ],
        )

    def test_build_runtime_runs_preflight_before_constructing_application(self) -> None:
        with patch.dict(os.environ, self.environment, clear=True):
            config = LocalRuntimeConfig.from_environment()

        with patch(
            "failroom_control_plane.local_runtime.preflight_runtime"
        ) as preflight:
            build_runtime(config, now=lambda: datetime(2026, 9, 15, tzinfo=UTC))

        preflight.assert_called_once_with(config)


if __name__ == "__main__":
    unittest.main()


class LocalRuntimeLifespanTests(unittest.IsolatedAsyncioTestCase):
    async def test_runs_before_listener_and_on_shutdown(self) -> None:
        class Maintenance:
            def __init__(self) -> None:
                self.calls = 0

            def run_once(self) -> None:
                self.calls += 1

        maintenance = Maintenance()
        async with local_lifespan(maintenance, interval=timedelta(seconds=1)):
            self.assertEqual(maintenance.calls, 1)
        self.assertEqual(maintenance.calls, 2)

    async def test_refuses_listener_when_initial_maintenance_fails(self) -> None:
        class Maintenance:
            def run_once(self) -> None:
                raise MaintenanceError("MAINTENANCE_INCOMPLETE")

        with self.assertRaises(LocalRuntimeError) as raised:
            async with local_lifespan(Maintenance(), interval=timedelta(seconds=1)):
                pass
        self.assertEqual(raised.exception.code, "RUNTIME_UNAVAILABLE")
