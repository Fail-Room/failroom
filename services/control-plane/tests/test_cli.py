import io
import tempfile
import unittest
from datetime import UTC
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, Mock, patch

from failroom_state import StoreError

from failroom_control_plane import cli
from failroom_control_plane.cli import main
from failroom_control_plane.local_runtime import LocalRuntimeError


class MigrationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "state.sqlite3"
        self.backup = root / "state-before-v2.sqlite3"

    def run_cli(self, argv: list[str], *, database_factory=None, local_runner=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        kwargs = {}
        if local_runner is not None:
            kwargs["local_runner"] = local_runner
        result = main(
            argv,
            database_factory=database_factory,
            stdout=stdout,
            stderr=stderr,
            **kwargs,
        )
        return result, stdout.getvalue(), stderr.getvalue()

    def test_migrate_requires_absolute_database_backup_and_busy_timeout(self) -> None:
        result, stdout, stderr = self.run_cli(
            ["migrate", "--database", "relative.db", "--backup", str(self.backup)]
        )
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "INVALID_CONFIGURATION\n")

    def test_migrate_requires_all_explicit_arguments(self) -> None:
        result, stdout, stderr = self.run_cli(["migrate"])
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "INVALID_CONFIGURATION\n")

    def test_migrate_delegates_only_to_explicit_database_migration(self) -> None:
        database = Mock()
        factory = Mock(return_value=database)

        result, stdout, stderr = self.run_cli(
            [
                "migrate",
                "--database",
                str(self.database),
                "--backup",
                str(self.backup),
                "--busy-timeout-ms",
                "5000",
            ],
            database_factory=factory,
        )

        self.assertEqual(result, 0)
        self.assertEqual(stdout, "MIGRATION_COMPLETED\n")
        self.assertEqual(stderr, "")
        factory.assert_called_once_with(self.database, busy_timeout_ms=5000)
        database.migrate_v1_to_v2.assert_called_once_with(self.backup)
        database.initialize.assert_not_called()

    def test_migrate_target_v3_delegates_to_v2_to_v3(self) -> None:
        database = Mock()
        factory = Mock(return_value=database)

        result, stdout, stderr = self.run_cli(
            [
                "migrate",
                "--database",
                str(self.database),
                "--backup",
                str(self.backup),
                "--busy-timeout-ms",
                "5000",
                "--target-version",
                "3",
            ],
            database_factory=factory,
        )

        self.assertEqual(result, 0)
        self.assertEqual(stdout, "MIGRATION_COMPLETED\n")
        self.assertEqual(stderr, "")
        database.migrate_v2_to_v3.assert_called_once_with(self.backup)
        database.migrate_v1_to_v2.assert_not_called()

    def test_migrate_target_v4_delegates_to_v3_to_v4(self) -> None:
        database = Mock()
        factory = Mock(return_value=database)

        result, stdout, stderr = self.run_cli(
            [
                "migrate",
                "--database",
                str(self.database),
                "--backup",
                str(self.backup),
                "--busy-timeout-ms",
                "5000",
                "--target-version",
                "4",
            ],
            database_factory=factory,
        )

        self.assertEqual(result, 0)
        self.assertEqual(stdout, "MIGRATION_COMPLETED\n")
        self.assertEqual(stderr, "")
        database.migrate_v3_to_v4.assert_called_once_with(self.backup)
        database.migrate_v1_to_v2.assert_not_called()
        database.migrate_v2_to_v3.assert_not_called()

    def test_migrate_preserves_safe_store_error_codes(self) -> None:
        for code in (
            "MIGRATION_REQUIRED",
            "UNSUPPORTED_SCHEMA",
            "STORE_BUSY",
            "STORE_FAILURE",
        ):
            with self.subTest(code=code):
                factory = Mock(side_effect=StoreError(code))
                result, stdout, stderr = self.run_cli(
                    [
                        "migrate",
                        "--database",
                        str(self.database),
                        "--backup",
                        str(self.backup),
                        "--busy-timeout-ms",
                        "5000",
                    ],
                    database_factory=factory,
                )
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, code + "\n")

    def test_migrate_reduces_unknown_store_error_to_fixed_code(self) -> None:
        factory = Mock(side_effect=StoreError("secret path"))
        result, stdout, stderr = self.run_cli(
            [
                "migrate",
                "--database",
                str(self.database),
                "--backup",
                str(self.backup),
                "--busy-timeout-ms",
                "5000",
            ],
            database_factory=factory,
        )
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "STORE_FAILURE\n")
        self.assertNotIn("secret path", stderr)

    def test_only_migrate_command_is_exposed(self) -> None:
        factory = Mock()
        result, stdout, stderr = self.run_cli(["serve"], database_factory=factory)
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "INVALID_CONFIGURATION\n")
        factory.assert_not_called()

    def test_serve_local_dispatches_injected_runner(self) -> None:
        runner = Mock()

        result, stdout, stderr = self.run_cli(["serve-local"], local_runner=runner)

        self.assertEqual((result, stdout, stderr), (0, "LOCAL_RUNTIME_STOPPED\n", ""))
        runner.assert_called_once()

    def test_serve_local_reduces_runtime_failure(self) -> None:
        result, stdout, stderr = self.run_cli(
            ["serve-local"], local_runner=Mock(side_effect=LocalRuntimeError())
        )

        self.assertEqual((result, stdout, stderr), (2, "", "INVALID_CONFIGURATION\n"))

    def test_default_local_runner_builds_loopback_uvicorn_server(self) -> None:
        config = SimpleNamespace(bind_host="127.0.0.1", bind_port=8765)
        runtime = SimpleNamespace(app=object())

        with (
            patch(
                "failroom_control_plane.cli.LocalRuntimeConfig.from_environment",
                return_value=config,
            ) as from_environment,
            patch(
                "failroom_control_plane.cli.build_runtime", return_value=runtime
            ) as build_runtime,
            patch("failroom_control_plane.cli.uvicorn.run") as run_server,
        ):
            cli._serve_local()

        from_environment.assert_called_once_with()
        build_runtime.assert_called_once_with(config, now=ANY)
        now = build_runtime.call_args.kwargs["now"]
        self.assertEqual(now().tzinfo, UTC)
        run_server.assert_called_once_with(
            runtime.app,
            host="127.0.0.1",
            port=8765,
            log_config=None,
            access_log=False,
        )


if __name__ == "__main__":
    unittest.main()
