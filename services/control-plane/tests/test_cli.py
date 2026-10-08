import io
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, Mock, patch

import test_qualification_collector as qualification
from failroom_sandbox.models import QualificationDecision
from failroom_sandbox.qualification import evaluate_qualification
from failroom_state import StoreError

from failroom_control_plane import cli
from failroom_control_plane.cli import main
from failroom_control_plane.local_runtime import LocalRuntimeError
from failroom_control_plane.qualification_collector import (
    QualificationError,
    format_collection,
)


class MigrationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "state.sqlite3"
        self.backup = root / "state-before-v2.sqlite3"

    def run_cli(
        self,
        argv: list[str],
        *,
        database_factory=None,
        local_runner=None,
        local_verifier=None,
        local_qualifier=None,
    ):
        stdout = io.StringIO()
        stderr = io.StringIO()
        kwargs = {}
        if local_runner is not None:
            kwargs["local_runner"] = local_runner
        if local_verifier is not None:
            kwargs["local_verifier"] = local_verifier
        if local_qualifier is not None:
            kwargs["local_qualifier"] = local_qualifier
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

    def test_unknown_command_is_rejected(self) -> None:
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
        runner.assert_called_once_with(None)

    def test_serve_local_reduces_runtime_failure(self) -> None:
        result, stdout, stderr = self.run_cli(
            ["serve-local"], local_runner=Mock(side_effect=LocalRuntimeError())
        )

        self.assertEqual((result, stdout, stderr), (2, "", "INVALID_CONFIGURATION\n"))

    def test_verify_local_dispatches_injected_preflight(self) -> None:
        verifier = Mock()

        result, stdout, stderr = self.run_cli(["verify-local"], local_verifier=verifier)

        self.assertEqual((result, stdout, stderr), (0, "LOCAL_RUNTIME_VERIFIED\n", ""))
        verifier.assert_called_once_with(None)

    def test_verify_local_reduces_runtime_failure(self) -> None:
        result, stdout, stderr = self.run_cli(
            ["verify-local"],
            local_verifier=Mock(side_effect=LocalRuntimeError("RUNTIME_UNAVAILABLE")),
        )

        self.assertEqual((result, stdout, stderr), (2, "", "RUNTIME_UNAVAILABLE\n"))

    @unittest.skipUnless(sys.platform == "linux", "Linux ownership evidence required")
    def test_verify_local_loads_explicit_operator_environment_file(self) -> None:
        environment_file = Path(self.temp.name) / "operator.env"
        environment_file.write_text("FAILROOM_LOCAL_BIND_HOST=127.0.0.1\n")
        os.chmod(environment_file, 0o600)
        verifier = Mock()

        result, stdout, stderr = self.run_cli(
            ["verify-local", "--environment-file", str(environment_file)],
            local_verifier=verifier,
        )

        self.assertEqual((result, stdout, stderr), (0, "LOCAL_RUNTIME_VERIFIED\n", ""))
        verifier.assert_called_once_with({"FAILROOM_LOCAL_BIND_HOST": "127.0.0.1"})

    def test_module_entrypoint_routes_verify_local_to_main(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "failroom_control_plane.cli", "verify-local"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "INVALID_CONFIGURATION\n")

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

    def test_default_local_verifier_parses_config_and_runs_preflight_only(self) -> None:
        config = SimpleNamespace()

        with (
            patch(
                "failroom_control_plane.cli.LocalRuntimeConfig.from_environment",
                return_value=config,
            ) as from_environment,
            patch("failroom_control_plane.cli.preflight_runtime") as preflight_runtime,
            patch("failroom_control_plane.cli.build_runtime") as build_runtime,
        ):
            cli._verify_local()

        from_environment.assert_called_once_with()
        preflight_runtime.assert_called_once_with(config)
        build_runtime.assert_not_called()

    def collection(self):
        docker = qualification.FakeDocker()
        return qualification.QualificationCollector(
            docker,
            qualification.FakeLifecycle(docker),
            qualification.profile(),
            max_age=timedelta(hours=1),
            now=lambda: qualification.NOW,
        ).collect()

    def test_qualify_local_prints_the_report_and_exits_by_decision(self) -> None:
        collection = self.collection()
        report = collection.report
        denied = evaluate_qualification(
            report.context, report, now=qualification.NOW, max_age=timedelta(hours=1)
        )
        for decision, code in ((denied, 3), (QualificationDecision(()), 0)):
            with self.subTest(code=code):
                qualifier = Mock(return_value=(collection, decision))

                result, stdout, stderr = self.run_cli(
                    ["qualify-local"], local_qualifier=qualifier
                )

                self.assertEqual((result, stderr), (code, ""))
                self.assertEqual(
                    stdout.splitlines(), list(format_collection(collection, decision))
                )
                qualifier.assert_called_once_with(None)

    def test_qualify_local_reduces_collection_failures(self) -> None:
        for error, code in (
            (QualificationError("CLEANUP_INCOMPLETE"), "CLEANUP_INCOMPLETE"),
            (LocalRuntimeError("RUNTIME_UNAVAILABLE"), "RUNTIME_UNAVAILABLE"),
            (LocalRuntimeError(), "INVALID_CONFIGURATION"),
        ):
            with self.subTest(code=code):
                result, stdout, stderr = self.run_cli(
                    ["qualify-local"], local_qualifier=Mock(side_effect=error)
                )
                self.assertEqual((result, stdout, stderr), (2, "", code + "\n"))

    def test_default_qualifier_reads_max_age_before_any_runtime_call(self) -> None:
        with (
            patch(
                "failroom_control_plane.cli.LocalRuntimeConfig.from_environment",
                return_value=SimpleNamespace(),
            ),
            patch("failroom_control_plane.cli.preflight_runtime") as preflight_runtime,
        ):
            with self.assertRaises(LocalRuntimeError):
                cli._qualify_local({})

        preflight_runtime.assert_not_called()

    def test_default_qualifier_collects_after_preflight_and_evaluates(self) -> None:
        collection = self.collection()
        controller = SimpleNamespace(
            docker_cli=Mock(return_value="docker"),
            seccomp_policy_store=Mock(return_value="policies"),
            profile="profile",
        )
        config = SimpleNamespace(controller=controller)
        environment = {"FAILROOM_QUALIFICATION_MAX_AGE_SECONDS": "3600"}
        calls = []

        with (
            patch(
                "failroom_control_plane.cli.LocalRuntimeConfig.from_environment",
                return_value=config,
            ),
            patch(
                "failroom_control_plane.cli.preflight_runtime",
                side_effect=lambda value: calls.append(("preflight", value)),
            ),
            patch(
                "failroom_control_plane.cli.DockerDiagnosticLifecycle",
                return_value="lifecycle",
            ) as lifecycle,
            patch("failroom_control_plane.cli.QualificationCollector") as collector,
        ):
            collector.return_value.collect.side_effect = lambda: (
                calls.append(("collect", None)) or collection
            )
            result, decision = cli._qualify_local(environment)

        self.assertEqual(calls, [("preflight", config), ("collect", None)])
        lifecycle.assert_called_once_with("docker", "policies")
        collector.assert_called_once_with(
            "docker",
            "lifecycle",
            "profile",
            max_age=timedelta(hours=1),
            now=ANY,
        )
        now = collector.call_args.kwargs["now"]
        self.assertIsInstance(now(), datetime)
        self.assertEqual(now().tzinfo, UTC)
        self.assertIs(result, collection)
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
