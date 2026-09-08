import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from failroom_state import StoreError

from failroom_control_plane.cli import main


class MigrationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "state.sqlite3"
        self.backup = root / "state-before-v2.sqlite3"

    def run_cli(self, argv: list[str], *, database_factory=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        result = main(
            argv,
            database_factory=database_factory,
            stdout=stdout,
            stderr=stderr,
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


if __name__ == "__main__":
    unittest.main()
