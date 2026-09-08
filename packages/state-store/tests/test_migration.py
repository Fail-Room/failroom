import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from failroom_state import Database, StoreError, schema


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.backup = Path(self.temp.name) / "state-before-v2.sqlite3"

    def assert_store_error(self, code, callback):
        with self.assertRaises(StoreError) as caught:
            callback()
        self.assertEqual(caught.exception.code, code)

    def create_v1_database(
        self,
        path,
        *,
        tamper=False,
        invalid_check=False,
        invalid_foreign_key=False,
    ):
        with closing(sqlite3.connect(path)) as connection:
            for statement in schema.V1_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                """INSERT INTO room_attempts
                (attempt_id,user_id,room_id,sandbox_id,generation,state,created_at,expires_at)
                VALUES ('legacy-attempt','alice','disk-full','legacy-sandbox',1,
                        'PROVISIONING',0,1)"""
            )
            if tamper:
                connection.execute(
                    "ALTER TABLE room_attempts ADD COLUMN unexpected TEXT"
                )
            if invalid_check:
                connection.execute("PRAGMA ignore_check_constraints=ON")
                connection.execute(
                    """INSERT INTO room_attempts
                    (attempt_id,user_id,room_id,sandbox_id,generation,state,created_at,expires_at)
                    VALUES ('invalid-attempt','alice','disk-full','invalid-sandbox',1,
                            'PROVISIONING',1,1)"""
                )
                connection.execute("PRAGMA ignore_check_constraints=OFF")
            if invalid_foreign_key:
                connection.execute("PRAGMA foreign_keys=OFF")
                connection.execute(
                    """INSERT INTO sandbox_resources
                    (sandbox_id,attempt_id,generation,state,expires_at)
                    VALUES ('orphan-sandbox','missing-attempt',1,'REQUESTED',1)"""
                )
                connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA application_id={schema.APPLICATION_ID}")
            connection.execute("PRAGMA user_version=1")
            connection.commit()

    def test_exact_v1_requires_explicit_migration(self):
        self.create_v1_database(self.path)

        with self.assertRaises(StoreError) as caught:
            Database(self.path, busy_timeout_ms=5000).initialize()

        self.assertEqual(caught.exception.code, "MIGRATION_REQUIRED")

    def test_tampered_v1_is_not_migratable(self):
        self.create_v1_database(self.path, tamper=True)
        database = Database(self.path, busy_timeout_ms=5000)

        self.assert_store_error(
            "UNSUPPORTED_SCHEMA", lambda: database.migrate_v1_to_v2(self.backup)
        )

        self.assertFalse(self.backup.exists())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIn(
                "unexpected",
                {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(room_attempts)")
                },
            )

    def test_migration_rejects_existing_or_relative_backup_path(self):
        self.create_v1_database(self.path)
        database = Database(self.path, busy_timeout_ms=5000)
        self.backup.touch()

        self.assert_store_error(
            "INVALID_CONFIGURATION", lambda: database.migrate_v1_to_v2(self.backup)
        )
        self.assert_store_error(
            "INVALID_CONFIGURATION",
            lambda: database.migrate_v1_to_v2(Path("relative-before-v2.sqlite3")),
        )

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_migration_rejects_check_integrity_failure_before_backup(self):
        self.create_v1_database(self.path, invalid_check=True)
        database = Database(self.path, busy_timeout_ms=5000)

        self.assert_store_error(
            "STORE_FAILURE", lambda: database.migrate_v1_to_v2(self.backup)
        )

        self.assertFalse(self.backup.exists())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_migration_rejects_foreign_key_failure_before_backup(self):
        self.create_v1_database(self.path, invalid_foreign_key=True)
        database = Database(self.path, busy_timeout_ms=5000)

        self.assert_store_error(
            "STORE_FAILURE", lambda: database.migrate_v1_to_v2(self.backup)
        )

        self.assertFalse(self.backup.exists())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_migration_rejects_current_v2_database(self):
        database = Database(self.path, busy_timeout_ms=5000)
        database.initialize()

        self.assert_store_error(
            "UNSUPPORTED_SCHEMA", lambda: database.migrate_v1_to_v2(self.backup)
        )

        self.assertFalse(self.backup.exists())

    def test_explicit_migration_backs_up_v1_and_reopens_v2(self):
        self.create_v1_database(self.path)
        database = Database(self.path, busy_timeout_ms=5000)

        database.migrate_v1_to_v2(self.backup)
        database.initialize()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertIsNone(
                connection.execute(
                    "SELECT runtime_operation_id FROM room_attempts "
                    "WHERE attempt_id='legacy-attempt'"
                ).fetchone()[0]
            )
        with closing(sqlite3.connect(self.backup)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertNotIn(
                "runtime_operation_id",
                {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(room_attempts)")
                },
            )

    def test_migration_rolls_back_after_a_migration_statement_failure(self):
        self.create_v1_database(self.path)
        database = Database(self.path, busy_timeout_ms=5000)

        with patch(
            "failroom_state.database.MIGRATE_V1_TO_V2",
            (
                "ALTER TABLE room_attempts ADD COLUMN runtime_operation_id TEXT",
                "INVALID SQL",
            ),
        ):
            self.assert_store_error(
                "STORE_FAILURE", lambda: database.migrate_v1_to_v2(self.backup)
            )

        self.assertTrue(self.backup.is_file())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertNotIn(
                "runtime_operation_id",
                {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(room_attempts)")
                },
            )
