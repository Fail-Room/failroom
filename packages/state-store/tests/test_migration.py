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

    def test_explicit_v2_to_v3_migration_adds_lease_table_and_backup(self):
        self.create_v1_database(self.path)
        database = Database(self.path, busy_timeout_ms=5000)
        database.migrate_v1_to_v2(self.backup)
        v3_backup = Path(self.temp.name) / "state-before-v3.sqlite3"

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertNotIn(
                "terminal_attachment_leases",
                {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                },
            )

        database.migrate_v2_to_v3(v3_backup)
        database.initialize()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertIsNotNone(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='terminal_attachment_leases'"
                ).fetchone()
            )
        with closing(sqlite3.connect(v3_backup)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='terminal_attachment_leases'"
                ).fetchone()
            )

    def test_explicit_v3_to_v4_migration_preserves_active_binding(self):
        with closing(sqlite3.connect(self.path)) as connection:
            for statement in schema.V3_STATEMENTS:
                connection.execute(statement)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                """INSERT INTO room_attempts
                (attempt_id,user_id,room_id,sandbox_id,generation,active_sandbox_id,
                 state,created_at,expires_at,runtime_operation_id)
                VALUES ('attempt-v3','alice','disk-full','sandbox-v3',1,'sandbox-v3',
                        'READY',1,100,'runtime-v3')"""
            )
            connection.execute(
                """INSERT INTO sandbox_resources
                (sandbox_id,attempt_id,generation,state,container_id,runtime_operation_id,
                 expires_at)
                VALUES ('sandbox-v3','attempt-v3',1,'READY','container-v3','runtime-v3',100)"""
            )
            connection.execute(f"PRAGMA application_id={schema.APPLICATION_ID}")
            connection.execute("PRAGMA user_version=3")
            connection.commit()

        database = Database(self.path, busy_timeout_ms=5000)
        v4_backup = Path(self.temp.name) / "state-before-v4.sqlite3"
        if not hasattr(database, "migrate_v3_to_v4"):
            self.fail("Database must expose explicit v3-to-v4 migration")
        database.migrate_v3_to_v4(v4_backup)
        database.initialize()

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)
            self.assertEqual(
                connection.execute(
                    """SELECT active_sandbox_id,active_generation,candidate_sandbox_id
                    FROM room_attempts WHERE attempt_id='attempt-v3'"""
                ).fetchone(),
                ("sandbox-v3", 1, None),
            )
        with closing(sqlite3.connect(v4_backup)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)

    def test_v2_to_v3_migration_rejects_existing_or_relative_backup(self):
        self.create_v1_database(self.path)
        database = Database(self.path, busy_timeout_ms=5000)
        database.migrate_v1_to_v2(self.backup)
        v3_backup = Path(self.temp.name) / "state-before-v3.sqlite3"
        v3_backup.touch()

        self.assert_store_error(
            "INVALID_CONFIGURATION",
            lambda: database.migrate_v2_to_v3(v3_backup),
        )
        self.assert_store_error(
            "INVALID_CONFIGURATION",
            lambda: database.migrate_v2_to_v3(Path("relative-v3.sqlite3")),
        )

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)

    def test_v2_to_v3_migration_rejects_tampered_v2_without_mutation(self):
        self.create_v1_database(self.path)
        database = Database(self.path, busy_timeout_ms=5000)
        database.migrate_v1_to_v2(self.backup)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("ALTER TABLE room_attempts ADD COLUMN unexpected TEXT")

        v3_backup = Path(self.temp.name) / "state-before-v3.sqlite3"
        self.assert_store_error(
            "UNSUPPORTED_SCHEMA",
            lambda: database.migrate_v2_to_v3(v3_backup),
        )
        self.assertFalse(v3_backup.exists())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)

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
