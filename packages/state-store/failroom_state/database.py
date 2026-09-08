"""Private local SQLite file; every repository operation uses a fresh connection."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .models import StoreError
from .schema import (
    APPLICATION_ID,
    LEGACY_VERSION,
    MIGRATE_V1_TO_V2,
    STATEMENTS,
    VERSION,
)

_V1_COLUMNS: dict[str, tuple[str, ...]] = {
    "room_attempts": (
        "attempt_id",
        "user_id",
        "room_id",
        "sandbox_id",
        "generation",
        "active_sandbox_id",
        "state",
        "session_epoch",
        "version",
        "created_at",
        "expires_at",
        "provisioning_intent",
        "expiry_intent",
        "destroy_intent",
    ),
    "sandbox_resources": (
        "sandbox_id",
        "attempt_id",
        "generation",
        "state",
        "version",
        "container_id",
        "expires_at",
        "expiry_intent",
        "destroy_intent",
        "evidence_digest",
        "cleanup_evidence_digest",
    ),
    "terminal_capability_uses": (
        "jti_hash",
        "attempt_id",
        "consumed_at",
        "expires_at",
        "consumed",
    ),
    "lifecycle_operations": (
        "operation_id",
        "actor",
        "action",
        "idempotency_key",
        "request_hash",
        "attempt_id",
        "sandbox_id",
        "generation",
        "status",
        "result_state",
        "result_version",
        "retry_count",
        "retry_at",
        "error_code",
    ),
}
_V1_OBJECTS = {("table", table) for table in _V1_COLUMNS} | {
    ("index", "attempts_expiry"),
    ("index", "operations_retry"),
    ("trigger", "room_attempts_immutable"),
    ("trigger", "sandbox_resources_immutable"),
    ("trigger", "attempt_owner_immutable"),
}


class CommitDenial(StoreError):
    """Internal: persist a monotonic cleanup intent before returning a denial."""


class Database:
    def __init__(self, path: Path, *, busy_timeout_ms: int) -> None:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or type(busy_timeout_ms) is not int
            or not 1 <= busy_timeout_ms <= 30000
        ):
            raise StoreError("INVALID_CONFIGURATION")
        self.path = path
        self.busy_timeout_ms = busy_timeout_ms

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    @staticmethod
    def _require_exact_v1(connection: sqlite3.Connection) -> None:
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id != APPLICATION_ID or version != LEGACY_VERSION:
            raise StoreError("UNSUPPORTED_SCHEMA")
        objects = {
            (row[0], row[1])
            for row in connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        if objects != _V1_OBJECTS:
            raise StoreError("UNSUPPORTED_SCHEMA")
        for table, expected_columns in _V1_COLUMNS.items():
            columns = tuple(
                row[1] for row in connection.execute(f"PRAGMA table_info({table})")
            )
            if columns != expected_columns:
                raise StoreError("UNSUPPORTED_SCHEMA")

    @staticmethod
    def _check_integrity(connection: sqlite3.Connection) -> None:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise StoreError("STORE_FAILURE")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StoreError("STORE_FAILURE")

    def _validate_backup_path(self, backup_path: Path) -> None:
        if (
            not isinstance(backup_path, Path)
            or not backup_path.is_absolute()
            or backup_path == self.path
            or backup_path.exists()
            or not backup_path.parent.is_dir()
        ):
            raise StoreError("INVALID_CONFIGURATION")

    @staticmethod
    def _backup_to(source: sqlite3.Connection, backup_path: Path) -> None:
        backup = None
        try:
            backup = sqlite3.connect(backup_path)
            source.backup(backup)
            backup.commit()
        except sqlite3.Error:
            if backup is not None:
                backup.rollback()
            try:
                backup_path.unlink()
            except OSError:
                pass
            raise
        finally:
            if backup is not None:
                backup.close()

    def migrate_v1_to_v2(self, backup_path: Path) -> None:
        self._validate_backup_path(backup_path)
        # SQLite's online backup API requires a read transaction, not an active writer.
        # The read snapshot still blocks concurrent writers before the DDL upgrade.
        with self._transaction(initializing=True, immediate=False) as connection:
            self._require_exact_v1(connection)
            self._check_integrity(connection)
            self._backup_to(connection, backup_path)
            for statement in MIGRATE_V1_TO_V2:
                connection.execute(statement)
            self._check_integrity(connection)
            connection.execute(f"PRAGMA user_version={VERSION}")

    @staticmethod
    def _check_schema(connection: sqlite3.Connection) -> None:
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id != APPLICATION_ID:
            raise StoreError("UNSUPPORTED_SCHEMA")
        if version == LEGACY_VERSION:
            Database._require_exact_v1(connection)
            raise StoreError("MIGRATION_REQUIRED")
        if version != VERSION:
            raise StoreError("UNSUPPORTED_SCHEMA")

    @contextmanager
    def _transaction(
        self, *, initializing: bool = False, immediate: bool = True
    ) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            if not initializing:
                self._check_schema(connection)
            try:
                yield connection
            except CommitDenial as error:
                connection.commit()
                raise StoreError(error.code) from None
            else:
                connection.commit()
        except sqlite3.Error as error:
            code = (
                "STORE_BUSY"
                if getattr(error, "sqlite_errorcode", None)
                in (
                    sqlite3.SQLITE_BUSY,
                    sqlite3.SQLITE_LOCKED,
                )
                else "STORE_FAILURE"
            )
            raise StoreError(code) from None
        finally:
            if connection is not None:
                connection.close()

    def initialize(self) -> None:
        with self._transaction(initializing=True) as connection:
            app_id = connection.execute("PRAGMA application_id").fetchone()[0]
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            objects = connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if app_id == 0 and version == 0 and not objects:
                for statement in STATEMENTS:
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={VERSION}")
            else:
                self._check_schema(connection)
        journal_connection = None
        try:
            journal_connection = self._connect()
            if (
                journal_connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                != "wal"
            ):
                raise StoreError("INVALID_CONFIGURATION")
        except sqlite3.Error:
            raise StoreError("STORE_FAILURE") from None
        finally:
            if journal_connection is not None:
                journal_connection.close()
