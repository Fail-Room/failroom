"""Private local SQLite file; every repository operation uses a fresh connection."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .models import StoreError
from .schema import APPLICATION_ID, STATEMENTS, VERSION


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
    def _check_schema(connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != VERSION
        ):
            raise StoreError("UNSUPPORTED_SCHEMA")

    @contextmanager
    def _transaction(
        self, *, initializing: bool = False
    ) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
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
