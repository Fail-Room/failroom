"""Operator-only database migration command surface."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, TextIO

from failroom_state import Database, StoreError

__all__ = ("main",)

_SAFE_STORE_CODES = frozenset(
    {
        "INVALID_CONFIGURATION",
        "MIGRATION_REQUIRED",
        "UNSUPPORTED_SCHEMA",
        "STORE_BUSY",
        "STORE_FAILURE",
    }
)


class _QuietParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("INVALID_CONFIGURATION")


def _parser() -> argparse.ArgumentParser:
    parser = _QuietParser(add_help=False)
    subparsers = parser.add_subparsers(
        dest="command", required=True, parser_class=_QuietParser
    )
    migrate = subparsers.add_parser("migrate", add_help=False)
    migrate.add_argument("--database", required=True)
    migrate.add_argument("--backup", required=True)
    migrate.add_argument("--busy-timeout-ms", required=True, type=int)
    migrate.add_argument("--target-version", choices=("2", "3"), default="2")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    database_factory: type[Database] | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run the sole explicit operator migration command."""
    factory = Database if database_factory is None else database_factory
    try:
        args = _parser().parse_args(argv)
        if args.command != "migrate":
            raise ValueError("INVALID_CONFIGURATION")
        database = factory(Path(args.database), busy_timeout_ms=args.busy_timeout_ms)
        if args.target_version == "2":
            database.migrate_v1_to_v2(Path(args.backup))
        else:
            database.migrate_v2_to_v3(Path(args.backup))
    except StoreError as error:
        code = error.code if error.code in _SAFE_STORE_CODES else "STORE_FAILURE"
        stderr.write(code + "\n")
        return 2
    except (SystemExit, ValueError, TypeError, OSError):
        stderr.write("INVALID_CONFIGURATION\n")
        return 2
    except Exception:
        stderr.write("STORE_FAILURE\n")
        return 2
    stdout.write("MIGRATION_COMPLETED\n")
    return 0
