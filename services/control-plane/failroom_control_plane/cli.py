"""Operator-only control-plane migration and local-runtime verification commands."""

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, TextIO

import uvicorn
from failroom_state import Database, StoreError

from .local_runtime import (
    LocalRuntimeConfig,
    LocalRuntimeError,
    build_runtime,
    preflight_runtime,
)

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
    migrate.add_argument("--target-version", choices=("2", "3", "4"), default="2")
    subparsers.add_parser("serve-local", add_help=False)
    subparsers.add_parser("verify-local", add_help=False)
    return parser


def _serve_local() -> None:
    config = LocalRuntimeConfig.from_environment()
    runtime = build_runtime(config, now=lambda: datetime.now(UTC))
    uvicorn.run(
        runtime.app,
        host=config.bind_host,
        port=config.bind_port,
        log_config=None,
        access_log=False,
    )


def _verify_local() -> None:
    """Validate local Docker and seccomp prerequisites without starting a runtime."""
    config = LocalRuntimeConfig.from_environment()
    preflight_runtime(config)


def main(
    argv: Sequence[str] | None = None,
    *,
    database_factory: type[Database] | None = None,
    local_runner: Callable[[], None] | None = None,
    local_verifier: Callable[[], None] | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run an explicit operator migration or local-runtime verification command."""
    factory = Database if database_factory is None else database_factory
    try:
        args = _parser().parse_args(argv)
        if args.command == "serve-local":
            runner = _serve_local if local_runner is None else local_runner
            runner()
            stdout.write("LOCAL_RUNTIME_STOPPED\n")
            return 0
        if args.command == "verify-local":
            verifier = _verify_local if local_verifier is None else local_verifier
            verifier()
            stdout.write("LOCAL_RUNTIME_VERIFIED\n")
            return 0
        if args.command != "migrate":
            raise ValueError("INVALID_CONFIGURATION")
        database = factory(Path(args.database), busy_timeout_ms=args.busy_timeout_ms)
        if args.target_version == "2":
            database.migrate_v1_to_v2(Path(args.backup))
        elif args.target_version == "3":
            database.migrate_v2_to_v3(Path(args.backup))
        else:
            database.migrate_v3_to_v4(Path(args.backup))
    except StoreError as error:
        code = error.code if error.code in _SAFE_STORE_CODES else "STORE_FAILURE"
        stderr.write(code + "\n")
        return 2
    except LocalRuntimeError as error:
        stderr.write(error.code + "\n")
        return 2
    except (SystemExit, ValueError, TypeError, OSError):
        stderr.write("INVALID_CONFIGURATION\n")
        return 2
    except Exception:
        stderr.write("STORE_FAILURE\n")
        return 2
    stdout.write("MIGRATION_COMPLETED\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
