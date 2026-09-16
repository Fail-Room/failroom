"""Operator-only control-plane migration and local-runtime verification commands."""

import argparse
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, TextIO

import uvicorn
from failroom_state import Database, StoreError

from .local_environment import load_operator_environment
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
    serve_local = subparsers.add_parser("serve-local", add_help=False)
    serve_local.add_argument("--environment-file")
    verify_local = subparsers.add_parser("verify-local", add_help=False)
    verify_local.add_argument("--environment-file")
    return parser


def _runtime_config(environment: Mapping[str, str] | None) -> LocalRuntimeConfig:
    if environment is None:
        return LocalRuntimeConfig.from_environment()
    return LocalRuntimeConfig.from_environment(environment)


def _operator_environment(environment_file: str | None) -> Mapping[str, str] | None:
    if environment_file is None:
        return None
    return load_operator_environment(environment_file)


def _serve_local(environment: Mapping[str, str] | None = None) -> None:
    config = _runtime_config(environment)
    runtime = build_runtime(config, now=lambda: datetime.now(UTC))
    uvicorn.run(
        runtime.app,
        host=config.bind_host,
        port=config.bind_port,
        log_config=None,
        access_log=False,
    )


def _verify_local(environment: Mapping[str, str] | None = None) -> None:
    """Validate local Docker and seccomp prerequisites without starting a runtime."""
    config = _runtime_config(environment)
    preflight_runtime(config)


def main(
    argv: Sequence[str] | None = None,
    *,
    database_factory: type[Database] | None = None,
    local_runner: Callable[[Mapping[str, str] | None], None] | None = None,
    local_verifier: Callable[[Mapping[str, str] | None], None] | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run an explicit operator migration or local-runtime verification command."""
    factory = Database if database_factory is None else database_factory
    try:
        args = _parser().parse_args(argv)
        if args.command == "serve-local":
            environment = _operator_environment(args.environment_file)
            runner = _serve_local if local_runner is None else local_runner
            runner(environment)
            stdout.write("LOCAL_RUNTIME_STOPPED\n")
            return 0
        if args.command == "verify-local":
            environment = _operator_environment(args.environment_file)
            verifier = _verify_local if local_verifier is None else local_verifier
            verifier(environment)
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
