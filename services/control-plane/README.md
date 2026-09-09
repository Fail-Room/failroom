# Control Plane

`failroom_control_plane` is a trusted, in-process composition package for the
Failroom state store and sandbox-engine primitives. It owns lifecycle ordering,
attachment-lease-to-PTY binding, and the optional capability HTTP/WebSocket
route composition; it is not a deployment process or a production listener.
It is the only in-repository package that composes state-store authority with
sandbox-engine Docker primitives. Transport authentication and external service
identity remain injected dependencies.

## Configuration

`ControllerConfig` requires every database, Docker, seccomp, profile, and
cleanup timing value explicitly. Database and seccomp-store paths must be
absolute. Invalid values raise the fixed `INVALID_CONFIGURATION` code without
including paths, provider messages, or credentials.

The `docker_cli()` and `seccomp_policy_store()` methods construct the existing
bounded adapters only when the control plane explicitly assembles them.
Constructing this configuration does not invoke Docker or read a policy file.
The seccomp store remains Linux-only and fails closed on unsupported platforms.

```python
config = ControllerConfig(
    database_path=database_path,
    docker_context=docker_context,
    docker_timeout_seconds=docker_timeout_seconds,
    docker_max_output_bytes=docker_max_output_bytes,
    seccomp_store=seccomp_store,
    seccomp_max_bytes=seccomp_max_bytes,
    profile=profile,
    cleanup_retry_delay=cleanup_retry_delay,
)
cli = config.docker_cli()
policies = config.seccomp_policy_store()
```

`LifecycleOrchestrator.provision()` is the trusted state-to-runtime ordering
boundary. It records `CREATING` before calling the runtime, records
`STARTING` before starting a created container, and records `READY` only
after a verified observation digest exists. It derives deterministic
phase-specific idempotency keys, re-inspects the current resource before each
runtime call, maps profile/ownership failures to fixed phase errors, and leaves
cleanup to the durable cleanup worker.

`DockerProvisioningRuntime` connects that ordering boundary to the sandbox
engine's pinned `prepare()` context. `DockerCleanupRuntime` converts the
state-store's exact `CleanupTarget` into a `DockerBinding`, preserves the
persisted runtime operation ID (including legacy `None`), and exposes only fixed
cleanup error codes.

There are no environment defaults, config-file fallbacks, process listeners,
background workers, or learner-facing commands in this package. The HTTP and
WebSocket route factories do not start a server; callers must explicitly inject
all authority, gateway, terminal, and limit dependencies.

## Terminal vertical slice

`ControlPlaneTerminalService` re-inspects the exact `ResourceRef` associated
with a consumed `AttachmentLease` immediately before opening `/bin/bash`. It
rejects expired leases, stale references, non-`READY`/`RUNNING` resources,
expiry or destroy intent, and missing container identity. The WebSocket route
accepts one bounded JSON authorization frame, calls the gateway once, and then
relays only bounded `input`, `resize`, `signal`, and `close` frames. It closes
the PTY on every disconnect and never returns capability or provider details in
WebSocket errors.

The route is available only when `create_app()` receives the optional terminal
dependencies (or when `mount_terminal_route()` is called directly). This is a
Phase 1 vertical slice: production identity verification, browser terminal UI,
multi-tenant deployment, and independent runtime attestation remain planned
until trusted deployment evidence exists.

The Linux PTY adapter currently accepts only signal value `2` (`SIGINT`/Ctrl+C)
and delivers it through the remote PTY line discipline; other signal values are
rejected without terminating the `docker exec` client.

## Operator migration

The only CLI surface is the explicit `migrate` command. It requires absolute
database and new backup paths plus a bounded busy timeout:

```text
failroom-control-plane migrate \
  --database /var/lib/failroom/state.sqlite3 \
  --backup /var/lib/failroom/state-before-v2.sqlite3 \
  --busy-timeout-ms 5000
```


기본 대상 버전은 `2`이며 v1 데이터베이스를 v2로 올린다. v3 lease 스키마로
올릴 때는 v2 데이터베이스와 새 백업 경로를 지정하고 `--target-version 3`을
명시한다. 마이그레이션은 기존 파일을 덮어쓰지 않고 새 절대 백업 경로에
SQLite 백업을 먼저 만든 뒤 원본의 무결성과 스키마를 검증한다.

```text
failroom-control-plane migrate --database /var/lib/failroom/state.sqlite3 --backup /var/lib/failroom/state-before-v3.sqlite3 --target-version 3 --busy-timeout-ms 5000
```

## Linux Docker integration evidence

The real Docker lifecycle evidence test is opt-in and requires a trusted Linux
controller. It provisions a disposable sandbox through the control-plane
orchestrator, verifies the resulting container hardening, leaves the Room, and
runs durable cleanup before checking that the exact four-label binding is gone.
The test does not use Docker mocks.

Run it only when Docker is available and every value below has been reviewed by
the operator:

The image, seccomp path/digest, UID/GID, and I/O device shown below are
placeholders; replace them with values verified for the trusted Linux host.

```text
export FAILROOM_DOCKER_INTEGRATION=1
export FAILROOM_DATABASE_DIR=/var/lib/failroom/integration
export FAILROOM_DATABASE_BUSY_TIMEOUT_MS=5000
export FAILROOM_DOCKER_CONTEXT=default
export FAILROOM_DOCKER_IMAGE=failroom/sandbox:local
export FAILROOM_DOCKER_UID=1000
export FAILROOM_DOCKER_GID=1000
export FAILROOM_SECCOMP_PATH=/etc/failroom/seccomp/default.json
export FAILROOM_SECCOMP_DIGEST=sha256:REVIEWED_POLICY_DIGEST
export FAILROOM_SECCOMP_STORE=/etc/failroom/seccomp.json
export FAILROOM_SECCOMP_MAX_BYTES=1048576
export FAILROOM_DOCKER_TIMEOUT_SECONDS=10
export FAILROOM_DOCKER_MAX_OUTPUT_BYTES=65536
export FAILROOM_CPU_LIMIT=1
export FAILROOM_MEMORY_BYTES=536870912
export FAILROOM_MEMORY_SWAP_BYTES=536870912
export FAILROOM_PIDS_LIMIT=128
export FAILROOM_WORKSPACE_TMPFS_BYTES=67108864
export FAILROOM_TEMP_TMPFS_BYTES=67108864
export FAILROOM_SHM_BYTES=67108864
export FAILROOM_FD_LIMIT=1024
export FAILROOM_IO_DEVICE=/dev/reviewed-device
export FAILROOM_IO_READ_BPS=1048576
export FAILROOM_IO_WRITE_BPS=1048576
export FAILROOM_TERMINAL_OUTPUT_BYTES=1048576
export FAILROOM_CONNECTION_LIMIT=4
export FAILROOM_SESSION_LIMIT=1
export FAILROOM_ABSOLUTE_TTL_SECONDS=300

uv run --locked python -m unittest tests.test_linux_docker_integration -v
```

On Windows and when the opt-in flag or any explicit operator input is absent,
the test is intentionally skipped with an `UNVERIFIED` reason. A skipped run
is not Docker lifecycle evidence; the Linux command must complete successfully
on the trusted controller before recording that evidence.

## Linux terminal integration evidence

The real terminal path is separately gated by
`FAILROOM_TERMINAL_INTEGRATION=1` and `sys.platform == "linux"`. In addition to
the Docker lifecycle inputs above, it requires explicit values for
`FAILROOM_CAPABILITY_SECRET`, `FAILROOM_CAPABILITY_LIFETIME_SECONDS`,
`FAILROOM_TERMINAL_INPUT_BYTES`, `FAILROOM_TERMINAL_SESSION_SECONDS`,
`FAILROOM_TERMINAL_ROWS`, `FAILROOM_TERMINAL_COLUMNS`,
`FAILROOM_TERMINAL_LEASE_SECONDS`, `FAILROOM_TERMINAL_AUTH_TIMEOUT_SECONDS`,
`FAILROOM_TERMINAL_FRAME_BYTES`, and
`FAILROOM_TERMINAL_POLL_INTERVAL_SECONDS`.

When enabled, the test uses a real Docker PTY through the capability gateway
and control-plane lease service. It verifies input/output, ANSI bytes, resize,
signal interruption, one-time capability replay denial, container hardening,
and cleanup. Missing inputs or a non-Linux controller produce `UNVERIFIED`
skips; those skips are not evidence.

```text
uv run --locked python -m unittest tests.test_linux_terminal_integration -v
```
