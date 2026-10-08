# Control Plane

`failroom_control_plane` is the trusted composition package for the Failroom
state store and sandbox-engine primitives. It owns lifecycle ordering,
attachment-lease-to-PTY binding, and the HTTP/WebSocket route composition. It
is the only in-repository package that composes state-store authority with
sandbox-engine Docker primitives.

It also provides an operator-only local runtime that serves those routes on a
loopback address for one local operator. The local runtime is a proof of
concept, not a deployment process or a production listener; read
[Local runtime](#local-runtime-operator-only-proof-of-concept) before using it.

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

Library composition has no environment defaults or config-file fallbacks. The
HTTP and WebSocket route factories do not start a server; callers must
explicitly inject all authority, gateway, terminal, and limit dependencies. Only
the operator `serve-local` command opens a listener and runs background
maintenance.

## Terminal vertical slice

`ControlPlaneTerminalService` re-inspects the exact `ResourceRef` associated
with a consumed `AttachmentLease` immediately before opening `/bin/bash`. It
rejects expired leases, stale references, non-`READY`/`RUNNING` resources,
expiry or destroy intent, and missing container identity. It also counts
authorized connections and open PTY sessions per sandbox generation (attempt,
sandbox and generation) and refuses one beyond the profile's
`connection_limit` or `session_limit` before opening a PTY. The WebSocket route
accepts one bounded JSON authorization frame, calls the gateway once, and then
relays only bounded `input`, `resize`, `signal`, and `close` frames. It closes
the PTY session on every disconnect, which also stops the shell's processes
inside the sandbox, and never returns capability or provider details in
WebSocket errors.

The route is available only when `create_app()` receives the optional terminal
dependencies (or when `mount_terminal_route()` is called directly). This is a
Phase 1 vertical slice: production identity verification, browser terminal UI,
multi-tenant deployment, and independent runtime attestation remain planned
until trusted deployment evidence exists.

The Linux PTY adapter currently accepts only signal value `2` (`SIGINT`/Ctrl+C)
and delivers it through the remote PTY line discipline. The adapter itself
rejects other signal values without terminating the `docker exec` client, but
the WebSocket route treats any rejected frame, including another signal value,
as fatal: it closes the connection and the PTY session.

## Local runtime (operator-only proof of concept)

> **Limitation:** the local runtime provisions Disk Full Room sandboxes through
> the diagnostic Docker lifecycle without collecting or checking a
> qualification report before allocation. It therefore does not meet the
> qualification requirement in [SECURITY.md](../../docs/SECURITY.md). Use it only
> as the local operator on your own host, and do not offer it to learners or
> other users. A trusted qualification collector and allocation gate remain
> planned.

`failroom-control-plane serve-local` composes the state store, the Docker
lifecycle and PTY adapters, the capability authority, and the HTTP/WebSocket
routes into one process:

1. It parses and validates every setting listed below. A missing or invalid
   value fails with `INVALID_CONFIGURATION` before any side effect.
2. It checks that the configured image exists on the Docker context and pins
   the seccomp policy by digest. A failure returns `RUNTIME_UNAVAILABLE`.
3. It opens or initializes the SQLite database and runs one maintenance pass:
   expiry, cleanup, finalization, and resumption of interrupted resets. If that
   pass fails, the listener does not start.
4. It serves the routes with access logging disabled, repeats maintenance on a
   fixed interval, and runs one final pass on shutdown.

`failroom-control-plane verify-local` performs only steps 1 and 2 and prints
`LOCAL_RUNTIME_VERIFIED`. `serve-local` prints `LOCAL_RUNTIME_STOPPED` after a
normal shutdown. Neither command prints configuration values, paths, or
credentials; a failure prints one fixed code to standard error and exits with
status 2.

The runtime binds only to `127.0.0.1` or `::1` and accepts exactly one bearer
token, which it keeps only as a SHA-256 digest. The token authenticates one
local user with the configured Room scopes until its expiry. Only the reviewed
`disk-full` Room can be entered.

### Running the local runtime

Run the commands from this directory after `uv sync --locked`, on a Linux host
with Docker:

```sh
uv run --locked failroom-control-plane verify-local --environment-file /absolute/path/operator.env
uv run --locked failroom-control-plane serve-local --environment-file /absolute/path/operator.env
```

Without `--environment-file`, both commands read the process environment. With
it, they read only that file and ignore the process environment. The file
loader:

- runs only on Linux and requires an absolute path;
- refuses symbolic links, non-regular files, files not owned by the effective
  user, and any mode other than `0600`;
- accepts at most 64 KiB of ASCII text;
- reads `KEY=VALUE` lines whose keys match `[A-Z][A-Z0-9_]*`, and skips empty
  lines and lines that start with `#`;
- rejects duplicate keys and any other line, including `export KEY=value`, and
  performs no shell evaluation, so quotes and `$NAME` references in values are
  kept literally.

Keep the environment file, the database, and the seccomp snapshot directory
outside the repository and synchronized folders. The bearer token and the
capability secret are credentials.

### Settings

Every setting is required; there are no defaults. Profile values are validated
by `StrictDockerProfile` as described in the
[sandbox-engine README](../sandbox-engine/README.md).

| Variable | Meaning and validation |
| --- | --- |
| `FAILROOM_LOCAL_BIND_HOST` | `127.0.0.1` or `::1` only. |
| `FAILROOM_LOCAL_BIND_PORT` | Listener port, 1–65535. |
| `FAILROOM_LOCAL_BEARER_TOKEN` | Bearer credential, 32–4096 ASCII characters. |
| `FAILROOM_LOCAL_USER_ID` | Identifier of the local user. |
| `FAILROOM_LOCAL_ROOM_SCOPES` | Comma-separated Room IDs the user may enter, for example `disk-full`. |
| `FAILROOM_LOCAL_TOKEN_EXPIRES_AT` | ISO 8601 time with a UTC offset, in the future at startup. Later requests fail with `AUTHENTICATION_EXPIRED`. |
| `FAILROOM_DATABASE_PATH` | Absolute path of the SQLite database file. |
| `FAILROOM_DATABASE_BUSY_TIMEOUT_MS` | SQLite busy timeout, 1–30000. |
| `FAILROOM_DOCKER_CONTEXT` | Docker CLI context name. |
| `FAILROOM_DOCKER_TIMEOUT_SECONDS` | Per-command Docker timeout, greater than 0 and at most 60. |
| `FAILROOM_DOCKER_MAX_OUTPUT_BYTES` | Docker CLI output limit, 1–1048576. |
| `FAILROOM_SECCOMP_PATH` | Absolute path of the reviewed seccomp policy JSON file; symbolic links are refused. |
| `FAILROOM_SECCOMP_DIGEST` | `sha256:` followed by the policy's lowercase hex digest. |
| `FAILROOM_SECCOMP_MAX_BYTES` | Maximum policy file size, greater than 0. |
| `FAILROOM_SECCOMP_STORE` | Absolute path of a directory owned by the runtime user with mode `0700`. Every parent must be owned by root or that user and must not be writable by group or others, except a root-owned sticky directory. |
| `FAILROOM_DOCKER_IMAGE` | `repository@sha256:<digest>` or a local image ID `sha256:<64 hex>`; tags are refused. |
| `FAILROOM_DOCKER_UID`, `FAILROOM_DOCKER_GID` | Non-root numeric user and group IDs. |
| `FAILROOM_CPU_LIMIT` | Decimal CPU limit. |
| `FAILROOM_MEMORY_BYTES`, `FAILROOM_MEMORY_SWAP_BYTES` | Memory limit; the swap limit must equal it. |
| `FAILROOM_PIDS_LIMIT`, `FAILROOM_FD_LIMIT` | Process and open-file limits. |
| `FAILROOM_WORKSPACE_TMPFS_BYTES`, `FAILROOM_TEMP_TMPFS_BYTES`, `FAILROOM_TARGET_SUPERVISOR_TMPFS_BYTES`, `FAILROOM_SHM_BYTES` | Sizes of the workspace, temporary, target-supervisor, and shared-memory mounts. |
| `FAILROOM_IO_DEVICE`, `FAILROOM_IO_READ_BPS`, `FAILROOM_IO_WRITE_BPS` | Docker host block device to throttle and its read and write limits. |
| `FAILROOM_TERMINAL_OUTPUT_BYTES` | Cumulative terminal output limit, at most 1048576 because the WebSocket relay uses the same limit. |
| `FAILROOM_CONNECTION_LIMIT`, `FAILROOM_SESSION_LIMIT` | Concurrent authorized terminal connections and open PTY sessions allowed per sandbox generation; a connection beyond either is closed with `4429`. |
| `FAILROOM_ABSOLUTE_TTL_SECONDS` | Absolute attempt lifetime. The container's PID 1 exits no later than the attempt deadline. |
| `FAILROOM_TERMINAL_INPUT_BYTES` | Largest input frame, 1–1048576 and not larger than the frame limit. |
| `FAILROOM_TERMINAL_SESSION_SECONDS` | Wall-clock PTY session limit, 1–3600. |
| `FAILROOM_TERMINAL_ROWS`, `FAILROOM_TERMINAL_COLUMNS` | Largest accepted resize, 1–500 rows and 1–1000 columns. |
| `FAILROOM_TERMINAL_AUTH_TIMEOUT_SECONDS` | Time allowed for the WebSocket authorization frame, 1–30. |
| `FAILROOM_TERMINAL_FRAME_BYTES` | Largest WebSocket frame, 128–1048576. |
| `FAILROOM_TERMINAL_POLL_INTERVAL_SECONDS` | PTY output poll interval, 0.001–1.0. |
| `FAILROOM_CAPABILITY_SECRET` | Capability HMAC key, at least 32 ASCII characters. |
| `FAILROOM_CAPABILITY_LIFETIME_SECONDS` | Terminal capability lifetime, 1–300. |
| `FAILROOM_TERMINAL_LEASE_SECONDS` | Attachment lease lifetime, 1–3600. |
| `FAILROOM_MAINTENANCE_INTERVAL_SECONDS` | Seconds between maintenance passes, 1–3600. |
| `FAILROOM_MAINTENANCE_LIMIT` | Records handled per maintenance pass, 1–1000. |
| `FAILROOM_CLEANUP_RETRY_SECONDS` | Delay before a failed cleanup is retried, 1–3600. |

### Disk Full image

The Disk Full Room runs the image in
[`scenarios/disk-full/image`](../../scenarios/disk-full/image), whose Ubuntu base
is pinned by digest. Build it on the same Docker context and use the printed
local image ID as `FAILROOM_DOCKER_IMAGE`:

```sh
docker --context default build --pull=false --quiet --tag failroom/disk-full:local ../../scenarios/disk-full/image
```

### HTTP and WebSocket interface

Every HTTP request needs `Authorization: Bearer <token>`; a missing, wrong, or
expired token returns `401`. Enter Room, Reset Room, recovery verification, and
Leave Room also need a non-empty `Idempotency-Key` header. Errors return only
`{"code": "<FIXED_CODE>"}`. The app serves no OpenAPI or documentation routes.

| Request | Purpose | Success response |
| --- | --- | --- |
| `POST /v1/rooms/{room_id}/attempts` | Enter Room | `201` with `attempt_id`, `room_id`, `state`, and `expires_at` |
| `GET /v1/attempts/{attempt_id}/status` | Room Status | `200` with `attempt_id`, `room_id`, `state`, `expires_at`, and `destroy_intent` |
| `POST /v1/attempts/{attempt_id}/terminal-capability` | Issue a single-use terminal capability | `200` with `capability` and `expires_at` |
| `POST /v1/attempts/{attempt_id}/reset` | Reset Room | `202` with the status fields |
| `POST /v1/attempts/{attempt_id}/verify-recovery` | Check the Disk Full recovery inside the sandbox | `200` with the status fields |
| `POST /v1/attempts/{attempt_id}/leave` | Leave Room | `202` with the status fields |

The terminal route is `/v1/terminal`. The client first sends
`{"type": "authorize", "capability": "<capability>"}` within the authorization
timeout. The server answers `{"type": "authorized"}` and then streams
`{"type": "output", "data": "..."}` frames. The client may send `input`
(`data`), `resize` (`rows`, `columns`), `signal` (`value`; only `2` is
accepted), and `close` frames. A capability works once, so a reconnect needs a
new capability. The server closes the connection with `4408` when authorization
times out, `4400` for an invalid frame, `4403` when authorization or attachment
is denied, `4409` for an oversized frame or input, `4429` when the sandbox
generation already has as many authorized connections or open sessions as the
profile allows, and `1011` for a runtime failure, including a rejected signal
value. A connection counts against these limits only after the gateway has
consumed its capability, because the capability is what names the sandbox: a
refused connection has used its capability, and sockets that have not
authorized are bounded only by the authorization timeout. The counts live in
the control plane's process memory and start empty when it restarts. Every
disconnect closes the PTY session and kills the shell's session inside the
sandbox, including its background jobs; Docker's init, the sandbox's PID 1,
reaps any of them that had been orphaned to it, so none remain as zombies. A
process started with `setsid` leaves that session and keeps running until the
sandbox's PID 1 lifetime ends.

## Operator migration

`migrate` upgrades an existing database by one schema version. It needs an
absolute database path, a new absolute backup path in an existing directory,
and a busy timeout. It validates the source version, shape, and integrity,
writes a SQLite backup to the new path, and then applies the change. It never
overwrites an existing file.

| `--target-version` | Upgrade |
| --- | --- |
| `2` (default) | v1 to v2 |
| `3` | v2 to v3, adding attachment leases |
| `4` | v3 to v4, adding reset generations |

```sh
uv run --locked failroom-control-plane migrate \
  --database /var/lib/failroom/state.sqlite3 \
  --backup /var/lib/failroom/state-before-v4.sqlite3 \
  --target-version 4 \
  --busy-timeout-ms 5000
```

New databases are created at v4, and current state operations use v4 columns,
so migrate an older database step by step to v4 before starting the local
runtime. Stop every writer first. The command prints `MIGRATION_COMPLETED` or
one fixed error code.

## Linux integration evidence

The opt-in tests below use real Docker containers and no Docker mocks. Run them
only on a trusted Linux controller, from this directory, after reviewing every
input. Without the opt-in flag, on another platform, or with a missing input,
they skip with an `UNVERIFIED` reason. A skip is not evidence; record evidence
only from a successful run.

All tests share these inputs. Replace the seccomp policy path, the I/O device,
and the IDs with values verified for the host. `FAILROOM_DATABASE_DIR` must be
an existing private directory; tests create temporary databases inside it.

```sh
install -d -m 0700 "$HOME/.local/state/failroom/integration" "$HOME/.local/state/failroom/seccomp-store"
export FAILROOM_DATABASE_DIR="$HOME/.local/state/failroom/integration"
export FAILROOM_DATABASE_BUSY_TIMEOUT_MS=5000
export FAILROOM_DOCKER_CONTEXT=default
export FAILROOM_DOCKER_IMAGE="$(docker --context default build --pull=false --quiet --tag failroom/disk-full:local ../../scenarios/disk-full/image)"
export FAILROOM_DOCKER_UID=1000
export FAILROOM_DOCKER_GID=1000
export FAILROOM_SECCOMP_PATH="$HOME/.local/share/failroom/policies/reviewed-default.json"
export FAILROOM_SECCOMP_DIGEST="sha256:$(sha256sum "$FAILROOM_SECCOMP_PATH" | cut -d' ' -f1)"
export FAILROOM_SECCOMP_STORE="$HOME/.local/state/failroom/seccomp-store"
export FAILROOM_SECCOMP_MAX_BYTES=1048576
export FAILROOM_DOCKER_TIMEOUT_SECONDS=30
export FAILROOM_DOCKER_MAX_OUTPUT_BYTES=1048576
export FAILROOM_CPU_LIMIT=1
export FAILROOM_MEMORY_BYTES=536870912
export FAILROOM_MEMORY_SWAP_BYTES=536870912
export FAILROOM_PIDS_LIMIT=128
export FAILROOM_WORKSPACE_TMPFS_BYTES=67108864
export FAILROOM_TEMP_TMPFS_BYTES=67108864
export FAILROOM_TARGET_SUPERVISOR_TMPFS_BYTES=1048576
export FAILROOM_SHM_BYTES=67108864
export FAILROOM_FD_LIMIT=1024
export FAILROOM_IO_DEVICE=/dev/sda
export FAILROOM_IO_READ_BPS=1048576
export FAILROOM_IO_WRITE_BPS=1048576
export FAILROOM_TERMINAL_OUTPUT_BYTES=1048576
export FAILROOM_CONNECTION_LIMIT=4
export FAILROOM_SESSION_LIMIT=1
export FAILROOM_ABSOLUTE_TTL_SECONDS=300
```

The terminal and local runtime tests also need the terminal and capability
settings:

```sh
export FAILROOM_CAPABILITY_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export FAILROOM_CAPABILITY_LIFETIME_SECONDS=60
export FAILROOM_TERMINAL_INPUT_BYTES=4096
export FAILROOM_TERMINAL_SESSION_SECONDS=600
export FAILROOM_TERMINAL_ROWS=40
export FAILROOM_TERMINAL_COLUMNS=120
export FAILROOM_TERMINAL_LEASE_SECONDS=30
export FAILROOM_TERMINAL_AUTH_TIMEOUT_SECONDS=10
export FAILROOM_TERMINAL_FRAME_BYTES=65536
export FAILROOM_TERMINAL_POLL_INTERVAL_SECONDS=0.05
```

The local runtime test also needs the local identity and maintenance settings.
It sets `FAILROOM_DATABASE_PATH` itself and requires `FAILROOM_DOCKER_IMAGE` to
be the Disk Full image:

```sh
export FAILROOM_LOCAL_BIND_HOST=127.0.0.1
export FAILROOM_LOCAL_BIND_PORT=18765
export FAILROOM_LOCAL_BEARER_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(36))')"
export FAILROOM_LOCAL_USER_ID=integration-user
export FAILROOM_LOCAL_ROOM_SCOPES=disk-full
export FAILROOM_LOCAL_TOKEN_EXPIRES_AT="$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%S+00:00)"
export FAILROOM_CLEANUP_RETRY_SECONDS=5
export FAILROOM_MAINTENANCE_INTERVAL_SECONDS=30
export FAILROOM_MAINTENANCE_LIMIT=10
```

| Test module | Opt-in flag | What it proves |
| --- | --- | --- |
| `test_linux_docker_integration.py` | `FAILROOM_DOCKER_INTEGRATION=1` | Provisioning through the orchestrator, container hardening, Docker's init as PID 1 from a read-only mount, Leave and Reset cleanup with every generation absent afterwards, and a PID 1 that outlives 60 seconds and stops by the attempt deadline |
| `test_linux_disk_full_integration.py` | `FAILROOM_DOCKER_INTEGRATION=1` | The Disk Full filler reduces workspace capacity and recovery restores it; the test builds the Disk Full image itself |
| `test_linux_terminal_integration.py` | `FAILROOM_TERMINAL_INTEGRATION=1` | Input and output, ANSI bytes, resize, Ctrl+C interruption, one-time capability replay denial, termination and reaping of the shell's session and background jobs after disconnect, and refusal with `4429` of a terminal beyond the profile's connection or session limit until one closes, through a real PTY |
| `test_linux_local_runtime_integration.py` | `FAILROOM_LOCAL_RUNTIME_INTEGRATION=1` | Enter Room, capability, terminal, recovery verification, Reset Room, and Leave Room through the local app; denial of unreviewed and unauthorized Rooms, of a reused capability, and of a capability issued before a reset; reset maintenance; and a terminal that stays responsive for 70 seconds |

Run one module, or every module whose flags are set:

```sh
uv run --locked python -m unittest discover -s tests -p 'test_linux_terminal_integration.py' -v
uv run --locked python -m unittest discover -s tests -p 'test_linux_*.py' -v
```

Use the `discover` form. The terminal and Disk Full modules import shared
helpers from `test_linux_docker_integration` by module name, so a dotted run
such as `python -m unittest tests.test_linux_terminal_integration` cannot import
them.
