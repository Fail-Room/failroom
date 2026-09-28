# Failroom State Store

Internal Phase 1 SQLite persistence for trusted services. This package stores
authority, lifecycle observations and recovery work. It owns immutable runtime
operation bindings and explicit v1-to-v2, v2-to-v3 and v3-to-v4 migrations. The trusted
attachment-lease state contract is implemented here; it does not implement an HTTP
API, authentication, signed-capability transport, Docker operations, a PTY, or a
background scheduler. The trusted control-plane package
consumes these records but owns Docker side effects; this package never imports
or invokes a Docker client. It includes a synchronous cleanup pass with an injected runtime verifier. It is not a running Failroom application.

## Ownership

| Table | Writer | Stored contract |
| --- | --- | --- |
| `room_attempts` | `BackendStore` | Room ownership, preallocated sandbox identity and generation, immutable runtime operation binding, active binding, state/version, session epoch, immutable deadline and provisioning/expiry/destroy intents. |
| `sandbox_resources` | `ControlPlaneStore` | Exact backend-reserved tuple, immutable runtime operation binding, resource state/version, container identity, matching deadline, expiry/destroy intents and trusted evidence references. |
| `terminal_capability_uses` | `BackendStore` | SHA-256 hash of consumed `jti`, attempt binding, consumed time and expiry. No raw `jti` or signed token. |
| `terminal_attachment_leases` | `ControlPlaneStore` | Consumed short-lived lease bound to a consumed `jti` hash, exact tuple, session epoch and hashed gateway session. No raw token or session ID. |
| `lifecycle_operations` | Operation owner | Actor-scoped idempotency key, request fingerprint, prior receipt, exact tuple, cleanup retry time/count and fixed failure code. |

Physical storage is shared; record ownership is not. Backend code cannot mutate
resource records through its repository, and control-plane code cannot overwrite
attempt authority. Python objects and SQLite access are not a security boundary
against other code running with the same trusted service account.

## Trusted inputs

`UserIdentity` must be constructed from authenticated identity and server-owned
Room authorization. `ServiceIdentity` must come from authenticated service
identity and server-granted role/action scopes. Never deserialize these contexts
from browser, sandbox, or unauthenticated service payloads. Identifiers alone are
not credentials. This package does not authenticate callers; the control plane's
local routes authenticate one local bearer credential with the verifier in
`services/api/`.

`CapabilityClaims` must originate from an already signature-verified, short-lived
capability. `consume()` rechecks owner, active tuple, generation, session epoch,
both records' attachable states, scope and expiry, then inserts the `jti` hash in
one write transaction. Only one concurrent consumption succeeds. This does not
open a WebSocket or authorize a PTY: the lease contract is a trusted state boundary,
but transport authentication, PTY runtime checks and lease invalidation are still
mandatory. The bounded signing/verification codec lives in `services/api/` and
HTTP issuance in the control plane; key distribution and replay-record retention
policy are not implemented.

Every time-dependent method requires `now`, a trusted zero-argument clock callable
returning an aware `datetime`, such as `lambda: datetime.now(UTC)`. It is invoked
after acquiring the SQLite writer lock, so lock waiting cannot preserve a stale
request-time authorization. It must be fast, local, nonblocking and independent
of learner input. Fixed clocks are for tests only. Time is stored as integer UTC
microseconds. Runtime adapters must separately check time before and after their
side effects; database receipts are not runtime allocation or attachment permits.

`READY` and `DESTROYED` resource observations require a well-formed SHA-256
evidence reference. A trusted runtime verifier must establish readiness or the
absence of every owned container, process, PTY, volume, network and session before
calling them. A digest's syntax is not proof, and these tests use synthetic
references. `FAILED` requires one of `CREATE_FAILED`, `START_FAILED`,
`RUNTIME_UNAVAILABLE`, or `CLEANUP_INCOMPLETE`; raw exception messages are rejected.

## Schema and migration contract

Fresh databases use schema v4. Operator-only migrations upgrade an existing
database one version at a time, each with a new absolute backup path:
`Database.migrate_v1_to_v2()`, `Database.migrate_v2_to_v3()`, which adds the
attachment-lease table, and `Database.migrate_v3_to_v4()`, which adds reset
generations (active and candidate sandbox pointers and reset intent). A v1
database reports `MIGRATION_REQUIRED`. v2 and v3 databases still open, but
current state operations, including `create()`, use v4 columns, so upgrade them
to v4 before use. Migrations preserve existing rows and never issue runtime
identities.

## Transaction and replay contract

- `create()` atomically persists the backend-generated attempt/sandbox tuple,
  generation 1, future absolute deadline and operation receipt before any resource
  record is accepted.
- Reset Room is the only transition that gives an attempt a new generation.
  `begin_reset()` accepts only a `READY`, `RUNNING` or `RESOLVED` attempt without
  destroy intent whose active tuple matches. It revokes the active generation by
  moving the attempt to `RESETTING` and incrementing the session epoch, so
  earlier capabilities stop working, and records a backend-generated sandbox ID
  and the next generation as the candidate. Only the old active resource may
  then be cleaned up, and the candidate is accepted for provisioning only after
  that resource is `DESTROYED`. `publish_reset_ready()` makes the candidate the
  active binding only after it is `READY`, and `fail_reset()` records `FAILED`
  after the candidate failed with destroy intent.
- Initialization creates version 4 only in an empty database. Unknown application
  IDs, existing unrelated objects, or unsupported schema versions are refused.
- An exact version 1 database is left untouched at startup and reports
  `MIGRATION_REQUIRED`. An operator must call `Database.migrate_v1_to_v2()` with a
  new absolute backup path; the method validates the legacy shape and integrity,
  creates a committed pre-migration backup, then applies the atomic schema change.
- Each migration entry point accepts only the exact previous version and shape.
  Tampered, corrupt, or already-migrated databases are rejected. There are no
  automatic migrations or schema resets.
- Each call uses a fresh connection, foreign keys, `BEGIN IMMEDIATE`, full
  synchronization and bounded lock waiting. Initialization enables WAL. SQL
  triggers prevent extending deadlines, changing owners or Rooms, changing an
  attempt's tuple outside the reset transition above, changing a resource
  record's tuple, lowering session epochs, clearing cleanup intents, or leaving
  `DESTROYED`.
- Resource transitions use expected tuple and version under the writer lock.
  The backend independently publishes the exact resource as active after `READY`.
  A failed generation can only progress toward cleanup.
- The same actor/key and request fingerprint returns the original receipt without
  repeating a mutation. Changed action/target/body conflicts. Some replay paths
  still deny when current expiry or destroy authority forbids the action. A
  receipt is a historical result, never authority to repeat a runtime side effect.
- Leave Room revokes the session epoch and persists destroy intent once. Expiry
  records both intents. An elapsed-TTL denial persists cleanup intent in the
  owner's existing record rather than rolling it back. A denied first resource
  acceptance leaves the reserved attempt/deadline for expiry and reconciliation.
- SQLite errors become bounded `STORE_BUSY` or `STORE_FAILURE` codes without SQL,
  host paths or raw exception text. A busy error is not a cleanup success.

## Recovery integration contract

Authenticated service integration must perform all of these steps on startup and
continue bounded retries during operation. These repository methods and the
injected cleanup pass do not schedule themselves or enforce a deadline while
every service is down.

1. Backend calls `expire()` in bounded batches to persist due attempt intents and
   revoke terminal access. Control-plane methods independently reject expired
   resources even before that sweep catches up.
2. Control plane calls `reconcile()` for due cleanup work. It discovers exact
   reserved tuples even if create stopped before inserting a resource row. It
   does not scan Docker or adopt unexpected identities. Repeated calls return the
   same pending cleanup operation; multiple workers must use that operation ID and
   tuple for idempotent runtime removal, not infer an exclusive work lease.
3. An unsuccessful cleanup calls `cleanup_failed()` with expected version, an
   idempotency key, fixed failure code and future retry time. Intent persists and
   the same work becomes eligible again. Batches are limited to 1–1000 records;
   workers must advance successful work or defer failed work before requesting
   the next batch to avoid repeatedly processing the first record.
4. After actual absence verification, the control plane records `DESTROYED` with
   its evidence reference. Backend calls `complete_cleanup()` independently.
5. Backend drains `pending_finalizations()` as well. This recovers a crash between
   the resource's destruction record and the attempt's final state update.

`DockerCleanupWorker(control, backend, runtime, retry_delay=...)` implements one
bounded pass of steps 2–5. Its `run_once(control_identity, backend_identity,
now=..., limit=...)` first validates control-plane `RECONCILE`, `INSPECT` and
`TRANSITION` scopes and backend `RECONCILE` and `PUBLISH` scopes. It drains pending
finalizations before requesting due cleanup work; the combined number of selected
records cannot exceed `limit` (1–1000). Before a runtime call, a fresh exact-tuple
inspection must still match the task version, `STOPPING`, and destroy intent.

The injected `CleanupRuntime.destroy_and_verify_absent(CleanupTarget)` receives
the reserved `ResourceRef`, optional container ID, nullable original `runtime_operation_id`,
and durable cleanup operation ID. A missing container ID still requires verification,
including interrupted create discovery by exact tuple. The cleanup operation ID is **not** the original
create-operation label; the runtime must resolve and validate creation labels
separately. The runtime must implement bounded, idempotent removal and verify
absence of every owned container, process, PTY, volume, network and session before
returning canonical `sha256:<64 lowercase hex>` evidence. This package imports
no Docker client and supplies no runtime verifier or service wiring.

Only verified absence followed by a successful version-checked `DESTROYED`
receipt permits backend completion. Runtime failures and malformed evidence
persist only `RUNTIME_UNAVAILABLE` or `CLEANUP_INCOMPLETE`, retain destroy intent,
and schedule a future retry using the explicit positive `timedelta` delay. Raw
exceptions become `CLEANUP_INCOMPLETE` without storing their text. Store contention
and concurrent state/version changes defer the affected operation without
recording a runtime failure. If writer-lock waiting consumes the retry interval,
the rejected retry record leaves work pending for a later pass. Deterministic
hashed keys bind each transition to the tuple, cleanup operation and observed
version; finalization keys bind the
tuple. Repeated passes recover interrupted backend completion without another
runtime call. Multiple workers may call the runtime for the same task, so this
contract does not provide an exclusive work lease.

`CleanupRun(destroyed, deferred, finalized)` counts successful destruction and
backend-completion receipts and deferred operations. Destruction and completion
can count the same tuple; a failed batch scan counts as one deferral. No internal
loop, sleep or automatic retry runs after the pass returns. The injected-runtime
tests establish SQLite orchestration behavior, not actual Docker removal or
isolation evidence.

The control plane's operator-only local runtime wires these contracts to Docker
creation, reset and verified cleanup for the Disk Full Room. It creates those
sandboxes without final-image qualification, which is a documented limitation
of that proof of concept, not a qualified learner allocator. Docker
inventory-wide orphan detection, runtime attachment lease race coverage and TTL
enforcement while every service is down also remain open: a container's PID 1
exits no later than the attempt deadline, but removing the container waits for
the next maintenance pass.

## Local checks and database placement

Python 3.12.13; no runtime dependencies. Development dependencies are pinned in
`uv.lock`. From this directory:

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy failroom_state
```

Tests use disposable OS-temporary databases, real independent SQLite connections,
concurrent callers, and child processes. They cover restart, abrupt exit before
commit, rollback after a statement failure, writer-lock expiry, the supported
resource-transition matrix, idempotency, ownership, consumption and recovery.
They do not prove runtime isolation, signed-token security or physical cleanup.

`Database` requires an explicit absolute file path and a 1–30000 ms busy timeout.
The trusted operator must provision a private local directory with restrictive
service-account permissions. Do not use a synchronized checkout, iCloud/OneDrive,
network filesystem, sandbox-accessible path, or sandbox mount. This package does
not configure OS ACLs or detect sync software; startup integration must validate
deployment permissions and placement before using it. The database and adjacent
WAL/journal files are private state, never repository artifacts.

No persistent service database is created by installation or these checks. For a
future deployed database, stop writers and use a consistent SQLite backup before
changes. Never delete its WAL or reset the schema to resolve a failure: this can
discard committed authority and pending cleanup. Unknown versions must remain
untouched until an explicitly reviewed migration or recovery is available.
