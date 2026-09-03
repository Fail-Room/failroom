# Sandbox

## Status and Scope

This document is the planned lifecycle, terminal, isolation, and cleanup contract for Failroom sandboxes. Phase 0 implements none of it. Phase 1 will prove one minimum secure terminal slice with one authoritative attempt record, backend-preallocated resource identity, one-time capability, backend introspection, control-plane attachment lease, bounded resources, explicit destroy, and durable absolute-TTL cleanup. The Phase 1 cleanup baseline persists `expires_at`, expiry intent, and destroy intent, reconciles owned runtime resources on startup, and resumes expiry or destroy until verified destruction. Phase 2 will generalize that slice into reset, multiple concurrent sandboxes, the complete reusable state machine and transition/race matrices, and broader reconciliation.

A sandbox is an internal disposable runtime resource for one Room attempt. It is not a product identity, an authorization credential, or a durable user environment.

## Responsibilities

- The backend API authenticates the caller and owns the authoritative Room attempt record: user ownership, attempt status, active and pending sandbox identities and generations, provisioning/reset intent, `session_epoch`, idempotency key, and immutable expiry deadline. It preallocates and persists every expected `sandbox_id` and generation before create.
- The trusted sandbox control plane owns each sandbox resource record and its lifecycle state, then creates, observes, stops, destroys, expires, and reconciles the corresponding runtime resource. It must create the backend-requested identity exactly and never allocate or substitute a sandbox ID or generation.
- The terminal gateway validates a signed terminal capability, confirms its claims against the backend's current authoritative record, and connects the authorized browser session to the matching PTY.
- The scenario system supplies validated, minimally declarative configuration for the initial state, limits, signals, and success checks.
- The untrusted sandbox runs Ubuntu, `/bin/bash`, learner commands, and scenario processes within its assigned boundaries.

The control plane reports observed runtime state only to authenticated trusted backend or control-plane service identities; it does not trust or serve browsers or sandboxes. The backend maps that resource state into a filtered learner-visible attempt status after revalidating authenticated user and Room ownership, but cannot overwrite the control plane's resource record.

## State Machine

The planned sandbox resource lifecycle is:

```text
REQUESTED → CREATING → STARTING → READY → RUNNING → RESOLVED → STOPPING → DESTROYED
CREATING | STARTING | STOPPING → FAILED
REQUESTED | CREATING | STARTING | READY | RUNNING | RESOLVED | FAILED → STOPPING → DESTROYED
```

`RESETTING` is not a state of an existing sandbox resource. It is a Room attempt status owned by the backend while the old resource follows `STOPPING → DESTROYED` and a replacement resource follows `REQUESTED → CREATING → STARTING → READY`. The backend may also use `PROVISIONING`, `READY`, `RUNNING`, `RESOLVED`, `STOPPING`, `DESTROYED`, and `FAILED` as attempt statuses mapped from the active or candidate resource; identical labels in the two records do not transfer authority.

| State | Meaning |
| --- | --- |
| `REQUESTED` | The control plane accepted the exact backend-preallocated `sandbox_id` and generation, but no runtime allocation has begun. |
| `CREATING` | The control plane is allocating isolated runtime, filesystem, network, and resource controls. |
| `STARTING` | The resource exists and startup plus readiness checks are running. |
| `READY` | The sandbox passed readiness checks and may accept an authorized terminal attachment. |
| `RUNNING` | The Room attempt has begun; terminal disconnect does not by itself erase attempt state. |
| `RESOLVED` | Trusted success checks verified the recovery condition. |
| `STOPPING` | Terminal access is revoked and resource teardown is in progress. |
| `DESTROYED` | Teardown has been verified and the sandbox is terminally unavailable. |
| `FAILED` | A create, start, or stop operation failed. The same resource generation may perform cleanup only. |

## Valid Transitions

- `REQUESTED → CREATING`: the control plane begins allocation.
- `CREATING → STARTING`: the isolated resource and its mandatory controls exist.
- `STARTING → READY`: startup and readiness checks pass.
- `READY → RUNNING`: the authorized attempt begins.
- `RUNNING → RESOLVED`: trusted scenario checks verify the recovery condition.
- `RESOLVED → STOPPING → DESTROYED`: completion policy or Leave Room removes the resource.
- `CREATING | STARTING | STOPPING → FAILED`: the active resource operation fails and records its reason.
- `REQUESTED | CREATING | STARTING | READY | RUNNING | RESOLVED | FAILED → STOPPING → DESTROYED`: expiry, cancellation, explicit leave, or cleanup takes priority from every nonterminal resource state.

Every transition is compare-and-set against the authoritative resource state and generation, records actor, operation ID, idempotency key, and reason, and is safe against duplicate requests. Duplicate idempotency keys return the prior operation result. A stale expected state or generation fails without side effects. `DESTROYED` has no outgoing transition.

Before the resource can enter `REQUESTED`, the backend must persist the same expected sandbox ID, generation, operation, idempotency key, immutable deadline, and provisioning or reset intent in the authoritative Room attempt record. `POST /sandboxes` cannot allocate or substitute either part of the tuple.

For the Room attempt record, Reset Room uses `READY | RUNNING | RESOLVED → RESETTING → READY`; reset failure uses `RESETTING → FAILED`; expiry uses any nonterminal attempt status, including `PROVISIONING` and `RESETTING`, to enter `STOPPING → DESTROYED`. An explicit initial-create retry uses attempt `FAILED → PROVISIONING`, while an explicit reset retry uses `FAILED → RESETTING`. Each starts a new operation and resource generation; neither resumes a `FAILED` resource.

## Invalid Transitions

Any transition not listed above is invalid and must be rejected without partial side effects. Examples include creation under a control-plane-selected or conflicting resource identity, terminal attachment before resource `READY`, direct `RUNNING → DESTROYED`, `FAILED → CREATING`, reusing a failed resource generation for create or reset, resolving from a client claim, and returning a destroyed resource to service.

Concurrent create, reset, destroy, and expiry operations serialize through compare-and-set updates on the Room attempt and generation-checked, idempotent resource operations. Expiry intent has priority. A losing request receives the authoritative current state or a conflict response; it cannot publish `READY`, clear expiry, swap the active sandbox, or start an untracked resource operation.

## Planned Internal API

The lifecycle HTTP endpoints below, together with the final attachment-lease endpoint, are internal, service-authenticated sandbox control-plane APIs. They describe intent and may be versioned before implementation:

```http
POST /sandboxes
GET /sandboxes/{sandbox_id}
DELETE /sandboxes/{sandbox_id}
POST /sandboxes/{sandbox_id}/terminal-attachment-leases
```

- `POST /sandboxes` accepts the exact backend-preallocated `sandbox_id` and generation plus attempt ID, scenario version, resource and network policy, immutable expiry deadline, and idempotency key. The control plane creates and returns that exact tuple or idempotently returns the existing matching operation result. It rejects a tuple or idempotency conflict and never allocates a different identity.
- `GET /sandboxes/{sandbox_id}` returns observed state, generation, bounded resource metadata, and failure information only to authenticated trusted backend or control-plane service identities. It is never directly callable with user credentials.
- `DELETE /sandboxes/{sandbox_id}` requires the expected generation and idempotency key and is idempotent. Repeated calls converge on verified `DESTROYED` without granting information to unauthorized callers.
- `POST /sandboxes/{sandbox_id}/terminal-attachment-leases` is called by the authenticated gateway after backend authorization. Immediately before PTY creation or attachment, the control plane verifies `sandbox_id`, `attempt_id`, and `generation` binding; resource state `READY` or `RUNNING`; immutable TTL; and absence of durable expiry, destroy, or reset intent. It atomically issues and consumes a short-lived scoped lease bound to the consumed `jti` and gateway session context, then hands that context directly to PTY creation as one authorize-and-attach operation. `STOPPING`, `FAILED`, expired, stale-generation, and reused requests are rejected.

The backend also exposes this authenticated internal authorization contract to the gateway:

```http
POST /internal/terminal-authorizations/verify-and-consume
```

It accepts capability claims and gateway connection context, permits only an exact match with current ownership, attempt status, `active_sandbox_id`, `generation`, and `session_epoch`, and atomically consumes the capability's unique `jti`. Only a non-reversible `jti` hash, status, and expiry are retained. Concurrent or later reuse is rejected even within the same generation and session epoch.

The conceptual browser-facing gateway endpoint is separate from those service-authenticated APIs:

```http
WS /sandboxes/{sandbox_id}/terminal
```

It is authenticated by a short-lived signed, single-use terminal capability containing unique `jti`, `user_id`, `attempt_id`, `sandbox_id`, `generation`, `session_epoch`, `expiry`, and `scope`. The gateway validates signature, expiry, and scope locally, then calls the authenticated verify-and-consume contract. The exact public route and WebSocket transport framing remain Phase 1 decisions.

The backend owns the learner-facing status and reset facades. Their exact public routes may change, but their conceptual contracts are:

```http
GET /rooms/{attempt_id}/status
POST /rooms/{attempt_id}/reset
```

The status facade revalidates authenticated user and Room ownership, reads control-plane state through the trusted internal inspect API, and returns filtered attempt and health information. The reset facade validates ownership and state, then runs the backend compound orchestration described below. It is not forwarded as a compound control-plane reset mutation.

For every user-facing HTTP path, the backend validates authenticated user, Room ownership, allowed action, and current attempt binding independently of the sandbox ID. A sandbox ID is never authorization. Internal control-plane calls accept only authenticated trusted service identities; mutations additionally require action scope, the backend-preallocated resource identity and generation, and an idempotency key, all compared with the authoritative resource record before side effects. WebSocket attachment follows the one-time capability and final lease checks above. Raw capabilities and leases are never logged.

Phase 1 may implement internal calls as in-process interfaces, but it must preserve the same request fields, one-time consumption, final attachment lease, authority checks, compare-and-set behavior, and trust contract.

## Terminal Session Contract

The terminal is a real PTY attached to `/bin/bash` inside the sandbox. It supports stdin, combined PTY output from stdout and stderr, ANSI sequences, colors, shell history within the attempt, terminal resize, Ctrl+C and allowed signals, interactive programs, and long-running commands.

The protocol distinguishes input bytes, output bytes, resize requests, permitted signal requests, readiness, closure, and errors. Resize dimensions, message size, output buffering, rate, and concurrent connection and session counts are bounded. Malformed or unauthorized control messages are rejected.

The gateway binds each session to the consumed `jti`, gateway session context, user, Room attempt, sandbox ID, generation, session epoch, scope, and expiry after the authoritative backend check. It then obtains the control-plane attachment lease and creates or attaches the PTY only through that atomically consumed lease. Reset, destroy, expiry, ownership loss, and capability revocation close the PTY attachment.

On network disconnect, the gateway closes the terminal session, invalidates its attachment lease, closes and reaps its PTY and shell process group, releases buffers, and decrements connection accounting. The Room and sandbox persist only according to an explicit reconnect window, Leave Room policy, and immutable absolute TTL. A transient disconnect does not by itself imply environment teardown; reconnect requires a new one-time capability and new attachment lease and creates a fresh PTY unless a separately reviewed resumable-session contract is introduced.

Output must come from the PTY. Fake terminal responses, predefined command-output mappings, and host command execution are prohibited.

## Isolation and Resource Contract

Every sandbox must have a separate process, filesystem, network, and runtime identity with finite CPU, memory, PID, storage, I/O, terminal-output, network, concurrent terminal connection and session, and absolute-lifetime limits. The shell runs as a non-root user without privileged mode or unnecessary capabilities.

The sandbox receives no `/var/run/docker.sock` or Docker, Podman, containerd, CRI, or other host runtime control socket, host shell, broad host filesystem mount, host credential, control-plane credential, or direct control-plane access. It cannot discover, connect to, inspect, or mutate another sandbox. Network access is denied by default or restricted to an explicit scenario allowlist.

Scenario storage limits must make a Disk Full condition genuine inside the assigned filesystem without risking unbounded host consumption. A fake command-output path cannot substitute for runtime behavior.

## Reset Strategy

`RESETTING → READY` is a Room attempt operation visible to the client, not a transition applied to an existing sandbox resource. Reset is destroy-and-recreate across the backend-owned attempt record and control-plane-owned resource records:

1. If no durable expiry intent exists, the backend compare-and-sets the attempt from `READY`, `RUNNING`, or `RESOLVED` to `RESETTING`, records a new reset operation and idempotency key, and increments `session_epoch` to reject every existing capability.
2. The backend calls the internal `DELETE /sandboxes/{sandbox_id}` with the old expected generation and idempotency key. The control plane durably records reset and destroy intent on that exact resource before teardown; from that point, a racing terminal attachment lease is rejected.
3. The gateway closes every terminal session and PTY for the old sandbox generation.
4. The control plane advances the old resource through `STOPPING → DESTROYED` and verifies removal of its processes, writable storage, and network allocation.
5. The backend preallocates a new `sandbox_id` and generation and compare-and-sets that tuple into the reset operation with the immutable attempt deadline, a create idempotency key, and an unchanged absence of expiry intent. Only after that durable update does it call the normal `POST /sandboxes` contract with the exact tuple. The replacement independently follows `REQUESTED → CREATING → STARTING → READY`.
6. After the control plane authoritatively reports the candidate `READY`, the backend compare-and-sets the still-`RESETTING` attempt with unchanged operation, session epoch, and no expiry intent. In one atomic update it swaps `active_sandbox_id` and `generation` to the replacement and sets attempt status `READY`.

The replacement is a different sandbox resource. Old IDs do not alias it, and stale terminal capabilities are rejected even if a runtime reuses an underlying name or address. While reset is in progress, the old active fields are retained only as nonattachable cleanup references; the attempt status and new session epoch prevent use.

If old-resource destruction or replacement creation fails, the backend does not bind the candidate. It records attempt `FAILED`, retains old and candidate operation references for cleanup and reconciliation, and reports a stable failure code. A lost create response is reconciled by querying or retrying the same preallocated tuple and idempotency key, never by accepting a different identity. An explicit reset retry compare-and-sets `FAILED → RESETTING` with a new operation ID, idempotency key, session epoch, and backend-preallocated resource tuple. It never resumes a `FAILED` resource generation. Durable expiry intent prevents every remaining reset step and drives all referenced resources to destruction.

## Cleanup and TTL

Cleanup is required after Leave Room, completion policy, reset, create or start failure, terminal failure where policy requires it, explicit destroy, absolute TTL expiry, and control-plane restart reconciliation. Disconnect cleans the terminal session and PTY but does not automatically destroy the environment; it never extends the absolute TTL.

Destroy first revokes access, then terminates the process tree, removes writable storage and network allocations, releases resource accounting, and verifies absence from the runtime. The operation is idempotent and retryable. Bounded retries use durable cleanup intent, and exhausted retries produce an alert plus an orphan record for reconciliation.

The backend persists an immutable `expires_at` on the Room attempt before any resource allocation, and every resource record receives the same deadline. Client traffic, reconnect, reset, and retry cannot extend or replace it.

At expiry, the backend durably records expiry intent and compare-and-sets any nonterminal attempt status, including `PROVISIONING` or `RESETTING`, to `STOPPING`. The control plane durably records the same intent for every old, active, or candidate resource. It may move any nonterminal resource from `REQUESTED`, `CREATING`, `STARTING`, `READY`, `RUNNING`, `RESOLVED`, or `FAILED` to `STOPPING`; an existing `STOPPING` operation continues.

Lifecycle workers check the immutable deadline and expiry intent before and after every side effect and before publishing a state transition. Create, start, reset, and ready-completion compare-and-set operations include the expected record version, generation, operation ID, and absence of expiry intent. Losing work may have created a partial runtime, but it cannot clear expiry, publish `READY`, or swap `active_sandbox_id`; it must register the resource for cleanup.

Expiry intent remains persisted and is retried across service restarts and stop failures until every associated resource is verified `DESTROYED` and the attempt is terminal. A stop failure may record resource `FAILED`, but the next same-generation operation is idempotent cleanup only. Cleanup metrics and structured events include reason, previous state, sandbox generation, operation and idempotency identifiers, duration, retry count, and final outcome without secrets.

Reconciliation joins backend provisioning and reset intents to control-plane resource records by the preallocated sandbox ID and generation. A missing response is resolved by inspecting or retrying the same tuple with the same idempotency key. A runtime or resource record without a matching backend intent is quarantined from terminal attachment and destroyed idempotently. A tuple conflict is reported; neither side invents or adopts a replacement identity.

## Failure Handling

- A resource failure in `CREATING`, `STARTING`, or `STOPPING` records a stable reason and transitions that resource generation to `FAILED`. A reset failure records `FAILED` on the separate Room attempt record.
- Partial resources remain cleanup candidates; resource `FAILED` never means they are absent.
- `FAILED → STOPPING → DESTROYED` retries idempotent cleanup for the same resource generation. A stop failure returns to `FAILED` with updated evidence and preserves cleanup or expiry intent.
- A create or reset retry uses a new operation ID, idempotency key, and resource generation beginning at `REQUESTED`. It cannot transition a failed resource back to `CREATING` or `STARTING`.
- From Phase 1 onward, process or service startup reconciliation compares authoritative Room intents and deadlines with owned runtime resources before allowing terminal attachment, then resumes pending expiry or destroy work until verified destruction. Phase 2 broadens this to replacement resources, multiple concurrent sandboxes, leases, capabilities, terminal sessions, and every lifecycle transition.
- Readiness failure never exposes a terminal. Gateway or PTY failure closes only the affected session unless lifecycle safety requires sandbox destruction.
- API responses provide stable error codes and correlation IDs without runtime secrets or cross-user details.

## Phase 1 Acceptance Criteria

- [ ] An authorized browser uses xterm.js through a WebSocket and real PTY to reach `/bin/bash` in an isolated Ubuntu sandbox.
- [ ] The backend persists one authoritative attempt with a preallocated `sandbox_id`, generation, provisioning intent, idempotency key, and immutable deadline before create; the control plane creates and returns only that exact tuple.
- [ ] Before attachment, the gateway validates every signed capability field, atomically consumes its unique `jti`, and confirms current ownership, attempt status, active sandbox, generation, and session epoch through the backend's authenticated contract.
- [ ] Concurrent replay of one capability opens at most one WebSocket, and reconnect requires a new capability.
- [ ] Immediately before PTY creation, the control plane grants one consumed-`jti`-bound attachment lease only for the matching attempt and generation in `READY` or `RUNNING`, with valid TTL and no expiry, destroy, or reset intent; it rejects `STOPPING`, `FAILED`, expired, stale-generation, and reused requests.
- [ ] `whoami`, `pwd`, `ls`, `ps aux`, `free -m`, and `df -h` execute in the sandbox and return real output.
- [ ] ANSI colors, shell history, interactive input, long-running commands, Ctrl+C, and terminal resize behave correctly.
- [ ] Disconnect closes and reaps the terminal session and PTY, releases connection accounting, and preserves or tears down the Room only according to the explicit reconnect, Leave Room, and TTL policy.
- [ ] Sandbox destruction removes the complete process tree and runtime resource.
- [ ] Absolute TTL and explicit idempotent destroy remove the single-slice resource even after a lost create response, using the same preallocated tuple for recovery.
- [ ] `expires_at`, expiry intent, destroy intent, and owned resource identity survive process or service restart in authoritative storage; startup reconciliation resumes cleanup and verifies that no orphan survives its deadline.
- [ ] The sandbox cannot access any Docker, Podman, containerd, CRI, or other host runtime control socket, host shell, host filesystem, host or control-plane credential, or another sandbox.
- [ ] Bounded CPU, memory, PID, storage, I/O, terminal output, network, concurrent terminal connections and sessions, and absolute lifetime are configured and exercised.
- [ ] No fake command or terminal response exists in the browser, API, gateway, or scenario path.

## Phase 2 Acceptance Criteria

- [ ] The Phase 1 create, terminal attachment, TTL, and destroy contracts are generalized into reusable ownership-aware lifecycle operations without weakening their authority boundaries.
- [ ] User-facing inspect and reset facades validate Room ownership; internal inspect accepts only authenticated trusted service identities and returns no direct user response.
- [ ] The signed terminal capability contains every required claim, is single-use by `jti`, and the gateway atomically consumes it against current authoritative backend state before PTY attachment.
- [ ] The final attachment lease rejects resource `STOPPING` or `FAILED`, expired TTL, stale attempt or generation, reused lease, and lifecycle-intent races.
- [ ] Two concurrent sandboxes cannot discover, connect to, inspect, or mutate each other.
- [ ] Every declared lifecycle transition succeeds under its preconditions, and every invalid transition is rejected without side effects.
- [ ] Reset deterministically recreates the initial scenario, atomically swaps the active sandbox only after replacement readiness, and rejects stale capabilities through generation and session epoch.
- [ ] Destroy is idempotent and verified to clean processes, filesystems, networks, sessions, and resource accounting.
- [ ] Absolute TTL wins races from every nonterminal attempt and resource state, cannot be cleared by losing work, destroys all old and candidate resources, and survives restart until verified cleanup.
- [ ] Concurrent reset, destroy, attach, and expiry requests resolve to one consistent Room and sandbox state.
- [ ] A failed resource generation permits only idempotent cleanup; create and reset retries begin a new operation and resource generation.
- [ ] The Phase 1 durable startup reconciliation and expiry baseline is generalized across reset and multiple concurrent sandboxes, retries lost responses by exact tuple, removes unreferenced resources, and never adopts a control-plane-selected identity.
