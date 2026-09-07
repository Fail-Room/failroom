# Architecture

## Status and Scope

This document defines the architecture for Failroom. Phase 0 established documentation and repository rules. Phase 1 implements an internal profile qualification evaluator in `services/sandbox-engine/` and SQLite repositories in `packages/state-store/`. No web/API application, terminal gateway, sandbox runtime, authentication system, or deployment is implemented.

The [qualification module](../services/sandbox-engine/README.md) evaluates trusted per-check evidence against the current runtime, image and profile fingerprints and an explicit maximum age. Its raising guard rejects incomplete, failed, malformed, stale or mismatched reports. It has no runtime side effects and cannot replace authentication, ownership, generation, lifecycle or final attachment authorization. Evidence collection and invocation from a real allocation adapter remain unimplemented.

The first implementation target is one secure browser-to-sandbox terminal path. Next.js, xterm.js, and FastAPI are planned architecture choices. Phase 1 selects and locks their concrete versions, manifests, dependency tooling, and integration layout. It implements the minimum secure slice: one authoritative attempt record, a backend-preallocated resource identity, one-time terminal capability, backend introspection, control-plane attachment lease, bounded resources, immutable absolute TTL, explicit destroy, and durable cleanup. That cleanup persists `expires_at`, expiry intent, and destroy intent in authoritative storage, reconciles owned runtime resources against records on service startup, and resumes expiry or destroy work until verified destruction so no orphan survives its deadline. Phase 2 generalizes this baseline into reset, multiple concurrent sandboxes, the complete reusable lifecycle state machine and transition/race matrices, and broader reconciliation. The component boundaries below are logical contracts; Phase 1 may colocate processes, but it must preserve the same authorization and trust boundaries.

## Implemented Persistence Boundary

The [state store](../packages/state-store/README.md) uses four SQLite tables: backend-owned `room_attempts` and `terminal_capability_uses`, control-plane-owned `sandbox_resources`, and an operation-owner `lifecycle_operations` log. Backend preallocation, ownership checks, exact tuple matching, compare-and-set resource transitions, immutable TTL, epoch revocation, request-fingerprint idempotency and atomic consumed-jti hashing are implemented at the repository boundary. Resource and attempt updates remain separate even though their transactions use one private local database.

These APIs require already authenticated contexts and verified capability claims from trusted callers; they do not implement authentication or signature verification. A trusted Clock is sampled after obtaining the writer lock. Resource readiness and destruction accept trusted evidence references, not sandbox assertions. Receipts are historical database results and cannot authorize allocation or attachment. Reset, runtime probes, lease consumption, workers and independent TTL enforcement remain unimplemented.

Cleanup intent and retry records survive reopening. Control-plane reconciliation enumerates reserved cleanup tuples, including interrupted creates without a resource row. Backend finalization has its own recovery query for interruptions after resource destruction was recorded. Actual inventory inspection, orphan removal and physical absence verification must be integrated before learner access. Store database and journal files outside synchronized source checkouts and sandbox-accessible paths.

## Decision Priorities

Architecture decisions are evaluated in this order:

1. Containment, authorization, and data integrity.
2. Authentic system behavior inside a Room.
3. Deterministic creation, reset, and cleanup.
4. A small, understandable implementation with explicit ownership.
5. Observable lifecycle and failure behavior.
6. Scale, catalog breadth, and infrastructure optimization.

Convenience or delivery speed cannot override a higher-priority property.

## Planned Logical Components

| Component | Planned responsibility |
| --- | --- |
| Web platform | A Next.js interface containing the Room experience and xterm.js client. It renders terminal bytes and sends input, resize, and signal events; it never executes learner commands locally. |
| Backend API | A FastAPI control API that owns authenticated identity, the authoritative Room attempt record, preallocation of sandbox IDs and generations, Room orchestration, issuance of short-lived signed one-time terminal capabilities, and atomic capability consumption. |
| Terminal gateway | Accepts an authorized WebSocket, validates its capability, atomically consumes it through the backend's authenticated internal contract, obtains a control-plane terminal attachment lease, and bridges terminal bytes, resize events, and signals to the matching sandbox PTY. |
| Sandbox control plane | A trusted lifecycle service that owns authoritative sandbox resource state, grants generation-bound terminal attachment leases, and has narrowly controlled runtime access for create, inspect, stop, destroy, TTL enforcement, and scenario provisioning. |
| User sandbox | An untrusted, disposable, isolated Ubuntu environment running `/bin/bash` and scenario workloads under strict limits. |
| Scenario system | Minimally declarative Room configuration for image selection, bounded resources, initial failure state, health signals, and success checks. It is not a general-purpose workflow engine. |
| PostgreSQL | Future durable storage for users, Room attempts, ownership, and reports. It is not required by the Phase 1 proof of concept. |

## Trust Boundaries

- The browser and all learner input are untrusted. The browser cannot assert ownership, lifecycle state, sandbox generation, or completion.
- The backend API is the authority for identity and the Room attempt record: user ownership, attempt status, active and pending sandbox identities, resource `generation`, and revocable `session_epoch`. Before any create mutation, it preallocates and persists the expected `sandbox_id` and `generation` with provisioning intent. A sandbox ID is a locator, not authorization.
- The terminal gateway is trusted only to validate a signed one-time capability, atomically consume its `jti` while confirming claims against the authoritative backend record, obtain a control-plane attachment lease, and relay the authorized PTY stream. It cannot infer access from a WebSocket URL or from locally cached ownership alone.
- The sandbox control plane is trusted infrastructure and the authority for sandbox resource lifecycle state, but it does not allocate sandbox IDs or generations. Mutations require an authenticated service identity, action scope, backend-preallocated resource identity and generation, and idempotency key; a raw sandbox ID is insufficient.
- The user sandbox is hostile by default. It never receives `/var/run/docker.sock`, any host runtime control socket such as Docker, Podman, or containerd, a host shell, host filesystem mounts, host credentials, control-plane credentials, or direct control-plane access.
- Each sandbox has isolated identity, filesystem, process, network, and resource scopes. One sandbox must not discover, connect to, inspect, or mutate another.
- Future PostgreSQL access remains behind the backend API. Browsers, terminal sessions, and user sandboxes receive no direct database credentials.

## HTTP Control Flow

The planned control flow is:

```text
Authenticated user → Enter Room request → ownership check → sandbox allocation → short-lived signed terminal capability
```

1. The browser submits an authenticated Enter Room or lifecycle request to the backend API.
2. The backend validates the user, Room ownership, requested operation, and current Room state.
3. Before creation, the backend preallocates an expected `sandbox_id` and `generation` and persists that tuple with the Room attempt's provisioning intent, immutable deadline, and operation idempotency key.
4. The backend sends the exact tuple and idempotency key to `POST /sandboxes`. The control plane creates that tuple or idempotently returns the existing exact match; it never substitutes or allocates an identity, and a conflicting tuple is rejected.
5. The control plane reports authoritative observed resource state for the expected tuple. The resource identifier alone grants no access.
6. Once the attempt is attachable, the backend issues a short-lived signed terminal capability containing unique `jti`, `user_id`, `attempt_id`, `sandbox_id`, `generation`, `session_epoch`, `expiry`, and `scope`. It can open one WebSocket only.
7. Inspect, reset, and leave requests repeat the ownership and transition checks before the backend invokes the control plane.

The backend retains only the capability identifier hash, consumption status, and expiry needed for atomic replay prevention. The signed capability itself is not stored in logs.

Control-plane mutations arrive through authenticated, action-scoped service requests. The control plane compares the requested sandbox ID and generation with its authoritative resource record and deduplicates the operation by idempotency key before performing side effects.

The exact browser-facing routes are deferred. The internal lifecycle intent is defined in [SANDBOX.md](SANDBOX.md).

## Terminal Data Flow

The planned terminal path is:

```text
Browser/xterm.js → authorized WebSocket → terminal gateway → PTY → /bin/bash → isolated Ubuntu sandbox
```

1. xterm.js opens a WebSocket with the short-lived signed one-time terminal capability.
2. The terminal gateway validates its signature, expiry, and scope, then calls the backend's authenticated authorization contract.
3. The backend permits the request only when `user_id`, `attempt_id`, `sandbox_id`, `generation`, and `session_epoch` match the authoritative current Room attempt record and its status allows a terminal. In the same atomic operation, it consumes the unique `jti`; reuse is rejected even within the same generation and session epoch.
4. The gateway requests a short-lived terminal attachment lease from the sandbox control plane, binding the consumed `jti` and gateway session context to the attempt, sandbox, and generation.
5. Immediately before PTY creation or attachment, the control plane verifies the `sandbox_id`, `attempt_id`, and `generation` binding; resource state `READY` or `RUNNING`; unexpired immutable TTL; and absence of durable expiry, destroy, or reset intent. It atomically issues and consumes the scoped lease for that attachment. `STOPPING`, `FAILED`, expired, or stale-generation resources are rejected.
6. Under the consumed lease context, the trusted sandbox adapter opens or attaches to a real PTY whose shell is `/bin/bash` inside the authorized sandbox resource generation and returns the stream to the gateway.
7. Input bytes flow to PTY standard input. PTY output, including ANSI control sequences, flows back to xterm.js.
8. Resize and signal requests are validated and forwarded to the PTY. Flow control and output limits protect the gateway and browser.
9. Disconnect closes and reaps the terminal session and PTY process group. Room and sandbox teardown follows the separate reconnect, Leave Room, and absolute-TTL policies; a transient disconnect does not implicitly destroy the environment. Reconnect requires a newly issued capability.

Terminal results come from the real PTY-backed shell. Fake terminal responses, predefined command-output mappings, and command execution in the web or API layer are prohibited.

## Planned Monorepo Shape

The following shape is the target layout. The sandbox qualification and state-store modules now exist; application and runtime directories remain planned:

```text
apps/
  web/                    Next.js interface and xterm.js client
services/
  api/                    FastAPI identity, ownership, and Room control
  sandbox-engine/         terminal gateway and trusted lifecycle adapters
scenarios/                minimal declarative Room definitions
packages/
  state-store/            backend/control-plane SQLite repositories
infra/                    local and deployment infrastructure definitions
docs/                     product and engineering contracts
```

Phase 1 may colocate the backend, terminal gateway, and sandbox control-plane adapters. Even in one process, terminal attachment must atomically consume the one-time capability against the authoritative Room attempt record and obtain the final resource-state attachment lease. Lifecycle mutations must remain authenticated, scoped, generation-checked, and idempotent so later separation does not change the security contract.

## State Ownership

| State | Planned owner | Rule |
| --- | --- | --- |
| Authenticated identity and Room ownership | Backend API | Derived from validated authentication and server-side records, never browser claims. |
| Room attempt record | Backend API | Authoritative `user_id`, attempt status, `active_sandbox_id`, active generation, pending preallocated `sandbox_id` and generation, provisioning/reset intent, `session_epoch`, idempotency key, and immutable expiry deadline. |
| Sandbox resource lifecycle | Sandbox control plane | Authoritative resource state, resource generation, limits, lease deadline, operation intent, and observed runtime identity. |
| Terminal capability consumption | Backend API | Atomically records one hashed `jti` as consumed after current ownership, attempt, generation, session epoch, expiry, and scope checks. |
| Terminal attachment lease | Sandbox control plane | Atomically authorizes one immediate PTY attachment after current resource binding, state, TTL, and lifecycle-intent checks. |
| Terminal connection and PTY relay | Terminal gateway | Bound to one consumed `jti`, gateway session context, user, attempt, sandbox generation, session epoch, scope, and expiry. |
| Process, filesystem, and service state | User sandbox | Treated as untrusted evidence; never authoritative for ownership. |
| Failure setup and success checks | Scenario system | Versioned declarations interpreted by trusted code with a narrow schema. |
| Durable users, attempts, and reports | Future PostgreSQL | Accessed only through backend-owned repositories and transactions. |
| Rendered UI state | Web platform | A cached view of server state, not a source of authority. |

The two authoritative records coordinate without sharing ownership. Before initial create or replacement create, the backend preallocates and durably records the expected sandbox ID and generation in the Room attempt's provisioning intent. It then requests that exact tuple; the control plane creates and returns the same tuple or idempotently returns an existing exact match. The control plane never chooses a replacement identity. It advances and reports resource lifecycle, while the backend maps observed state into learner-facing attempt status with compare-and-set updates. A terminal is attachable only when both records agree on the active sandbox and generation.

During Reset Room, the backend owns the compound orchestration. It compare-and-sets the attempt to `RESETTING`, increments `session_epoch`, and has the control plane durably record reset and destroy intent on the old generation before issuing a generation-checked destroy. It then preallocates and persists the replacement `sandbox_id` and generation under the reset operation before invoking the normal create contract. The old resource follows `STOPPING → DESTROYED`, while the replacement independently follows `REQUESTED → CREATING → STARTING → READY`. Only after the exact replacement is authoritatively `READY` does the backend atomically swap `active_sandbox_id` and active generation and set the attempt to `READY`. Failure or expiry cannot publish the candidate as active; expiry has priority, and the attempt retains every operation and resource reference for idempotent cleanup.

The backend persists one immutable `expires_at` deadline plus durable expiry and destroy intent in authoritative storage before allocation, and the control plane copies the deadline to each resource record. From Phase 1 onward, service startup reconciles owned runtime resources against these records and resumes expiry or destroy operations until verified destruction. Expiry intent has priority from every nonterminal attempt and resource state. Lifecycle compare-and-set updates check the deadline and intent before and after side effects, so losing create or reset work cannot clear expiry, publish a resource as active, or leave an orphan alive past its deadline.

## Observability Baseline

Each planned request and lifecycle operation carries a correlation ID plus user, Room attempt, sandbox, generation, session epoch, and idempotency identifiers where applicable. Capability and lease events use non-reversible identifier hashes rather than raw tokens. Structured events must cover authorization decisions, replay rejection, attachment-lease decisions, state transitions, provisioning duration, terminal attach and detach, reset, destroy, TTL expiry, cleanup retries, and failures.

Metrics must include active sandboxes and terminal sessions, lifecycle latency, failed transitions, rejected authorization, resource-limit events, expired leases, and orphan cleanup. Health checks distinguish API, gateway, control-plane, runtime, and persistence failures.

Reconciliation compares backend provisioning and reset intents with control-plane resource records and runtime inventory. A persisted expected tuple with a missing response is safely retried using the same idempotency key; an exact existing match is adopted by the operation, while an unexpected or unreferenced resource is quarantined from attachment and driven through idempotent destroy. The control plane never repairs a mismatch by allocating a new identity.

Logs must not contain credentials, secrets, or raw authorization headers. Raw terminal content is not logged by default; any future recording feature requires a separate privacy and retention decision.

## Deferred Architecture

Phase 0 does not select deployment topology, sandbox runtime implementation, PostgreSQL schema, event bus, cache, orchestration platform, production identity provider, multi-region strategy, or high-availability model. Profiles, multiple Room families, organization features, and advanced reporting are also deferred.

These decisions follow evidence from the browser terminal proof of concept and Room lifecycle implementation. They must not weaken the logical boundaries defined here.

## Architecture Decision Rules

- Record decisions that change a trust boundary, state owner, protocol, persistence model, runtime, or operational dependency before implementation.
- Prefer the smallest reversible design that proves the next phase's acceptance criteria.
- Keep lifecycle transitions explicit and reject operations that do not match the current state.
- Preallocate and persist every sandbox identity and generation in the backend-owned attempt intent before invoking control-plane creation; never let the control plane substitute an identity.
- Authenticate service-to-service calls and authorize every user operation independently of resource identifiers.
- Consume each terminal capability once and require a current control-plane attachment lease immediately before PTY creation.
- Make lifecycle mutations generation-checked and idempotent, and make immutable expiry intent win every operation race.
- Preserve a real PTY data path; interface simulations cannot substitute for sandbox execution.
- Treat scenario definitions as data with a constrained schema, not executable control-plane extensions.
- Require bounded resources, deterministic reset, idempotent cleanup, and observable failure handling in every sandbox design.
- Revisit deferred choices only when measured requirements justify the additional component or privilege.
