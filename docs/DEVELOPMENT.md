# Development

## Current Repository State

Failroom is in Phase 0. The repository contains product and engineering contracts plus repository hygiene only. There is no runnable application, dependency manifest, setup command, terminal, sandbox, authentication flow, database, deployment, or production service.

Next.js, xterm.js, and FastAPI are the planned architecture choices. Phase 1 is the next engineering milestone and will select and lock their concrete versions, manifests, dependency tooling, and integration layout. Application setup commands will be documented only after those artifacts exist and are verified.

## Delivery Principles

- Deliver in this order: foundation → real terminal vertical slice → lifecycle → Disk Full Room → incident console and Room Report → more Rooms → production authentication and profiles → later collaboration capabilities.
- Prove authentic behavior through one narrow end-to-end slice before expanding platform breadth.
- Treat isolation, authorization, resource limits, cleanup, and failure handling as acceptance criteria, not follow-up hardening.
- Keep changes small, reviewable, reversible, and backed by evidence from the actual runtime introduced by the change.
- Preserve explicit component boundaries and state ownership even when early services are colocated.
- Do not claim a capability until its implementation and tests exist.

## Phase 0 — Technical Foundation

Phase 0 defines Failroom's mission, vocabulary, architecture, threat model, sandbox lifecycle, delivery sequence, and repository conventions. It deliberately creates no application directories or runtime dependencies.

Completion means the public documents agree on planned status, component responsibilities, hard security rules, lifecycle states, terminal authenticity, reset semantics, and the next milestone.

## Phase 1 — Browser Terminal Sandbox PoC

Phase 1 uses the planned Next.js, xterm.js, and FastAPI choices and selects the smallest integration layout that proves this path:

```text
Next.js/xterm.js → authorized WebSocket → terminal gateway → PTY → /bin/bash → isolated Ubuntu sandbox
```

The proof must execute real commands and demonstrate ANSI output, Ctrl+C, resize, long-running processes, and destruction. Disconnect must close and reap the terminal session and PTY without automatically destroying an otherwise valid environment; reconnect, Leave Room, and absolute TTL determine the Room and sandbox lifetime.

Before control-plane creation, the backend must persist one authoritative attempt record with a preallocated `sandbox_id`, generation, provisioning intent, idempotency key, and immutable deadline. The control plane creates and returns only that exact tuple or idempotently returns the existing match; it never allocates an identity. A lost response is recovered with the same tuple, and an unreferenced resource is denied attachment and destroyed.

Before PTY attachment, the gateway must validate a short-lived signed, single-use capability containing unique `jti`, user, attempt, sandbox, generation, session epoch, expiry, and scope claims. Authenticated backend introspection confirms current authoritative state and atomically consumes `jti`, so concurrent replay opens at most one WebSocket and reconnect requires a new capability.

The gateway must then obtain a short-lived control-plane attachment lease bound to the consumed `jti` and session context. Immediately before PTY creation, the control plane admits only the matching attempt and generation in resource state `READY` or `RUNNING`, with unexpired immutable TTL and no expiry, destroy, or reset intent. Colocation may use in-process authenticated interfaces, but it must preserve both authorization stages and atomic consumption.

The sandbox must have exercised bounds for CPU, memory, PID, storage, I/O, terminal output, network, concurrent terminal connections and sessions, and absolute lifetime. Phase 1 persists `expires_at`, expiry intent, destroy intent, and owned resource identity in authoritative storage. On process or service startup it reconciles owned runtime resources against those records before terminal attachment, resumes or retries expiry and destroy work until verified destruction, and prevents an orphan from surviving its deadline. It must not use fake command responses or expose any Docker, Podman, containerd, CRI, or other host runtime control socket, host shell, host filesystem, host or control-plane credential, or another sandbox.

Phase 1 does not require a Room catalog, durable PostgreSQL data, profiles, production identity, or a generalized scenario framework.

## Phase 2 — Room Lifecycle

Phase 2 generalizes the secure Phase 1 create, terminal attachment, durable absolute-TTL cleanup, startup reconciliation, and destroy slice into the complete learner-facing lifecycle. It adds reusable state-machine handling, ownership-filtered inspect, Reset Room, multiple concurrent sandboxes, complete invalid-transition and operation-race matrices, and broader reconciliation across every owned and candidate resource. The backend owns the authoritative Room attempt record, while the sandbox control plane separately owns authoritative resource lifecycle state.

Reset is a backend-owned compound operation, not a control-plane reset mutation. The backend increments the attempt session epoch, generation-checks and destroys the old sandbox, preallocates and persists the replacement sandbox ID and generation, invokes the normal create contract, and atomically swaps the active pointer only after that exact replacement is ready. Expiry has priority, and expired or stale capabilities cannot access the replacement.

Phase 2 extends the Phase 1 durable TTL and startup-reconciliation baseline across every nonterminal attempt and resource state, including provisioning and reset, and across multiple concurrent sandboxes. Its generalized workers make expiry win the complete lifecycle race matrix and retry until all active, old, and candidate resources are verified destroyed. Reconciliation joins backend intents to exact preallocated tuples, removes unreferenced resources, and never adopts a control-plane-selected identity. A failed resource generation may retry only idempotent cleanup; create or reset retry starts a new operation and backend-preallocated generation.

## Phase 3 — Disk Full Room

Phase 3 introduces one deterministic Disk Full Room using the minimum scenario declaration needed for that experience. Storage exhaustion, investigation, recovery, reset, and success detection must be genuine inside the sandbox while host storage remains bounded.

The phase validates that a learner can use real evidence such as `df` and `du`, restore the target service, and repeat the same initial failure after reset.

## Phase 4 — Incident Console and Room Report

Phase 4 adds learner-visible Room Status, relevant service signals, elapsed time, Reset Room and Leave Room actions, automated completion, and a basic Room Report. The report summarizes evidence, root cause, recovery actions, and outcome without replacing hands-on investigation.

Operational state displayed by the web interface remains derived from backend and control-plane observations, not client assertions.

## Later Phases

Additional Room families follow only after the first four phases are validated. Production authentication, account recovery, profiles, progress history, organization features, advanced reporting, instructor or multiplayer experiences, and optional incident-team collaboration remain later work.

Infrastructure expansion such as PostgreSQL, orchestration, stronger sandbox runtimes, high availability, and deployment automation must be introduced in response to measured requirements with explicit architecture and security review.

## Branch and Pull Request Workflow

- Create one focused branch per change using a descriptive prefix such as `feat/`, `fix/`, `docs/`, or `chore/`.
- Keep commits coherent and avoid mixing unrelated refactors, generated files, or dependency updates.
- Rebase or merge the current target branch according to repository policy before final validation.
- Require review before merging changes that affect a trust boundary, lifecycle transition, terminal protocol, scenario schema, persistence, or infrastructure privilege.

Every pull request description includes:

- **Summary:** what changed.
- **Why:** the user or engineering problem addressed.
- **Implementation:** important design choices and affected components.
- **Security impact:** changed trust boundaries, privileges, authorization, data, and abuse cases, or an explicit statement that none changed.
- **Testing:** exact automated and manual checks with results.
- **Screenshots:** required for visible UI work, including relevant viewport and state coverage.
- **Known limitations:** deferred work, residual risk, and compatibility constraints.

Sandbox-related changes must explicitly cover backend-preallocated identity, authoritative attempt and resource state, internal inspect access, one-time capability consumption, final attachment leasing, isolation, CPU/memory/PID/storage/I/O/output/network/concurrent-session/absolute-lifetime limits, disconnect and PTY cleanup, reset orchestration, expiry races, reconciliation, idempotent cleanup, and failure handling. A sandbox ID must never be presented as authorization.

## Local Validation

Phase 0 has no application setup or test command. Documentation-only changes should at minimum:

1. Confirm every referenced local Markdown link resolves.
2. Check headings, terminology, planned-status wording, and final newlines.
3. Run `git diff --check` to detect whitespace errors.
4. Inspect the diff for secrets, unsupported claims, accidental generated files, and weakened security requirements.
5. Confirm the branch contains only files intended for the change.

Each later phase adds reproducible setup, formatting, static analysis, unit, integration, security, and end-to-end commands alongside the first code that requires them. Validation must exercise the actual selected runtime where isolation or terminal behavior is claimed.

## Documentation Updates

- Update `README.md` when status, entry points, roadmap, or setup availability changes.
- Update `PRODUCT.md` when product vocabulary, user flow, MVP scope, or success criteria change.
- Update `ARCHITECTURE.md` when component boundaries, trust boundaries, state ownership, data flow, or persistence change.
- Update `SECURITY.md` when threats, privileges, network access, credentials, logging, cleanup, or residual risk change.
- Update `SANDBOX.md` when lifecycle states, APIs, terminal behavior, reset, limits, TTL, or failure handling change.
- Update this document when phase order, validation commands, review fields, or completion criteria change.

Documentation and implementation must land together when behavior changes. Planned language is replaced with implemented language only after verification evidence exists.

## Definition of Done

A change is done when:

- acceptance criteria are explicit and satisfied;
- implementation respects the owning architecture, security, and sandbox contracts;
- automated tests and required manual checks pass on the supported environment;
- create persists the backend-preallocated sandbox ID, generation, provisioning intent, immutable deadline, and idempotency key before mutation, and the control plane returns only that exact tuple;
- Phase 1 persists `expires_at`, expiry and destroy intent, and owned resource identity; startup reconciliation resumes cleanup until verified destruction and prevents deadline-surviving orphans;
- internal inspect accepts only authenticated trusted service identities, while learner-visible status is ownership-checked and filtered by the backend;
- terminal capabilities contain a unique `jti`, are atomically consumed once against the backend's authoritative ownership, state, sandbox generation, and session epoch, and reject concurrent replay when authorization is affected;
- the control plane atomically grants and consumes a short-lived attachment lease immediately before PTY creation only for the matching attempt and generation in `READY` or `RUNNING`, with valid immutable TTL and no expiry, destroy, or reset intent;
- tests prove no host runtime control socket, host filesystem, host or control-plane credential, or cross-sandbox access is exposed when sandbox execution is affected;
- CPU, memory, PID, storage, I/O, output, network, concurrent terminal connection and session, and absolute-lifetime limits are exercised when affected;
- disconnect cleans the terminal session and PTY without unintended environment teardown, and reconnect follows explicit policy when terminal behavior is affected;
- reset remains a backend-owned compound operation that destroys the old generation, persists a preallocated replacement tuple, uses normal create, swaps the active pointer only after replacement readiness, and rejects stale capabilities;
- absolute-TTL race tests prove persisted expiry intent wins from every nonterminal state and cleanup reaches verified destruction when lifecycle behavior is affected;
- failed resource generations perform only idempotent cleanup, while create and reset retries use new operations and generations;
- reconciliation retries lost creates by exact tuple and destroys unreferenced resources without accepting a control-plane-selected identity;
- observability covers new lifecycle operations and failures without leaking secrets;
- documentation, examples, and setup instructions match verified behavior;
- the pull request includes all required fields and UI evidence where applicable;
- no unrelated files, credentials, debug artifacts, or unsupported claims are included; and
- rollback or recovery behavior is understood for changes with persistent or operational impact.
