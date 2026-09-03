# Security

## Status

Failroom Phase 0 has no application runtime, terminal gateway, sandbox implementation, authentication system, or production deployment. Every control in this document is a mandatory requirement for future implementation, not an implemented guarantee. Runtime claims require test evidence from the phase that introduces them.

## Security Objective

Failroom's product design objective is that failures have real consequences inside a Room and zero consequences outside it. Because no system can establish that as an absolute guarantee, the enforceable security target is narrower: learner activity must cause no unauthorized security or availability impact outside the Room's explicitly allowed, resource-bounded egress and infrastructure effects. A learner may fully investigate and modify the assigned environment without gaining access to the host, control plane, another sandbox, another user's data, or resources beyond the Room's limits.

## Trust Model

- Browsers, client state, terminal input, uploaded or pasted data, and all learner-controlled commands are untrusted.
- User sandboxes are hostile and disposable, even when created from a trusted image.
- The backend API is trusted to authenticate users and own the authoritative Room attempt record, including ownership, attempt status, active and pending sandbox identities and generations, provisioning/reset intent, session epoch, and expiry. It preallocates and persists the expected resource tuple before any create mutation.
- The terminal gateway is trusted to validate signed terminal capabilities and confirm their claims against the backend's current authoritative record before attaching to the exact authorized sandbox generation.
- The sandbox control plane is highly trusted because it holds constrained runtime privileges and owns authoritative sandbox resource lifecycle state. It creates only backend-preallocated resource identities and never allocates or substitutes a sandbox ID or generation. It is never reachable from a user sandbox.
- Scenario declarations are trusted only after schema validation and review; scenario processes run in the untrusted sandbox.
- Host runtime, kernel, deployment credentials, and future persistence are protected infrastructure, not part of the learning environment.

Trust is not transitive. Knowing a Room ID, sandbox ID, network address, or terminal URL does not prove identity or ownership.

## Protected Assets

- Host kernel, processes, filesystem, network, container runtime, and every runtime control socket, including Docker, Podman, and containerd endpoints.
- Sandbox control-plane credentials and lifecycle authority.
- Backend, gateway, deployment, and future database credentials.
- Other users' identities, Room attempts, reports, and terminal sessions.
- Other sandboxes' processes, filesystems, network namespaces, and resource allocations.
- Scenario definitions, validation rules, and completion results.
- Service availability, resource capacity, logs, metrics, and audit records.
- Terminal credentials and authenticated browser sessions.

## Threat Actors and Capabilities

- An unauthenticated remote attacker can probe HTTP and WebSocket endpoints, replay identifiers, and exhaust connection handling.
- An authenticated malicious learner can execute arbitrary shell commands, create hostile processes and files, flood terminal output, and attempt lateral movement.
- A compromised process inside a sandbox can attempt privilege escalation, container escape, kernel exploitation, or access to runtime APIs.
- A learner can launch fork bombs or exhaust CPU, memory, PID, storage, I/O, terminal buffers, network, or lifetime limits.
- A sandbox can attempt host filesystem or Docker daemon access, network scanning, external abuse, metadata-service access, and data exfiltration.
- An attacker who obtains a terminal capability or sandbox ID can attempt cross-user discovery, capability reuse, stale-session attachment, reset, or destruction.
- Misconfiguration or vulnerable dependencies can leak secrets through source, environment variables, logs, error responses, images, or sandbox mounts.
- Process crashes and partial lifecycle operations can leave orphaned resources, active credentials, or inconsistent ownership state.

## Mandatory Controls

### Runtime and Privilege

- Never execute a learner shell directly on the host.
- Run every user sandbox without privileged mode, with a non-root user, dropped Linux capabilities, no-new-privileges, and an enforced syscall and mandatory-access-control profile where the chosen runtime supports them.
- Do not place `/var/run/docker.sock` or any Docker, Podman, containerd, CRI, or other host runtime control socket, host credential, or control-plane credential in a user sandbox.
- Keep runtime control access in the trusted control plane behind authenticated, narrow operations.
- Pin and scan base images, minimize installed packages, and rebuild rather than patch long-lived sandbox instances.
- Document and review any required capability or device access before it is introduced; default access is none.

### Filesystem

- Give each sandbox a separate writable filesystem and bounded scratch storage.
- Do not mount the host filesystem or broad host paths. Any future narrow read-only asset mount requires explicit review and path traversal tests.
- Prevent device-node creation and access to sensitive pseudo-filesystems beyond the minimum required for the scenario.
- Apply storage quotas so a Disk Full Room exhausts only its assigned filesystem, never host capacity.
- Destroy writable layers and temporary volumes during reset, completion, leave, failure, and expiry.

### Network

- Use a separate network namespace and identity for every sandbox.
- Target deny-by-default ingress and egress. Any allowed outbound destination, protocol, and port must be explicit and scenario-scoped.
- Block access to host services, control-plane endpoints, runtime APIs, cloud metadata services, private infrastructure, and other sandboxes.
- Apply connection, bandwidth, and DNS controls that limit scanning, denial of service, external abuse, and exfiltration.
- Document any narrower local proof-of-concept network policy gap with an owner, compensating control, and removal condition.

### Resources and Lifetime

- Enforce finite CPU, memory, PID, storage, I/O, terminal-output, network, concurrent terminal connection and session, and absolute-lifetime limits per sandbox.
- Persist an immutable absolute-TTL deadline before allocation. Check it before and after every lifecycle side effect, including create, start, and reset work, and use bounded cleanup retries.
- Make limits effective below the host's exhaustion threshold and test both individual and concurrent sandboxes.
- Terminate process trees and reclaim namespaces, filesystems, and network allocations after the lease ends.

### Authorization

- Authenticate every browser and service caller using a server-validated mechanism.
- Verify Room ownership and allowed lifecycle transition for every create, inspect, reset, destroy, and terminal request.
- Preallocate and persist the exact expected `sandbox_id`, generation, provisioning intent, immutable deadline, and idempotency key in the backend-owned attempt record before calling create. Require the control plane to create and return that exact tuple or idempotently return an existing exact match; reject conflicts instead of allocating a different identity.
- Restrict the control-plane inspect API to authenticated trusted backend and control-plane service identities. A browser uses a backend facade that revalidates authenticated user and Room ownership and returns only filtered learner-visible status.
- Never treat a sandbox ID as authorization, even if the identifier is random or unguessable.
- Issue a signed, short-lived, single-use terminal capability containing unique `jti`, `user_id`, `attempt_id`, `sandbox_id`, `generation`, `session_epoch`, `expiry`, and `scope`.
- After locally validating signature, expiry, and scope, require the gateway to check the capability claims against the backend's authoritative current ownership, attempt status, active sandbox, generation, and session epoch through an authenticated internal API. That operation atomically consumes `jti`; reuse is rejected even within the same generation and session epoch.
- Store only a non-reversible `jti` hash, consumption status, and expiry needed for replay prevention. Never log or persist the raw signed capability.
- Before PTY creation or attachment, require the gateway to obtain a short-lived control-plane terminal attachment lease bound to the consumed `jti`, gateway session context, attempt, sandbox, and generation.
- Require the control plane to verify the `sandbox_id`, `attempt_id`, and generation binding; resource state `READY` or `RUNNING`; immutable TTL; and absence of durable expiry, destroy, or reset intent immediately before attachment. Lease issue, consumption, and handoff to PTY creation form one authorize-and-attach operation; `STOPPING`, `FAILED`, expired, stale-generation, or reused requests are rejected.
- Require every control-plane mutation to carry authenticated service identity, action scope, expected sandbox ID and generation, and an idempotency key; compare these with the authoritative resource record before side effects.
- Revoke or reject capabilities after expiry, reset, ownership change, failure, resolution policy, or destruction.
- Return non-enumerable errors and record denied cross-user attempts without exposing resource details.

### Terminal Sessions

- Validate the WebSocket's authentication, origin policy, ownership, scope, expiry, generation, and sandbox state before PTY attachment.
- Bound concurrent sessions, input messages, resize dimensions, signal types, output rate, and buffered bytes.
- Forward bytes to a real PTY inside the sandbox. Fake terminal responses and predefined command-output mappings are prohibited.
- Keep the PTY and process tree associated with one sandbox generation; reset or destroy closes every attached session.
- On network disconnect, close the terminal session, close and reap its PTY and shell process group, and release gateway buffers and connection accounting. Preserve the Room and sandbox only under the explicit reconnect, Leave Room, and absolute-TTL policy; a transient disconnect does not by itself require environment destruction.
- Reject stolen, replayed, expired, or stale terminal capabilities and prevent attachment to replacement sandboxes.
- Require a new one-time capability for every reconnect and bind the downstream attachment lease to the consumed `jti` and gateway session context.
- Define disconnect behavior explicitly and ensure abandoned processes cannot outlive the sandbox lease.

### Secrets and Logging

- Do not place host, deployment, backend, runtime, or database secrets in sandbox images, mounts, environment variables, shell history, or scenario files.
- Keep secrets, raw terminal capabilities, and raw attachment leases out of client bundles, URLs, error details, structured logs, metrics labels, and terminal output generated by trusted services.
- Log structured identifiers, authorization outcomes, lifecycle transitions, resource-limit events, and cleanup results without raw credentials.
- Do not record raw terminal content by default. Any future recording requires explicit consent, access control, retention, deletion, and redaction rules.
- Redact authorization headers and tokens at ingestion, and restrict access to security logs.

### Cleanup

- Revoke terminal access before reset or destroy begins.
- Keep reset orchestration in the backend: invalidate the session epoch, generation-check and destroy the old resource, persist a preallocated replacement tuple, call normal create, and swap the active pointer only after that exact replacement is `READY`. Expiry intent overrides every reset step.
- Make destroy idempotent so retries converge even after partial failure or missing resources.
- Trigger cleanup on explicit leave, reset, completion policy, creation failure, terminal/session failure where applicable, service restart reconciliation, and TTL expiry.
- Persist expiry intent and give it priority over create, start, reset, and attach completion. Compare-and-set completion updates must include the unchanged deadline and absence of expiry intent, so losing work cannot publish `READY` or clear expiry.
- From the first real Phase 1 sandbox, persist `expires_at`, expiry intent, destroy intent, and owned resource identity in authoritative storage that survives process or service restart. On startup, reconcile owned runtime resources against those records before terminal attachment and resume cleanup until verified destruction.
- Retry expiry cleanup until verified destruction. A resource in `FAILED` may retry only idempotent cleanup in the same generation; create or reset retry starts a new operation and resource generation.
- Reconcile desired records with runtime inventory to detect and remove orphaned sandboxes, volumes, networks, and sessions.
- Reconcile backend provisioning/reset intents with the exact control-plane resource tuples. Retry a lost create response with the same tuple and idempotency key, and quarantine then destroy unreferenced or mismatched resources; never adopt a control-plane-selected replacement identity.
- Record cleanup attempts and alert when bounded retries cannot reclaim a resource.

## Prohibited Designs

- A learner shell or learner-controlled command running directly on the host.
- Privileged user sandboxes or access to `/var/run/docker.sock` or any Docker, Podman, containerd, CRI, or equivalent host runtime control socket.
- Host filesystem mounts, shared writable filesystems between users, or control-plane credentials inside a sandbox.
- Lifecycle or terminal authorization based only on a Room ID, sandbox ID, URL secrecy, or client-supplied ownership.
- Control-plane allocation or substitution of a sandbox ID or generation, a compound control-plane reset that performs destroy and replacement creation, or direct user access to control-plane inspection.
- Long-lived or cross-sandbox terminal bearer credentials.
- Reusable terminal capabilities, attachment without atomic `jti` consumption, or PTY creation without a current control-plane attachment lease.
- Unbounded CPU, memory, PID, storage, I/O, output, network, session count, or lifetime.
- Unrestricted access to other sandboxes, host services, internal infrastructure, metadata services, or the public network.
- Fake command execution, fake terminal responses, or predefined mappings that replace the real PTY path.
- In-place reset that can retain learner processes, files, credentials, or hidden state from the previous attempt.
- A create, start, reset, or attach completion that can overwrite durable expiry intent or publish an expired resource as ready.
- Silent cleanup failure or lifecycle code that assumes runtime deletion succeeded without verification.

## Required Security Tests

Before a sandbox capability is accepted, automated or reproducible tests must demonstrate:

- unprivileged identity, capability restrictions, syscall controls, and failed access to host processes, devices, filesystem, credentials, Docker, Podman, containerd and other runtime control sockets, and control-plane endpoints;
- failed cross-sandbox discovery, connectivity, file access, inspection, terminal attachment, reset, and destroy attempts;
- ownership enforcement for every HTTP and WebSocket operation, including guessed IDs and mismatched users;
- initial create with a backend-preallocated and persisted tuple, including lost-response idempotency, conflicting-tuple rejection, no control-plane identity substitution, and orphan reconciliation;
- control-plane inspection denial for user credentials and filtered backend status responses after authenticated ownership checks;
- rejection of modified, expired, wrong-scope, wrong-generation, and post-reset terminal capabilities, plus concurrent replay of one `jti` where exactly one WebSocket-open attempt may consume it;
- final attachment-lease rejection for mismatched attempt or generation, resource `STOPPING` or `FAILED`, expired TTL, durable expiry/destroy/reset intent, reused lease, and state changes racing PTY creation;
- containment of fork bombs, CPU and memory pressure, PID exhaustion, storage and I/O exhaustion, network abuse, terminal output floods, concurrent terminal connection and session exhaustion, and absolute-lifetime expiry;
- network policy enforcement against other sandboxes, host services, private ranges, metadata services, and unapproved egress;
- real PTY behavior for commands, ANSI output, resize, signals, and long-running processes without trusted-service command simulation;
- deterministic backend-orchestrated reset with old-generation destruction, persisted preallocated replacement identity, normal-create reuse, atomic active-pointer swap only after readiness, expiry priority, and rejection of stale sessions;
- terminal-session and PTY cleanup on disconnect without unintended Room teardown, plus idempotent destroy, failed-creation cleanup, service-restart reconciliation, and TTL cleanup;
- process and service restart after deadline or during destroy, proving authoritative expiry intent is resumed and no owned or unreferenced runtime resource survives its deadline;
- expiry races injected before and after create, start, reset, and attachment side effects, proving persisted expiry intent wins and every associated resource reaches verified destruction;
- create and reset retries that allocate a new operation and resource generation while a failed generation permits only idempotent cleanup;
- bounded Disk Full behavior that cannot consume unbounded host storage; and
- logs and error responses that contain useful identifiers but no secrets, raw credentials, or unintended terminal content.

Tests must run against the actual selected runtime and document platform-specific exceptions. A passing interface mock is not isolation evidence.

## Known Phase 0 Limitations

There is no runtime to inspect or test in Phase 0, so none of these controls is implemented or verified. The runtime, identity provider, credential format, network enforcement mechanism, syscall profile, storage driver, secret store, cleanup reconciler, and production topology remain unselected.

Phase 1 is a local proof of concept, not evidence of production-grade multi-tenant isolation. It must still prove one authoritative attempt record, backend-preallocated resource identity, one-time capability, authenticated backend introspection, final control-plane attachment lease, bounded resources, explicit destroy, and durable absolute-TTL cleanup. The Phase 1 baseline persists `expires_at`, expiry intent, and destroy intent in authoritative storage, reconciles owned runtime resources on process or service startup, and resumes expiry or destroy until verified destruction so no orphan survives its deadline. Phase 2 generalizes these controls into reset, multiple concurrent sandboxes, the complete reusable state machine and transition/race matrices, and broader reconciliation; it is not the first implementation of durable cleanup. Any temporary local limitation must be explicit, bounded, and unable to violate the non-negotiable host socket, host shell, host filesystem, authorization, isolation, resource-limit, TTL, or cleanup rules.

## Future Isolation Options

The initial runtime decision will be made during Phase 1 planning. Options for later evaluation include Rootless Docker, Rootless Podman, gVisor, Kata Containers, and Firecracker microVMs. These are deferred choices, not present safeguards.

Evaluation must compare host support, kernel boundary strength, PTY behavior, filesystem and network policy, resource accounting, startup latency, cleanup reliability, observability, maintenance cost, and known escape surface. Stronger isolation does not replace application-level ownership checks or credential scoping.

## Security Review Checklist

- [ ] Trust boundaries and protected assets changed by the proposal are identified.
- [ ] User-controlled input and the maximum attacker capability are documented.
- [ ] No host shell, Docker, Podman, containerd or other runtime control socket, host filesystem, host credential, privileged mode, or control-plane credential reaches a sandbox.
- [ ] Identity and ownership are verified independently of every resource identifier against the authoritative Room attempt record.
- [ ] Initial and replacement resource IDs and generations are preallocated and persisted by the backend; the control plane creates only the exact requested tuple and reconciliation destroys unreferenced resources.
- [ ] Control-plane inspection accepts only authenticated trusted service identities, while the backend facade revalidates ownership and filters user-visible status.
- [ ] Terminal capabilities contain unique `jti` and all required claims and are signed, short-lived, single-use, single-sandbox, generation- and session-epoch-bound, scoped, and revocable.
- [ ] Backend introspection atomically consumes the hashed `jti`, rejects replay, and never logs the raw capability.
- [ ] The control plane atomically issues and consumes a current-state attachment lease immediately before PTY creation, rejecting stale generation, terminal states, TTL expiry, and durable lifecycle intent.
- [ ] CPU, memory, PID, storage, I/O, output, network, concurrent terminal connections and sessions, and absolute lifetime are bounded.
- [ ] Cross-sandbox and infrastructure network access is denied and tested.
- [ ] Reset destroys the prior resource and stale sessions cannot reach the replacement.
- [ ] Disconnect cleans the terminal session and PTY without implicitly destroying an otherwise valid Room.
- [ ] Cleanup is idempotent, reconciled, observable, and covered for failure and race-safe absolute-TTL paths.
- [ ] Phase 1 durable cleanup storage and startup reconciliation prevent an orphan from surviving its immutable deadline.
- [ ] Logs and errors exclude secrets, credentials, and unintended terminal content.
- [ ] Required security tests use the real runtime and include adversarial cases.
- [ ] Known limitations, rollback behavior, and residual risk are explicit.
