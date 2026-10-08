# Failroom API Contract Package

Internal Phase 1 capability primitives for trusted services. This package provides
a bounded HMAC codec for the short-lived terminal capability contract and an
injected bearer-credential verifier. It does not run an HTTP listener, integrate
with a production identity provider, distribute keys, open a WebSocket, or attach
a PTY.

## Capability contract

`CapabilityCodec` requires an explicit private key of at least 32 bytes and an
explicit lifetime no longer than five minutes. It issues and verifies a canonical
three-segment capability containing:

- `jti`
- `user_id`
- `attempt_id`
- `sandbox_id`
- `generation`
- `session_epoch`
- `expires_at`
- `scope`

Only `scope=terminal:attach` is accepted. Verification is bounded, constant-time
for the HMAC comparison, and returns `CapabilityClaims` for the authenticated
backend contract. The state store must still re-check ownership, generation,
session epoch, expiry and resource state before consuming the capability.

The codec does not prove that a user is authenticated or that a Room is attachable.
The injected verifier provides only the caller-supplied local credential boundary;
key custody, production identity integration, deployment authentication, and
browser transport remain outside this package.
Never put the key, raw capability or decoded claims in a learner sandbox, URL, log,
metric label or terminal output.

## Backend authority facade

`BackendCapabilityAuthority` composes an already authenticated `UserIdentity`,
the owner-filtered state store and `CapabilityCodec`. `issue()` only emits a
capability for the current attempt when its active sandbox is `READY` or
`RUNNING`, its session epoch and immutable deadline are current, and no expiry
or destroy intent exists. `introspect_and_consume()` verifies the token and
delegates atomic `jti` consumption to the gateway-scoped backend contract.

The facade returns fixed `AuthorityError` codes and never logs or persists the
raw capability. Browser-provided identity objects, HTTP listeners, service
authentication middleware and WebSocket/PTY transport remain outside this
package.

## Checks

From this directory:

```powershell
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy failroom_api
```
