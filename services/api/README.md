# Failroom API Contract Package

Internal Phase 1 capability and identity primitives for trusted services. This
package provides a bounded HMAC codec for the short-lived terminal capability
contract, the backend capability authority facade, and a bearer identity
verifier. It does not run an HTTP listener, distribute keys, open a WebSocket,
or attach a PTY; the trusted control plane composes these primitives into its
HTTP and WebSocket routes.

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

The codec does not prove that a user is authenticated or that a Room is
attachable; the bearer verifier and the backend authority facade below perform
those checks. HTTP issuance and gateway transport live in the control-plane
package. Key custody and distribution remain planned: the local runtime takes
its key from explicit operator configuration. Never put the key, raw capability
or decoded claims in a learner sandbox, URL, log, metric label or terminal
output.

## Bearer identity verifier

`BearerIdentityVerifier` holds explicitly configured credentials as a mapping
from the SHA-256 hex digest of each bearer token to a `BearerCredential` with a
`UserIdentity` and an aware expiry time; it never stores raw tokens. `verify()`
accepts only an `Authorization` value of the form `Bearer <token>` with 32–4096
ASCII characters, compares the token digest with each configured digest in
constant time, and returns the matching identity. It raises the fixed
`AUTHENTICATION_REQUIRED` code for a missing, malformed or unknown token and
`AUTHENTICATION_EXPIRED` once the credential has expired. The local runtime
configures exactly one credential; this verifier is not a login, account or
token-issuing service.

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
