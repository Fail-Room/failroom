# Failroom API Contract Package

Internal Phase 1 capability primitives for trusted services. This package provides
a bounded HMAC codec for the short-lived terminal capability contract; it does not
run an HTTP listener, authenticate users, distribute keys, consume `jti` values,
open a WebSocket, or attach a PTY.

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
Those checks, key custody, HTTP issuance and gateway transport remain planned.
Never put the key, raw capability or decoded claims in a learner sandbox, URL, log,
metric label or terminal output.

## Checks

From this directory:

```powershell
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy failroom_api
```
