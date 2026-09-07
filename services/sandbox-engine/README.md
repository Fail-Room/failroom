# Sandbox Engine

This component currently implements a profile qualification evidence evaluator
and a raising guard. It has no Docker adapter, probe runner, HTTP service,
database, terminal gateway, or sandbox creation endpoint.

The package uses Python 3.12.13 and the standard library. Ruff and mypy are pinned
development tools; `uv.lock` locks their transitive dependencies. Commands below
run from this directory with uv installed:

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy failroom_sandbox
```

## Qualification contract

`evaluate_qualification(context, report, *, now, max_age)` returns an immutable
decision. `require_qualified_profile` has the same arguments, returns `None` on
success, and raises `ProfileNotQualified` on denial. Consumers must use the guard
or inspect `decision.allowed`; the decision object itself is not a boolean or an
authorization credential.

Every `Check` member is required exactly once. The required set is owned by code,
not supplied by the caller:

- unprivileged identity, syscall restrictions, filesystem/process/network
  isolation, and absence of host socket/filesystem/device/credential access;
- CPU, memory including swap, PID, storage, I/O, and file descriptor limits;
- terminal output/buffers, connection and session limits;
- immutable absolute TTL, disconnect cleanup, and restart cleanup.

Every result must contain an `Outcome` enum, a timezone-aware `observed_at`, and a
SHA-256 reference to its evidence artifact. Only `Outcome.PASS` qualifies. Missing,
FAIL, UNVERIFIED, duplicated, or malformed results deny qualification. Raw strings
such as `"PASS"` are not silently promoted into verified outcomes.

The caller supplies a positive `timedelta` maximum age and an aware current time.
Each check must have `0 <= now - observed_at < max_age`. The exact maximum-age
boundary is expired; future observations are rejected. Evaluation does not update
timestamps or refresh evidence. The trusted collector must retain the actual test
observation time, not substitute report issuance time.

Both times are normalized to UTC before subtraction, including repeated hours at
daylight-saving transitions. Invalid timezone offsets, conversion failures, and
out-of-range UTC instants deny evaluation without exposing provider error text.

Current and report contexts must match all of these fields:

| Context field | Required source |
| --- | --- |
| `runtime.engine_id` | Actual Docker engine identity |
| `runtime.host_boot_id` | Current Docker host/VM boot identity |
| `runtime.daemon_epoch` | Trusted identity changed on daemon restart/reconnection |
| `runtime.configuration_digest` | Full relevant runtime configuration, including engine version, storage/cgroup configuration, security policy and backing device identities |
| `image_digest` | Exact immutable image used by the proposed sandbox |
| `profile_digest` | Complete explicit profile, including Docker settings, gateway/session limits and TTL/cleanup policy |

`configuration_digest` hashes a JSON object with sorted object keys, compact
separators, ASCII escaping and SHA-256. Object key order does not matter; value
types, nested values and list order do. Non-string object keys, cycles, non-finite
numbers and non-JSON types are rejected. It does not validate the security of
configuration values, fill defaults, or access Docker. Loaders must reject
duplicate JSON keys, resolve every setting, and serialize mutations while
fingerprinting. Required settings must not be omitted from the document.

## Trust and integration boundary

Only the trusted control plane may assemble contexts and reports. Do not build
them from a browser request or treat sandbox-generated success text as evidence.
The collector, artifact storage and actual resource probes are not implemented.
Artifact hashes are references, not signatures: this evaluator does not establish
artifact authenticity, inspect their contents, or prove that tests ran.

A complete report must come from the actual runtime and final image. Synthetic
reports in unit tests exercise decision logic only. A partial operator diagnostic
does not qualify a learner sandbox. In particular, configuration inspection alone
does not prove runtime enforcement or cleanup during a service outage.

The future allocation adapter must call the guard with fresh context before side
effects. It must also validate service authentication, ownership, expected
sandbox/generation, idempotency and lifecycle/expiry intent, and serialize these
checks with creation. This guard cannot prevent time-of-check/time-of-use races
on its own. A previous success must never be cached as continuing permission.

## Error contract

`ProfileNotQualified.code` is `SANDBOX_PROFILE_UNVERIFIED`. The exception message
and its decision contain only fixed denial codes and optional `Check` identifiers.
They do not copy raw evidence, configuration, runtime IDs, paths, or credentials.

| Denial | Meaning |
| --- | --- |
| `EVALUATION_INVALID` | Invalid clock or maximum-age policy |
| `CONTEXT_INVALID` | Invalid current runtime/image/profile identity |
| `REPORT_MISSING` / `REPORT_INVALID` | Absent report, invalid shape, invalid references or duplicate checks |
| `CONTEXT_MISMATCH` | Evidence belongs to another runtime, image or profile |
| `CHECK_MISSING` / `CHECK_FAILED` / `CHECK_UNVERIFIED` | Mandatory check is not verified as passing |
| `EVIDENCE_EXPIRED` / `EVIDENCE_FUTURE` | Evidence is outside the allowed observation interval |

Failures in the future runtime collector must produce FAIL or UNVERIFIED, not an
empty passing report. Cleanup remains permitted and required even when a profile
cannot qualify for new creation.
