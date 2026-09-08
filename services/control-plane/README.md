# Control Plane

`failroom_control_plane` is a trusted, in-process composition package for the
Failroom state store and sandbox-engine primitives. It is not an HTTP service,
learner allocation endpoint, terminal gateway, or deployment process.

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

There are no environment defaults, config-file fallbacks, HTTP listeners,
background workers, shell execution paths, or learner-facing commands in this
package.

## Operator migration

The only CLI surface is the explicit `migrate` command. It requires absolute
database and new backup paths plus a bounded busy timeout:

```text
failroom-control-plane migrate \
  --database /var/lib/failroom/state.sqlite3 \
  --backup /var/lib/failroom/state-before-v2.sqlite3 \
  --busy-timeout-ms 5000
```
