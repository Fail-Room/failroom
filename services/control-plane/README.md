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

There are no environment defaults, config-file fallbacks, HTTP listeners,
background workers, shell execution paths, or learner-facing commands in this
package. Lifecycle orchestration, state transitions, Docker cleanup, and the
operator-only migration command are added in later approved tasks.
