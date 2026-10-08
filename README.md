# Failroom

> **Your first production incident shouldn't be in production.**

Failroom is an experimental project for learning incident response by investigating and recovering failures in isolated environments.

> **Status: Experimental · Work in Progress · Not Production Ready**

## Why Failroom

Production에서 실패하면 장애다. Failroom에서 실패하면 경험이다.

In production, failure is an incident. In Failroom, failure is experience. Failroom is intended to give engineers a safe place to build operational judgment before a real outage demands it.

## Core Experience

The planned learning loop is:

`Break → Observe → Investigate → Diagnose → Recover → Understand → Repeat`

Each Room will begin with a real, inspectable failure. Learners will use system evidence and a real shell to form a diagnosis, recover the system, and understand why the recovery worked.

## What Failroom Is

Failroom is being designed as a browser-based incident training platform. A learner will Enter Room, investigate an isolated Linux environment, monitor Room Status, recover the incident, and receive a Room Report. Reset Room and Leave Room will provide explicit recovery and exit actions.

## What Failroom Is Not

Failroom is not a video course, quiz, static tutorial, command-simulation game, or generic operations dashboard. The planned terminal must execute real commands in an isolated environment; predefined or fake command responses are outside the product model.

## Planned Architecture

The intended terminal path is:

`Browser → xterm.js → authorized WebSocket → terminal gateway → PTY → isolated Linux sandbox`

The planned architecture uses Next.js with xterm.js for the browser interface and FastAPI for backend authorization and control. It separates those layers from the terminal gateway, trusted sandbox control plane, untrusted user sandbox, and Room scenario definitions. Internal profile qualification, the verified diagnostic Docker lifecycle, the trusted in-process control-plane composition, the bounded signed capability codec, the consumed attachment-lease contract, and SQLite state modules are implemented. The control plane enforces explicit configuration, state-before-runtime ordering, persisted runtime bindings, operator-only migration, and evidence-gated cleanup. It also runs an operator-only local runtime that serves Enter Room, Room Status, a real PTY terminal over WebSocket, Reset Room, recovery verification, and Leave Room for the Disk Full Room on a loopback address with one local bearer credential. The browser interface remains planned.

## Security Boundary

Future user sandboxes must be disposable, isolated, resource-bounded, and treated as untrusted. They must not receive host container-runtime control sockets, including Docker, Podman, or containerd/CRI sockets, or gain host shell access, broad host filesystem access, or control-plane credentials. A sandbox identifier alone must never authorize terminal or lifecycle access.

As a product design objective, failures should have real consequences inside a Room and zero consequences outside it. The enforceable security target is no unauthorized security or availability impact outside a Room, except for explicitly allowed and bounded egress and resource effects. This is a requirement for the planned runtime, not an implemented guarantee; runtime work cannot be considered complete until isolation, authorization, limits, cleanup, and failure handling are verified.

## Current Development Status

Phase 0 established documentation and repository rules. The repository now contains a tested profile qualification gate, a verified diagnostic Docker lifecycle, a transactional SQLite state store with explicit migrations through v4, a trusted control-plane composition, a bounded capability codec, an atomic attachment-lease contract, Reset Room, and the Disk Full scenario. The control plane's operator-only local runtime connects them into a loopback HTTP and WebSocket path to a real PTY.

That runtime provisions sandboxes without a qualification report, so it is a local proof of concept for the operator on their own host, not a learner-facing service. A report-only qualification collector now covers the twelve container checks; collecting the six scenario checks and an allocation gate are the next required steps. Real Docker evidence comes from opt-in tests on a trusted Linux controller and is UNVERIFIED on Windows. There is still no web application, browser terminal, production authentication, or deployment.

## Roadmap

- **Phase 0 — Technical Foundation:** Define the product, architecture, security, sandbox, and development contracts.
- **Phase 1 — Browser Terminal Sandbox PoC:** Prove the planned Next.js/xterm.js and FastAPI path to a real PTY-backed shell in an isolated Ubuntu environment through an authorized browser connection.
- **Phase 2 — Room Lifecycle:** Generalize Phase 1's secure single-sandbox create, terminal, durable TTL, and destroy slice into the complete learner-facing Room lifecycle, including reset, multiple sandboxes, full state and race handling, and restart reconciliation.
- **Phase 3 — Disk Full Room:** Deliver the first deterministic incident scenario without consuming unbounded host storage.
- **Phase 4 — Incident Console and Room Report:** Add Room Status, service signals, timing, Reset Room, Leave Room, and a basic Room Report.

## Documentation

- [Product](docs/PRODUCT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [Sandbox](docs/SANDBOX.md)
- [Development](docs/DEVELOPMENT.md)

## Local Development

The [sandbox engine](services/sandbox-engine/README.md), [state store](packages/state-store/README.md), [control plane](services/control-plane/README.md), and [API contract package](services/api/README.md) are Python 3.12 modules with reproducible test, lint, format, and type checks. Docker and control-plane integration are opt-in and require a trusted Linux host with explicit operator inputs. The control-plane README also documents the operator-only local runtime and its limitations. A web interface and learner-facing setup remain planned.

## Contributing

The project is not yet accepting runtime feature contributions against a stable application surface. Documentation contributions should preserve the product vocabulary, planned-status wording, and security boundary. Future implementation changes should be small, testable, and accompanied by their security impact and validation evidence.
