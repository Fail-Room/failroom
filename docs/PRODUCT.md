# Product

## Mission

Failroom's mission is to help engineers develop incident-response judgment through a planned experience where they will troubleshoot real failures in safe, isolated environments before those skills are needed in production.

Its primary message is: **Your first production incident shouldn't be in production.**

Supporting messages are **A safe place to fail** and **Fail here, not in production**.

## Product Principle

As a product design objective, the planned product should make failures technically real inside a Room, observable through authentic system behavior, and capable of real consequences inside the Room with zero consequences outside it. The enforceable security target is no unauthorized security or availability impact outside a Room, except for explicitly allowed and bounded egress and resource effects. This is a planned requirement, not an implemented guarantee. The intended learning experience will come from investigation and recovery, not from selecting a predetermined answer.

The product should prove one secure, credible incident experience before expanding the catalog or platform surface.

## Target Users

- Software engineers who need practical Linux and production debugging experience.
- Junior operations, platform, and site reliability engineers preparing for incident response.
- Experienced engineers who want repeatable practice with unfamiliar failure modes.
- Engineering teams seeking a shared, hands-on incident training format.

## Core Learning Model

Every planned Room follows the same loop:

`Break → Observe → Investigate → Diagnose → Recover → Understand → Repeat`

- **Break:** Begin from a controlled, deterministic failure state.
- **Observe:** Read symptoms, service signals, and system behavior without being given the answer.
- **Investigate:** Gather evidence through a real terminal and relevant operational views.
- **Diagnose:** Identify the failure mechanism and choose a recovery action.
- **Recover:** Restore the affected system inside the Room.
- **Understand:** Review the cause, evidence, actions, and outcome.
- **Repeat:** Reset the experience and practice until the reasoning is durable.

## Product Vocabulary

- **Room:** A contained incident-training experience comprising a scenario, an isolated runtime, observable state, recovery criteria, and a result.
- **Enter Room:** Start or resume an authorized Room attempt and connect to its learning environment.
- **Reset Room:** Discard the current attempt environment and recreate the Room's initial incident state.
- **Leave Room:** End the active learning session and trigger the applicable session and environment cleanup behavior.
- **Room Status:** The learner-visible state of the Room and its relevant operational signals, such as readiness, service health, progress, and elapsed time.
- **Room Report:** The post-attempt summary of the incident, observed evidence, recovery result, and learning feedback.

These terms are the product-facing language. Infrastructure-specific terms such as container, sandbox resource, and terminal session describe implementation details rather than learner actions.

## Main User Flow

The complete planned browser-first journey is:

1. Arrive at the Failroom landing page and understand the learning promise.
2. Browse the Room list and select an incident scenario.
3. Review the objective, expected difficulty, and environment constraints.
4. Choose Enter Room and wait for an isolated attempt environment to become ready.
5. Observe Room Status and investigate through the real browser terminal.
6. Diagnose the failure, recover the system, and allow the Room to validate the outcome.
7. Review the Room Report and evaluation feedback.
8. Return to the Room list or, after profiles are introduced, review progress in a profile.

The MVP journey ends with the basic Room Report. Profiles belong to a later phase.

## MVP Question

Can users learn incident response by troubleshooting and recovering a real isolated system directly from a browser?

The MVP exists to answer this question with observed user behavior and verified system behavior, not with catalog size or feature breadth.

## Mandatory MVP Capabilities

The MVP must provide:

- A landing experience, Room list, Room description, and Enter Room action.
- One deterministic Disk Full Room with a genuine failure contained by strict storage limits.
- A disposable, isolated Ubuntu/bash environment with bounded CPU, memory, processes, storage, network access, and lifetime.
- A real PTY-backed browser terminal supporting command execution, ANSI output, terminal resize, signals, and long-running processes.
- Ownership-aware Room and terminal access that does not treat a sandbox identifier as authorization.
- Learner-visible Room Status, relevant service signals, and elapsed time.
- Deterministic Reset Room behavior and explicit Leave Room cleanup.
- Automated success detection followed by a basic Room Report.
- Terminal session and PTY cleanup on disconnect; a transient disconnect must not itself destroy the Room or sandbox, which persists according to reconnect, Leave Room, failure, or TTL policy.

All capabilities in this section are requirements for the planned MVP. None is implemented in Phase 0.

## Non-goals

The MVP is not intended to be:

- a video course platform or static tutorial.
- a multiple-choice quiz platform or certification exam.
- a fake terminal or command-simulation game with predefined command-output mappings.
- a ChatGPT wrapper that substitutes generated answers for hands-on system investigation.
- a generic CRUD SaaS product.
- a broad catalog of shallow scenarios.
- a production hosting platform for user workloads.

## Deferred Capabilities

The following capabilities are explicitly deferred until the core learning loop and isolation model are proven:

- Multi-user production authentication and account recovery.
- Persistent learner profiles, history, progression, and achievements.
- Additional Room families and advanced difficulty levels.
- An AI incident team as an optional in-product collaboration capability.
- Multiplayer and instructor-led sessions.
- A scenario marketplace and third-party scenario authoring.
- Alternate operating systems and non-Linux runtime environments.
- Organization administration, billing, and enterprise reporting.

## Success Criteria

The MVP succeeds when evidence shows that:

- A learner can enter the Disk Full Room, use real system commands, identify the cause, and restore the target service from the browser.
- The failure and recovery are genuine inside the isolated environment rather than simulated by interface logic.
- Reset recreates the same initial incident reliably, and stale sessions cannot access the replacement environment.
- Concurrent Room attempts remain isolated and cannot access host or control-plane resources.
- Resource limits and cleanup prevent an abandoned or hostile attempt from persisting outside its allowed lifetime.
- The Room Report helps the learner explain the symptoms, root cause, and recovery in their own words.
- User testing demonstrates improved confidence and repeatable diagnostic reasoning after completing and replaying the Room.
