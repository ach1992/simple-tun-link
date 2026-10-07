# ADR-0001: Go control plane, native data plane

- Status: Accepted
- Date: 2026-10-07

## Context

The predecessor scripts demonstrated that shell can quickly configure GRE, WireGuard, and IPsec, but duplicated lifecycle/validation/firewall/diagnostic logic grows difficult to reason about as methods and future panel/agent use expand.

The desired product still needs to remain operationally simple and high-performance.

## Decision

Implement the project control plane in Go from the first version.

For native backends, packet forwarding remains in Linux/native implementations. Go orchestrates configuration, state, validation, diagnostics, rollback, and presentation; it does not copy tunnel packets.

Prefer small validated integrations with standard Linux tools/interfaces over reimplementing networking protocols in userspace.

Keep engine logic independent of the interactive menu and provide non-interactive/machine-readable CLI behavior so a future agent/panel can reuse the same engine.

## Consequences

Positive:
- typed state/configuration;
- testable orchestration;
- safer process execution and input handling than large shell managers;
- cleaner backend contracts;
- easier future agent/API/panel composition;
- no native-backend dataplane performance penalty.

Cost:
- binary build/release pipeline is required;
- Linux integration still requires careful privileged testing;
- Go architecture can be over-engineered if abstractions are added speculatively.

Constraint:
- do not build daemon/API/database infrastructure until an actual consumer requires it.
