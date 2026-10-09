# Development Guide

## Principles

1. Preserve the Link abstraction: consumers care about Link Addresses, not backend internals.
2. Keep Go in the control plane for native backends.
3. Prefer safe native Linux interfaces/tools rather than reimplementing networking protocols without a concrete need.
4. Make operations idempotent and rollback only owned state.
5. Fail loudly and actionably; never report success after a failed apply.
6. Keep interactive UI separate from engine logic.
7. Add abstractions only when current implementation has at least two real implementations/consumers or a proven near-term need.
8. Optimize from measurement, not folklore.
9. Avoid global host tuning unless the selected backend demonstrably requires a narrowly scoped change.
10. Keep generic external reuse possible through deterministic CLI/JSON/core boundaries without designing around any particular future consumer.

## Toolchain

The project language baseline is Go 1.27.0 and the repository pins the current development/build toolchain with the `toolchain` directive. CI must use that directive through `actions/setup-go` rather than silently selecting an older patch.

Use the standard toolchain commands:

~~~bash
gofmt -w .
go vet ./...
go test ./...
~~~

CI checks formatting, vet, and tests.

## Dependency policy

Prefer the Go standard library.

A dependency is justified when it materially improves correctness, portability, maintainability, or implementation risk and the value exceeds supply-chain/API/maintenance cost.

Do not introduce:
- a CLI framework merely for a handful of commands;
- a TUI framework before the interactive workflow needs capabilities not reasonably served by a small terminal layer;
- ORM/database layers in v0.1;
- a generic plugin framework for built-in backends.

## External commands

Command execution must:
- use argv-based execution, never shell-concatenate untrusted input;
- use explicit timeouts/contexts;
- capture stderr separately enough to produce actionable failures;
- validate parsed outputs;
- never log credentials/private keys;
- be wrapped behind narrow Linux integration functions so tests can substitute behavior.

## Machine-readable contracts

Interactive terminal text is not an API.

Every JSON payload must include a top-level integer `schema_version`. Additive backward-compatible fields may keep the same schema version; breaking semantic/shape changes require a version bump and explicit compatibility handling. JSON output and exit codes must never expose secret material.

Automation should prefer idempotent desired-state operations such as `stl link ensure ... --json` rather than reproducing lifecycle branching outside STL.

## State

State writes must be atomic.

Secret-bearing files must use restrictive permissions.

State schemas are versioned. Unknown newer schema versions must fail safely rather than being partially interpreted.

## Error handling

Errors should preserve:
- operation;
- object/backend;
- underlying cause;
- actionable context.

Do not swallow errors with “best effort” semantics when failure changes actual link correctness.

Optional cleanup/diagnostic failures may be warnings only when the requested operation is still genuinely correct.

## Testing

Testing is evidence, not ceremony. Add or run a test only when its failure could reveal a real behavioral, compatibility, security, concurrency, rollback, or contract defect. Do not add tests for obvious language/compiler behavior, trivial getters/constants, documentation-only edits, or implementation details already exercised by a stronger behavioral test.

During implementation:
- run the narrowest relevant package/test after a meaningful behavioral slice when early feedback is useful;
- do not rerun the full suite after every edit;
- do not use race, fuzz, repeated/shuffled loops, cross-compilation, or privileged E2E by default—use them only when the changed surface creates that specific risk or a prior failure justifies them;
- when a regression is fixed, keep one focused deterministic regression where practical instead of permanently repeating large stress loops;
- preserve still-valid evidence after unrelated edits.

For a stable Go candidate, run the repository-required acceptance gate once: formatting, `go vet ./...`, `go test ./...`, and exact-candidate CI. Re-run broader evidence only when a later change invalidates it.

### Unit tests
Prioritize behavior with meaningful failure modes:
- parsing/validation and malformed input;
- address/resource allocation and collision rules;
- setup-link encode/decode/versioning and secret redaction;
- plan/idempotency/rollback logic;
- public CLI/JSON/error contracts where compatibility matters.

Avoid duplicate tests that prove the same branch through multiple layers unless the layer boundary itself is the risk.

### Linux integration and E2E tests
Use disposable environments only for behavior that unit/fake tests cannot establish, especially real kernel/backend effects:
- create/reapply/remove and actual data transfer;
- rollback after real partial failure;
- MTU/PMTU behavior and backend counters;
- collision/isolation across simultaneous Links;
- same-peer coexistence, including GRE Native + WireGuard + GRE/FOU;
- persistence/restart behavior in a disposable systemd-capable environment;
- backend-specific capability and mismatch behavior.

Do not duplicate the full cross-backend matrix in each backend Issue. Backend Issues own focused backend proofs; Issue #12 owns release-level coexistence, multi-Link, restart/reapply, and supported-environment E2E evidence.

Privileged tests may never mutate the AI Server Agent control-plane interface/routes/firewall.

### GRE live acceptance, without a permanent privileged CI runner

After obtaining **separate authorization for a dedicated disposable test VM**, run
`sudo env STL_E2E_DISPOSABLE_HOST=approved ./scripts/e2e/gre-netns.sh`
from a clean checkout. **Never run this on the AI Server Agent control plane,
a shared host or production infrastructure.** The environment flag is a
deliberate local opt-in, *not* authorization by itself.

The opt-in script creates only fresh paired network namespaces, synthetic
veth underlay and per-side temporary state; it invokes the real CLI/Engine/GRE
backend for Native, FOU and GUE separately. For each mode it checks first
ensure, idempotent re-ensure, verified status, real bidirectional Link Address
traffic, read-only diagnostics, owned removal and empty state. Cleanup runs
even on failure. It does **not** install packages, load modules explicitly,
reconfigure the host control-plane interface, or silently report unsupported
FOU/GUE capabilities as passing. Kernel module autoload may still occur;
therefore the host must be disposable.

Preserve the complete log, test exit code, source SHA and printed kernel,
iproute2, iptables and Go versions as Issue #4/#12 acceptance evidence.
Compiling the gated Go test in ordinary CI does **not** count as a live pass.
This backend-focused test does **not** replace Issue #12's coexistence,
concurrency, pairing, systemd restart or distro release matrix.

## Git/GitHub

- main is the integration target.
- Use focused branches and reviewable PRs for substantive code; `main` is protected by required PR + CI once repository rules are applied.
- Issues own unresolved durable work.
- ADRs own lasting architectural decisions.
- Do not mirror live status into docs.
- PRs should link the Issue they implement.
- CI evidence is tied to the candidate commit.

## Documentation authority

- docs/PROJECT-SPEC.md: project outcome/scope/constraints.
- docs/ARCHITECTURE.md: technical boundary.
- docs/decisions/: lasting rationale.
- GitHub Issues: live unresolved work.
- code/tests: implementation truth.
- README: entry point/navigation.

If these conflict, fix the authoritative source rather than adding explanatory duplication elsewhere.
