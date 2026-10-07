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
10. Keep future panel/agent use possible through deterministic CLI/JSON/core boundaries without building the panel now.

## Toolchain

The project targets Go 1.27 for initial development.

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

### Unit tests
Cover:
- parsing/validation;
- address allocation;
- setup-link encode/decode/versioning;
- plan/idempotency logic;
- secret redaction;
- CLI/JSON contracts where useful.

### Linux integration tests
Use network namespaces and disposable interfaces for:
- create/reapply/remove;
- actual data transfer, not only interface existence;
- failure rollback;
- MTU behavior;
- conflicting resources;
- two simultaneous links;
- mismatched peer configuration;
- reboot/reapply semantics where feasible;
- backend isolation.

Privileged tests must run only in an explicitly disposable environment and may never mutate the AI Server Agent control-plane interface/routes/firewall.

## Git/GitHub

- main is the integration target.
- Use focused branches and reviewable PRs for substantive code.
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
