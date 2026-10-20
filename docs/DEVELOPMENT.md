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

Source-code reuse is separate from learning from other projects.
Check the source's actual license and provenance before incorporating
code or derived files into MIT-licensed STL. Public visibility is not
a license grant; copyleft material needs an explicit compatibility
decision rather than accidental copying. In particular, an early
design reference, `AminMGMT/BackPack`, was identified as AGPLv3:
**do not copy its implementation into STL's MIT-distributed code**
without a separate reviewed licensing decision. Historical source
audits and exact dates are recoverable from Git history, not a
standing dependency on that project.

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

Tests are evidence, not ceremony. Add and execute checks when they can
catch a real behavior, security, state, compatibility, concurrency or
rollback problem. During implementation prefer focused deterministic
checks, then the required broad/exact-candidate gates when stable.
Do not repeatedly run expensive whole-system suites as a proxy for
understanding changed code. Do not add duplicate tests for trivial
language behavior or unchanged surfaces.

For a stable Go candidate run the repository-required acceptance
commands (plus the exact-candidate GitHub CI):

~~~sh
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
~~~

- Unit/fake-runner tests: validators, addressing/collision, versioned
  pairing and JSON contracts, secret redaction, Engine idempotency and
  exact-owned rollback/error classifications.
- Privileged Linux tests: real Link Address packets for selected
  GRE/IPIP/WireGuard/IPsec backends, resource/credential ownership,
  mixed/same-peer and distinct-peer Links, kernel MTU and diagnostic
  observations. Unsupported capabilities are failures or explicit
  unsupported results, never silent PASS.
- Full-guest persistence tests: installed binary, trusted systemd,
  **the same committed Link after real guest reboot** and observed
  bilateral packets, with a separately tested crash/recovery path
  when the release change warrants it.
- Release qualification: verified exact-tag downloads and installed
  identities are a separate gate from green source/CI. Physical
  two-server WAN/NAT acceptance is an Owner-controlled test,
  not inferred from isolated namespace/VM acceptance.

**Privileged host/network operations require separate authorization
and a dedicated disposable VM/guest**. The `STL_E2E_DISPOSABLE_HOST`
opt-in flag is not authorization by itself. Never execute privileged
E2E on a production, shared or AI Server Agent control-plane host.
Docker guests can share their host kernel and trigger module loads;
if this would affect an unauthorized host, use an isolated VM.

Use the established reproducible runbooks instead of repeating
long environment-specific commands or old acceptance reports here:

- [Cross-backend real E2E](operations/CROSS-BACKEND-REAL-E2E.md):
  six simultaneous GRE/WireGuard/IPsec Links, sequential IPIP,
  native architecture, collision and sibling isolation proof.
- [IPsec real native/systemd E2E](operations/IPSEC-REAL-E2E.md):
  positive private-runtime admission, ESP/NAT-T traffic, VICI/XFRM,
  restart/restore and safe retirement.
- [Release artifacts](RELEASE-ARTIFACTS.md) and
  [Install](INSTALL.md): installer/offline regressions,
  exact published artifact identity and compatibility/rollback.

Representative source scripts include:

~~~sh
bash scripts/test-install-requirements.sh
bash scripts/test-install.sh
bash scripts/test-quick-install.sh
~~~

For an independently authorized disposable kernel test, select the
narrowest relevant runner (such as
`scripts/e2e/gre-netns.sh`,
`scripts/e2e/gre-multipeer-netns.sh` or
`scripts/e2e/cross-backend-docker.sh`) according to the runbook.
Record source SHA, runner/guest/kernel/toolchain identity, command,
test result and cleanup evidence with the candidate's CI/work item.
Do not turn an old run's outcome into a claim about a new source
or installed release.

### Optional WSS v11 executable compatibility

The WSS Carrier is **not active in STL**. To verify the first helper's
real parser/TLS/restricted-UDP forwarding behavior on a disposable Linux
x86_64 test host, extract the official `wstunnel v11.0.0` Linux amd64
archive and verify it against the upstream release `checksums.txt`.
Then, with the extracted binary at an **absolute path**, run:

~~~sh
scripts/e2e/wss-v11-compat.sh /absolute/path/to/wstunnel 6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49
~~~

The runner independently enforces that executable SHA-256 and exact
`wstunnel-cli 11.0.0` version, creates short-lived test certificates
and **public test-only** bearer headers, and uses unprivileged
`unshare -Urn` with IP/loopback sockets confined to a newly
verified user+network namespace. Even a direct call to the internal
`--inside` mode fails before any IP operation without the independent
binary/namespace-launch evidence. The test checks the real version's
**mTLS + per-Link bearer + exact path** behavior, including the
reviewed missing-CN-with-forged-path bypass attempt *without*
the bearer. The upstream v11 does not enforce strict CN identity
when a certificate has no CN; approved admission requires the
additional secret, as described in
[ARCHITECTURE.md](ARCHITECTURE.md).
It needs Bash, OpenSSL, Python 3,
`ip`, `ss`, `sha256sum`, `timeout` and unprivileged user namespace
support. It never installs system packages, starts a host service,
changes host routing/firewall or touches real peers. The upstream
release and the generated fixture policy are deliberately pinned;
a different architecture/version requires a separately verified
acceptance envelope, not an arbitrary latest download. This optional
test does not replace native regression tests or actual STL-managed
two-peer acceptance.

## Git and documentation ownership

- `main` is the protected integration target. Use scoped branches,
  reviewable PRs and repository-required CI/approval gates.
- GitHub Issues/PRs/checks/releases own active work, implementation
  history and exact evidence; don't mirror their changing status
  into product or operational documents.
- `docs/PROJECT-SPEC.md` is the **single durable product intent**
  reference. It changes only when product-level goals, non-goals
  or accepted architectural constraints genuinely change.
- `docs/ARCHITECTURE.md` owns Engine/backend/system design and
  durable resource/runtime boundaries. Accepted architectural
  trade-offs live in short, maintainable `docs/decisions/` ADRs.
- `docs/CLI.md` owns machine command/schemas; `docs/PAIRING.md`
  owns setup-link encoding/inversion; `docs/SECURITY.md` owns
  secrecy and privilege policy; `docs/DIAGNOSTICS.md`
  owns measurement semantics.
- `docs/INSTALL.md`, `docs/OPERATOR-RECOVERY.md`,
  `docs/SUPPORTED-ENVIRONMENTS.md`,
  `docs/RELEASE-ARTIFACTS.md` and `docs/operations/` own
  their respective executable procedures and supported boundaries.
- `README.md` is the concise user introduction, quick start
  and navigation map. Code and tests are implementation truth.

If sources conflict, reconcile the source that actually owns the
contract. Prefer links over copying rules into another long
document. A new file/ADR earns its place only when it serves
a lasting, distinct, demonstrably useful purpose.
