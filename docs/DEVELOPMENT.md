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

The Issue #12 release-level cross-backend Docker runner requires a
strongSwan-capable disposable image for each supported userspace. It
exercises six *simultaneously persisted* Links on the same two guest
namespaces and state roots: GRE Native/FOU/GUE, authenticated WireGuard,
native IKEv2/XFRM ESP, and a separately keyed IKEv2/XFRM NAT-T Link.
The original five-Link ESP-only acceptance remains historical evidence;
the new NAT-T coexistence gate needs its own successful privileged run.
On an expressly authorized disposable Docker test machine, from a clean
committed checkout, build the task-only images and then run:

~~~bash
docker build -f scripts/e2e/cross-backend.Dockerfile \
  --build-arg BASE_IMAGE=ubuntu:24.04 -t stl-cross-five:ubuntu24 .
docker build -f scripts/e2e/cross-backend.Dockerfile \
  --build-arg BASE_IMAGE=debian:trixie -t stl-cross-five:debian13 .
sudo env PATH="$PATH" STL_E2E_DISPOSABLE_HOST=approved \
  STL_E2E_IMAGE_UBUNTU=stl-cross-five:ubuntu24 \
  STL_E2E_IMAGE_DEBIAN=stl-cross-five:debian13 \
  bash scripts/e2e/cross-backend-docker.sh
~~~

The runner is **not** safe to run on a production or control-plane server.
The image builds use the distribution's package repositories and may
install packages inside the *images only*. The runtime guests remain
network-disconnected with fresh, isolated namespaces. The dedicated
PR workflow now runs this source on both real x86_64 and ARM64 GitHub-hosted
VMs, with exact-native Go/guest architecture assertions; runner-local
`fou` module activation fails closed on unsupported kernels. Six-Link acceptance
requires *both* actual ESP and ESP-in-UDP XFRM SAs, distinct protected
credentials, pre-negotiation plaintext rejection, actual bidirectional
inner traffic, exact shared-state inventory, scoped ESP removal with NAT-T
still operational, and eventual credential/SA retirement. Unavailable
kernel/daemon support is a failure for this required test, not a PASS
or silent SKIP. See
`docs/operations/CROSS-BACKEND-REAL-E2E.md` for exact evidence rules and
remaining full-guest reboot / ARM64 limitations.

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

### GRE and IPIP live acceptance, without a permanent privileged CI runner

After obtaining **separate authorization for a dedicated disposable test VM**, run
`sudo env STL_E2E_DISPOSABLE_HOST=approved ./scripts/e2e/gre-netns.sh`
from a clean checkout. **Never run this on the AI Server Agent control plane,
a shared host or production infrastructure.** The environment flag is a
deliberate local opt-in, *not* authorization by itself.

For the release-level shared-state **GRE Native + GRE/FOU + GRE/GUE +
WireGuard** test, use the same independently approved isolated fixture with
both opt-ins:

~~~bash
sudo env STL_E2E_DISPOSABLE_HOST=approved STL_E2E_CROSS_WG=approved ./scripts/e2e/gre-netns.sh
~~~

This requires working kernel WireGuard support and the wg executable in
addition to existing GRE/IPIP prerequisites. Missing wg is a capability
failure, not a passing test. The cross test uses the same two network
namespaces and **same per-peer state roots** for all four Links; checks the
live four-ID persisted collection; confirms bidirectional encrypted
WireGuard traffic and real active, probe-confirmed MTU/connectivity
diagnosis; then removes/retires only WireGuard and checks that the three
GRE siblings still work before continuing the original IPIP suite.
The flags alone never authorize testing on an active control-plane host.

### Reproducible Ubuntu/Debian same-peer cross-backend release E2E

Issue #12 owns the combined real-kernel acceptance. Use **only an expressly
designated disposable Docker-capable test VM**, never a shared host, production
or the AI Server Agent. Docker containers share the host kernel and may cause
module autoload; if that effect is forbidden, use a dedicated disposable
VM with its own kernel instead.

From a committed clean checkout on that test VM, prepare both task-only images
(online packages are installed only in the disposable image builds):

~~~bash
docker build -f scripts/e2e/cross-backend.Dockerfile \
  --build-arg BASE_IMAGE=ubuntu:24.04 -t stl-cross-backend:ubuntu24 .
docker build -f scripts/e2e/cross-backend.Dockerfile \
  --build-arg BASE_IMAGE=debian:13 -t stl-cross-backend:debian13 .
sudo env STL_E2E_DISPOSABLE_HOST=approved \
  ./scripts/e2e/cross-backend-docker.sh
~~~

The driver builds the exact clean Git revision into one test executable,
verifies its SHA256 inside each fresh network-disconnected container, and runs
two fresh guest namespaces with task-owned state. It performs no host-wide
package or firewall administration, and does not mount host networking,
Docker socket, agent credentials or systemd. Both guests exercise **real**
GRE Native, FOU, GUE, WireGuard and sequential IPIP using the canonical
CLI/Engine. Live same-peer coexistence, idempotency, FOU remove/reapply,
owned interface-loss recovery, simultaneous FOU port claims, foreign
interface rejection, sibling packet delivery and scoped cleanup must pass;
no mock/skip is accepted as proof.

Keep a release receipt with guest versions, source and executable SHA,
kernel and packet/rule observations, plus explicit missing capabilities.
See [cross-backend evidence and outstanding gates](operations/CROSS-BACKEND-REAL-E2E.md).
This does **not** assert ARM64 runtime, full guest reboot, IPsec plus all
other backends in one session, or physical power-loss durability.

### GRE Native, one A host with two distinct peers

After separate authorization for an isolated disposable test VM, the
three-namespace runner can be executed from a **clean committed checkout**:

~~~bash
sudo env STL_E2E_DISPOSABLE_HOST=approved ./scripts/e2e/gre-multipeer-netns.sh
~~~

This **separate Issue #12 fixture** reuses the same production GRE test/CLI/Engine,
with independent A-B and A-C synthetic underlay pairs, two stable Link IDs and
one A-side desired-state directory. It checks bidirectional Link Address
traffic, identity-checked status/diagnostics, idempotent reapply, the exact
saved Link ID sets, A-C traffic and firewall identity after A-B removal,
and owned cleanup. It changes no host control-plane configuration. Actual
kernel acceptance requires a documented **successful privileged execution**;
source/CI/Go skip alone are not a live proof. Real systemd service
restart/restore remains a distinct release requirement.

The opt-in script creates only fresh paired network namespaces, synthetic
veth underlay and per-side temporary state; it invokes the real CLI/Engine/GRE
backend for Native, FOU and GUE on the same synthetic underlay pair,
using distinct GRE keys for the UDP-encapsulated siblings. The unkeyed
same-pair FOU request must fail as a typed conflict before host mutation.

The **same namespace pair and temporary state** then runs IPIP Native,
FOU and GUE sequentially via the real CLI and IPIP backend, while all
three existing GRE Links remain active. IPIP endpoint-pair lookup cannot
distinguish a second IPIP mode to the same underlay pair, so the attempted
second mode must fail with a typed conflict and without leaked UDP receive
state. Each IPIP mode must pass create, idempotent ensure, identity-checked
status, bidirectional Link Address traffic, read-only diagnostic counters
and owned removal. After each removal, the GRE Links must still pass
bidirectional traffic and their existing FOU/GUE mappings must be unchanged.

The runner verifies sibling isolation and final cleanup. Cleanup runs
even on failure. It does **not** install packages, load modules explicitly,
reconfigure the host control-plane interface, or silently report unsupported
FOU/GUE capabilities as passing. Kernel module autoload may still occur;
therefore the host must be disposable.

Preserve the complete log, test exit code, source SHA and printed kernel,
iproute2, iptables and Go versions as Issue #4/#12 acceptance evidence.
Compiling the gated Go tests and syntax-checking the script in ordinary CI
**do not count as privileged live evidence**. The opt-in flag alone is never
permission to test on a shared or production host. This slice validates
GRE/IPIP cross-backend isolation. The optional WireGuard cross fixture
covers one four-Link same-peer scenario; the separate three-namespace fixture
targets different-peer concurrent Links. Neither source fixture, without
real approved execution, satisfies the corresponding live acceptance.
IPsec, concurrency/failure, real systemd persistence/restart, the
Ubuntu/Debian release matrix and arm64 qualification also remain Issue #12 gates.

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
