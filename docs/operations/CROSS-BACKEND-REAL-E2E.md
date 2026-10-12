# Issue #12: real-kernel cross-backend release E2E

This is **source-only privileged non-production acceptance**. Running it
requires an expressly designated disposable Docker-capable test VM; the
STL_E2E_DISPOSABLE_HOST=approved flag is not permission to run on an Agent
control plane or production host. Docker shares the VM kernel, so module
autoload is possible. Test images are built on the disposable test host;
no host packages, systemd units or strongSwan services are changed.

## Reproduction and identity

Use the build/run commands in [DEVELOPMENT.md](../DEVELOPMENT.md).
Review the Dockerfile and base image digest first. The root driver refuses
an unclean checkout, absent images or unverified test-binary digest, and
enforces fresh --network none containers with a read-only mount of the exact committed script/go.mod and binary,
no Docker socket, no host systemd or foreign runtime state. Each guest uses
temporary veth-backed A/B network namespaces. The test executable uses the
canonical production CLI -> Engine -> backend path, not a simulated tunnel.
Ordinary non-privileged CI executes only the script syntax check.

Record the exact Git HEAD, SHA256 of the test executable, guest image IDs,
distribution (/etc/os-release), architecture, kernel, iproute2, WireGuard
tools, and the named PASS markers. The distributions are **container
userspace** sharing the **disposable test VM kernel**; they do not certify
independent guest kernels. Keep relevant public packet counters and verified
owned aliases/firewall rules/FOU mappings, but never credentials or sensitive
Quick Link handoffs.

## Acceptance checks (PASS requires a real successful run)

- GRE Native + keyed GRE/FOU + keyed GRE/GUE simultaneously share the same
  A/B underlay while retaining independent Link IDs, /31 addresses,
  receive mappings/firewall rules and real bidirectional packets.
- The same per-side Engine state roots host authenticated WireGuard. The
  four persisted IDs, public handshake/RX/TX, MTU diagnosis, and real
  bilateral inner traffic over all four active Links must pass.
- With WireGuard and sibling GRE modes active, remove, re-create and
  idempotently re-ensure GRE/FOU. Intentionally delete A's strictly owned
  GRE/FOU interface, reapply and reconfirm all other Link traffic/rules.
- Concurrent independent CLI/Engine Ensure operations claim the same FOU
  receive port with distinct Link IDs and subnets. Exactly one may commit;
  the other must return machine-readable conflict. Remove the winner only.
- Introduce a **task-created synthetic foreign GRE interface** at the
  deterministic would-be name, refuse adoption with unchanged identity,
  delete only the synthetic foreign fixture and verify sibling traffic.
- With all four GRE/WireGuard Links still live, bring up **actual
  strongSwan/IKEv2 + Linux XFRM/ESP** inside the SAME disposable A/B
  namespaces, same underlying 192.0.2.10/11 endpoints and same per-side
  fsynced state roots. Use a fifth, independent IPsec Link ID and /31.
  Confirm a five-Link exact-ID inventory on both peers, reject plaintext
  pre-negotiation, then prove two-way encrypted packets and kernel ESP SAs.
- Bring up an independently keyed **sixth, NAT-T IPsec Link** without
  retiring the fifth ESP Link or any GRE/WG siblings. Reject pre-IKE
  plaintext, then verify actual bilateral NAT-T packets, two
  ESP-in-UDP SAs and four total ESP SAs on *each* namespace, distinct
  /31 and exact six-Link shared-state inventory.
- With both IPsec Links negotiated, remove/reapply/repair GRE/FOU;
  recheck live ESP, NAT-T, GRE and WireGuard traffic and resource identity.
  Remove the ESP Link *first* and verify NAT-T SAs, protected credentials,
  traffic and the exact five surviving Links. Then remove NAT-T and verify
  both credential retirement receipts, zero ESP SAs and XFRM aliases and
  the four original GRE/WireGuard siblings still carry packets.
- Remove/retire WireGuard without deleting any GRE sibling; execute the
  existing sequential IPIP Native, FOU and GUE suite while GRE is still
  alive. Reject same-peer IPIP resource collisions, then remove exactly
  the owned resources and verify namespace, rule and mapping cleanup.

If a required capability is absent, this E2E attempt must **fail**, not
silently skip the backend and report PASS. The harness checks owned state,
exact firewall and FOU mappings, guest/host routing baselines, and cleanup
without blindly restoring unexpected host changes. For interrupted tests,
inspect and retire **only task-owned** resources after reviewing evidence.

## Five-Link real IPsec acceptance method

The isolated cross-backend image now includes `charon-systemd` and
`strongswan-swanctl` userspace, solely inside task-created Docker images.
Build distinct Ubuntu 24.04 and Debian 13 image tags from
`cross-backend.Dockerfile`, as documented in `docs/DEVELOPMENT.md`.
The root driver opts in with `STL_E2E_CROSS_WG=approved`,
`STL_E2E_CROSS_IPSEC=approved` and `STL_E2E_CROSS_NATT=approved`;
the standalone GRE runner remains usable without optional IPsec.
`TestIPsecCanonicalCLIRealIsolatedE2E` adds strictly test-only `c`
(ESP) and `d` (NAT-T) identities and uses the exact per-peer
`/tmp/stl-gre-e2e.*/{a,b}` shared state root when the cross-mode option
is present. Normal CLI and production admission are unchanged.

The runner owns two fixture-only strongSwan processes (one per namespace),
a private 0700 VICI configuration directory, and the bounded test-only
CLI credential exchange. The restricted disposable Docker capability set
includes `NET_BIND_SERVICE` for strongSwan's IKE UDP 500/4500 listeners;
without it VICI can appear healthy while IKE traffic is impossible.
Each fresh namespace must confirm BOTH actual UDP listeners before Connect. It starts no host systemd unit and never mounts
an Agent's host strongSwan socket, runtime, credential directory or
network namespace. The guest test forces the IPsec capability rather than
silently skipping it. Host-only CI checks source syntax; actual privileged
packet proof must be performed independently in disposable guests.

The original five-Link markers remain supported. New markers
`SIX_SAME_PEER_GRE_NATIVE_FOU_GUE_WG_ESP_NATT=PASS`,
`FOU_RECOVERY_PRESERVES_ESP_AND_NATT=PASS`,
`REMOVE_ESP_PRESERVES_NATT_AND_GRE_WG=PASS` and
`NATT_SCOPED_REMOVE_PRESERVES_GRE_WG_SIBLINGS=PASS` are emitted **only**
after real in-kernel ESP/ESP-in-UDP observations, protected native
CLI operations, exact shared-state inventory, bilateral traffic and
scoped cleanup. A syntax check or ordinary CI Go test does **not**
constitute these acceptance results. The complete source-bound Docker
matrix and final cleanup must both succeed; record failed/blocked
attempts separately instead of inventing PASS evidence.

## Ephemeral privileged PR verification

`.github/workflows/cross-backend-e2e.yml` runs this exact-source matrix
on two separately allocated GitHub-hosted disposable **VMs** for
same-repository PRs touching runtime/E2E files: an Ubuntu 22.04 x86_64
runner and a **real** Ubuntu 24.04 ARM64 runner. These two hosts have
independent, running kernel identities. The workflow explicitly loads only the `fou` and `ipip` kernel
modules in these disposable runners: the first PR x86 runner failed
early GRE/FOU inspection until `fou` was loaded, and the next x86
and ARM64 runs both proved the new six-Link ESP/NAT-T lifecycle but
stopped on a later IPIP Native `inspect_failed` before completing
the full preexisting IPIP matrix. A missing module still **FAILS**
acceptance; no bypass or SKIP is permitted. It does **not** modify the dedicated AI Test
Server or AI Server Agent. The workflow checks out the PR's exact HEAD,
uses a read-only repository token with no persisted checkout credentials,
builds test-only Ubuntu 24.04 and Debian 13 images, and exercises both
guests with `--network none` and the existing owner-/cleanup-guarded
driver. The runner has a distinct, ephemeral x86_64 kernel and real
kernel tunnel operations, but **not** independently booted distro
kernels or a whole-guest OS reboot. A successful ARM64 job with
`uname -m=aarch64`, `GOARCH=arm64`, native guest architecture, real
packet evidence, correct exclusive kernel resource identities and cleanup
**does** qualify as native ARM64 runtime evidence. Cross-compilation does not.

Real `SUCCESS` runs for both native architecture jobs with the six-Link
markers and zero cleanup failures are required before claiming the full
cross-backend architecture matrix; record partial successes by kernel and
distribution without promoting them to a full matrix PASS.
acceptance. A blocked job, missing container capability, cancelled
run, unsupported provider kernel, or `SKIP` is not acceptance.
The ordinary Go CI remains nonprivileged and is not a substitute.

## Remaining gates outside this package

Issue #12 stays **OPEN** pending actual full guest reboot/boot persistence
(distinct from a real systemd service restart), broader failure/rollback and
full reboot/boot coverage for strongSwan and mixed Links, plus ARM64 **runtime** acceptance where
an isolated capable machine is available. Cross-building on amd64 is not
ARM64 runtime proof. Valid earlier systemd GRE/IPsec and standalone IKEv2
ESP/NAT-T proofs remain separate evidence; this Docker runner does not
pretend to retest them.

Issue #11 exclusively owns release artifacts and safe
install/update/uninstall. No merge, tag, release or deployment is implied.
