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
enforces fresh --network none containers with a read-only source/binary mount,
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
- Remove/retire WireGuard without deleting any GRE sibling; execute the
  existing sequential IPIP Native, FOU and GUE suite while GRE is still
  alive. Reject same-peer IPIP resource collisions, then remove exactly
  the owned resources and verify namespace, rule and mapping cleanup.

If a required capability is absent, this E2E attempt must **fail**, not
silently skip the backend and report PASS. The harness checks owned state,
exact firewall and FOU mappings, guest/host routing baselines, and cleanup
without blindly restoring unexpected host changes. For interrupted tests,
inspect and retire **only task-owned** resources after reviewing evidence.

## Remaining gates outside this package

Issue #12 stays **OPEN** pending actual full guest reboot/boot persistence
(distinct from a real systemd service restart), broader failure/rollback and
cross-backend IPsec interactions, plus ARM64 **runtime** acceptance where
an isolated capable machine is available. Cross-building on amd64 is not
ARM64 runtime proof. Valid earlier systemd GRE/IPsec and standalone IKEv2
ESP/NAT-T proofs remain separate evidence; this Docker runner does not
pretend to retest them.

Issue #11 exclusively owns release artifacts and safe
install/update/uninstall. No merge, tag, release or deployment is implied.
