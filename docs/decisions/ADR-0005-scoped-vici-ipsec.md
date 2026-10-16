# ADR-0005: Scoped IPsec VICI and an STL-owned native runtime

- **Status:** Accepted
- **Original decision:** 2026-10-10; subsequent accepted operational boundary
  incorporated here
- **Decision evidence:** [Issue #7](https://github.com/ach1992/simple-tun-link/issues/7),
  [Issue #101](https://github.com/ach1992/simple-tun-link/issues/101),
  [Issue #105](https://github.com/ach1992/simple-tun-link/issues/105),
  [Issue #112](https://github.com/ach1992/simple-tun-link/issues/112)

## Context

STL must manage independent IPsec/XFRM Links without disturbing another
connection or a foreign strongSwan installation. Bulk `swanctl --load-conns`,
`--load-creds`, `--clear`, daemon restart or config reload can reconcile
objects other than the intended Link. In shared VICI namespaces,
`load-shared` and `load-conn` may replace matching names; inspecting name
vacancy alone cannot close a race with an external writer.

## Decision

1. **Dedicated, attestable runtime.** Operational IPsec uses one
   STL-owned native-exclusive `charon-systemd`/strongSwan runtime per
   eligible host, serving multiple per-Link IKEv2/XFRM identities. Its
   exact origin, effective systemd configuration, trusted executable and
   active process, VICI socket/peer credentials, bounded IKE UDP port
   ownership and secret-safe effective logging are independently attested.
   IPsec is not admitted when that combined proof is incomplete.
2. **Scoped VICI calls only.** Use the maintained `govici` protocol
   implementation with per-Link `load-conn`/`unload-conn` and
   `load-shared`/`unload-shared`. Never use daemon-wide connection or
   credential loads, global flush, reload or restart as ordinary Link
   operations. A matching name is not ownership proof.
3. **Stable per-Link identity.** Derive deterministic VICI object names,
   XFRM identity and selectors from the complete Link ID and public Link
   addresses. XFRM `if_id` is a possible collision key, not a right to
   adopt an interface. Per-Link SA/policy selectors are scoped to the
   endpoint Link Addresses; do not silently install catch-all routes or
   `0.0.0.0/0` child selectors.
4. **Canonical Engine ownership.** All effectful IPsec operations use
   shared Engine maintenance, Link and resource locks; re-inspect state
   immediately before effects; verify exact owned identity. Persist
   protected, nonsecret operation journals for ambiguous VICI/XFRM
   creation, deletion and restoration. A kernel interface name/alias
   without a durably recorded original ifindex grants no deletion right.
   An uncertain operation halts further mutation pending explicit
   identity-bound reconciliation, never blind retry.
5. **Protected credentials and scoped retirement.** Keep the 256-bit
   per-Link PSK in private, descriptor-verified, no-replace storage; keep
   sensitive receiver handoffs distinct from ordinary State/JSON/logs.
   Loading requires an attested safe daemon CFG logging policy. A
   successful Link Remove publishes an exact nonsecret retirement receipt;
   `retire-ipsec` can then retire the corresponding PSK without an
   active daemon, but never from Link absence alone.
6. **Qualified preparation, never silent takeover.** Missing trusted
   distro prerequisites and verified STL-private service publication may
   be prepared only under a specifically previewed, approved transaction.
   Package hooks may have disclosed persistent effects; a failed package
   operation is not atomic Link rollback. A separately verified service
   installed by that transaction may be stopped/disabled after its exact
   provenance is established. A **pre-existing official distro
   `strongswan.service`** may be stopped/disabled only through the
   separately typed `STOP strongswan.service` confirmation, clear
   immediate-VPN-interruption warning, independent eligibility and
   identity reattestation under the exclusive maintenance gate.
   Generic `PREPARE` consent never grants this permission. Other
   foreign/unknown services, configs, writers or resources require
   manual remediation and explicit recheck.
7. **Backend isolation.** Unknown, unavailable or conflicting IPsec
   ownership blocks only IPsec; GRE/IPIP/WireGuard remain independent.
   A systemd `not-found/inactive/dead` placeholder for the private unit
   is not automatically a real loaded service or a foreign conflict.
   Its exact classification must be revalidated, not guessed.
8. **Read-only remains read-only.** `doctor`, `status` and diagnostics
   never authorize daemon provisioning or silently repair state; a
   successful local admission check is not proof of IKE/ESP/NAT-T
   connectivity, and no isolated acceptance proves arbitrary WAN/NAT.

## Consequences and trade-offs

- Native-exclusive isolation is a deliberate safety/portability choice,
  not a claim that external strongSwan coexistence is inherently
  impossible. A future coexistence model needs its own real consumer
  demand, safety design and compatibility evidence.
- STL may decline IPsec operation on an ambiguous host rather than take
  over unrelated VPN state. This preserves independence and prevents
  destructive name-based recovery.
- Protected receipts, transaction journals, runtime attestation and
  explicit confirmations add implementation cost, but they belong in
  shared Engine/host adapters rather than divergent interactive and
  machine-facing lifecycles.
- Proven local activation, committed state and observed peer traffic
  remain separate acceptance states.

## Implementation and operational references

- [Architecture](../ARCHITECTURE.md): ownership, shared Engine and
  native-exclusive runtime.
- [Security](../SECURITY.md): credentials, service admission, logs and
  resource protection.
- [CLI](../CLI.md): exact operator/machine commands and confirmations.
- [IPsec native E2E runbook](../operations/IPSEC-REAL-E2E.md):
  reproducible evidence and its explicit limits.
- [strongSwan load-conns](https://docs.strongswan.org/docs/latest/swanctl/swanctlLoadConns.html),
  [load-creds](https://docs.strongswan.org/docs/latest/swanctl/swanctlLoadCreds.html),
  [VICI interface](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md),
  [govici](https://github.com/strongswan/govici).

Earlier source-only milestones and their review history remain in the
linked Issues/PRs and Git history. They are **not** parallel current
operational specifications.
