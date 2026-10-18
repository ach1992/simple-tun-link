# Source-IP Diagnostics — standalone architecture (Owner-approved direction)

Status: **architecture contract / development target**, NOT evidence that the functionality or a release has been delivered. Controlling research owner: [Issue #125](https://github.com/ach1992/simple-tun-link/issues/125). Existing implementation candidate: [DRAFT PR #130](https://github.com/ach1992/simple-tun-link/pull/130).

## 1. Independence from STL

- SAME GitHub repository `ach1992/simple-tun-link`, isolated under `research/spoof-diagnostics/`. The tool is not a built-in backend, an STL Link, a change to STL install/update, or an automatic transport selector.
- Future integration is deliberately **undecided**. Option A: preserve a standalone diagnostic and export only independently verified candidate observations for an operator configuring STL. Option B: after separate architectural approval, integrate a transport adapter beneath STL's normal private Link Address/L3 lifecycle. Neither is authorized by this research contract.
- The research tool never creates STL-managed interfaces, routes, policies, services, credentials, or saved Links. The STL default stable release and `releases/latest` behavior remain unchanged.

## 2. Two product roles and a third optional observer

```text
A: send agent --(approved short lived test datagrams)--> B: independent receive agent
         |                                         |
         |---------- authenticated control --------|
                   (only if reachable)

Optional C: explicitly owned return observer; distinct from A.
```

The measurement model records **observations at specific locations**, not one overloaded "working IP" flag:

1. A local request to transmit (submitted) is not independent physical egress.
2. Independent sender VETH/NIC egress capture is different from B peer ingress.
3. B's authenticated reception is different from a successful return to A.
4. A response addressed to a forged address may be routed to C instead of A.
5. A diagnostic packet in the lab is not a usable authenticated encrypted private L3 Link.

Tests must fail closed on absent evidence. Every observation records `run_id`, `time_window`, `test_environment`, `origin_node`, `peer_observer`, `direction`, `source_ip`, `destination_ip`, `packet_size`, `sample_id`, `policy_epoch`, `status`, `capture_origin`, `auth_verified`, and `limitations`, as applicable. Never expose keys or credentials in ordinary reports.

### Asymmetric directions are first-class

A source address may be eligible for packets **A → B**, while a *different* address/path is eligible **B → A**; measured directional quality may also change with packet size and epoch. Keep separate sets for:

- `tx_source_candidate`: claimed address attached to packets emitted by a particular sender.
- `rx_destination_address`: real destination where the opposite node expects to receive packets.
- `authenticated_peer_observation`: which independently controlled endpoint actually received the request.
- `authenticated_return_observation`: whether and **where** a correlated reply was actually received.
- `direction`: `A_TO_B` or `B_TO_A`, always accompanied by concrete sender/receiver IDs.
- `l3_qualified`: **NOT_TESTED** until independent encrypted/private L3 bidirectional evidence exists.

**Never** assume a reverse tunnel from an A→B source-admission PASS. Each direction is evaluated separately and the final bidirectional readiness check demands verified usable destination/return routing, cryptographic peer authentication, packet integrity/replay controls and actual L3 evidence.

## 3. Standalone Go implementation boundary

Target runtime: a self-contained Go executable `stl-spoofdiag` for supported Linux amd64/arm64. Use standard-library-only Go where possible, pinned exact toolchain and `CGO_ENABLED=0`. No `pip`, `apt`, compiler or `go mod download` on installed hosts. No hidden dependency on running STL.

Proposed stable internal boundaries (keep APIs private until real consumption justifies publication):

```text
operator menu + machine CLI/JSON
        |
configuration and explicit candidate import (CSV/JSON, one or more exact IPs)
        |
preflight / plan / permission gate
        |
test session coordinator -- mTLS identity -- sender/peer observer
        |
independent evidence records -- directional classifier -- report exporter
        |
small protocol/adapter boundary (research-only, not an STL backend)
```

The menu and CLI invoke the same engine and expose the same validation, operation status and error semantics. A console action requiring risk authorization is disabled without the required provider/platform evidence; a text checkbox or fabricated permit JSON is NOT itself permission.

## 4. Private control and evidence rendezvous

The Go candidate now implements a genuine, **loopback-only** TLS 1.3 mutually authenticated control channel with HMAC-authenticated UDP observations and receiver Ed25519-signed portable receipts. A separate functional **local** mode issues sender-signed, bounded/expiring challenges; the receiver independently validates its allowlist, keeps a private consumed-run ledger, verifies individually Ed25519-signed UDP packets, and signs offline receipts. Operators can verify challenge and receipt together without mTLS connectivity. **Absence of the control path is not evidence of packet rejection.** These local modes verify authentication/replay logic, NOT public-IP admission, independent physical egress, asymmetric return routing, or private L3. A separate RFC1918 RAW IPv4 adapter now exists only for detached, veth-only, no-public-route `sdg*` Linux netns using a signed private-destination challenge. At this checkpoint exact-binary A-R-B acceptance is still NOT_RUN. General public-field operation and production credential provisioning are NOT implemented.

Provision and protect peer keys on the appropriate private hosts. Do not package production keys, operator permit documents or observed candidate inventories into a public release.

## 5. Safe transport/test boundaries

Lab: dedicated, non-public netns or full disposable VMs with only RFC1918 addresses, no public default route or external network adapter in test nodes, privileged raw socket only inside that isolated lab. Separate simulated provider/router applies source ACL, return ACL, strict rp_filter, MTU, loss, policy drift. Preserve unrelated host routes/interfaces/sysctls/iptables and verify teardown. Prefer real kernel packet proof for the **exact candidate executable**, not only mocks.

Future authorized field: no forged source packets or public candidate scan until documented source-prefix rights, destination/peer consent, network-provider authorization and platform/tool permission are independently established. A permit file is useful traceable metadata, not independent proof of authorization. Bound duration, exact peers/candidates/rate/size, explicitly requested by operator; no automatic background probe, no third-party reflector/amplifier.

### Result vocabulary

`NOT_TESTED`, `BLOCKED_BY_PERMISSION`, `CONTROL_UNAVAILABLE`, `SUBMITTED_ONLY`, `EGRESS_OBSERVED`, `PEER_OBSERVED`, `RETURN_OBSERVED_AT:<controlled_id>`, `REJECTED_BY_LAB_POLICY`, `INCONCLUSIVE`, `L3_NOT_TESTED`. The system must not collapse these into a single online/offline boolean.

## 6. Future STL consumption — both options remain open

A **versioned, immutable, read-only diagnostic evidence export** is the only tentative cross-product contract. It must include protocol/schema version, run and binary identity, observed direction, exact peers and sources, confidence and evidence provenance, policy epoch, expiry/staleness and `NOT_TESTED` fields. It contains **no** STL Link creation operations, credentials, addresses secretly injected into Link State, or automatic switching policy.

Only a later Owner-approved architecture review may map validated bidirectional carrier capabilities to actual authenticated private L3 and managed STL Link Address operations. A source-IP candidate list alone is insufficient.

## 7. Validation and integration gates

Target acceptance is a runnable **separate Go CLI/menu**, offline bundled package/install/update/uninstall and independent CI, followed by real packet 2/3-node *fully isolated* local E2E and install/recovery negative tests. Existing 22 Python tests prove the earlier Python prototype only, not a future Go port. Root STL Go tests do not replace dedicated diagnostic acceptance. Keep branch/PR DRAFT and do not publish releases or touch physical test servers before appropriate gates.
