# Spoof Diagnostics — delivery contract and evidence-driven acceptance matrix

Scope: **standalone `stl-spoofdiag` Go product** under `research/spoof-diagnostics/`, tracking [Issue #125](https://github.com/ach1992/simple-tun-link/issues/125) and [draft PR #130](https://github.com/ach1992/simple-tun-link/pull/130). No STL runtime or backend integration without the separate Owner architecture decision in #123.

## Accepted operator outcome

An operator should be able to download one architecture-specific release archive and install/use the tool **without Go, Python, package repositories, Docker, or network access** on a destination server. An online bootstrap should download, authenticate, and invoke the *same* offline installer, never download and execute arbitrary `main` scripts. Both routes must expose the same program and version. A clean terminal interface must show identity, current mode, supported operations, missing prerequisites, error explanations, verification status, and clear next action. Errors and invalid menu input must return to the menu, not terminate an otherwise healthy session.

Separate **source-candidate enumeration** (an explicitly authorized/owned input list) from packet submission, independently observed physical egress, authenticated receiver ingress, returnability, and actual bidirectional private L3. Store direction A→B and B→A independently and preserve sample size and policy epoch. Do not silently interpret any of these layers as proving another. Distinguish `PASS`, `FAIL`, `PARTIAL`, `INCONCLUSIVE`, `NOT_RUN`, `APPROVAL_REQUIRED`. Signed receipts prove an identified observer made a claim; independent packet capture corroborates actual ingress; neither proves what an ISP would permit.

Architecture for future STL consumption: standalone diagnostic CLI/JSON engine with versioned, neutral evidence, no STL side effects. STL integration is deferred; do not embed country-specific endpoints, backend assumptions or unreviewed keys in the protocol. Avoid product-imposed source counts or bandwidth quotas; enforce only justified resource, kernel, operator-authorized scope, privacy and packet-safety limits. Test limits of the current experimental adapter must be labelled, not silently marketed as field guarantees.

**Research and evidence boundaries:** The currently proven executable is laboratory restricted. No public-Internet spoofing, third-party recipient testing, public source scanning, host-wide route/firewall changes, production deployment, or bypass of a tool/provider approval. Enabling a general real-network forged-source sender requires distinct security, authorization and provider compatibility review; no permissive user-interface switch proves such permission. Any public release remains gated on exact-artifact acceptance and independent review. Source address filtering (BCP38, RFC2827/3704), kernel uRPF/rp_filter, cloud source/destination checks and provider-specific firewalls can all reject a packet even when a local sandbox passes.

## Isolated acceptance topology

**Required:** two *separate, booted Linux VMs* A and B on separate L2 segments connected by an isolated routing/policy VM R (minimum 3 guests in the strict topology; 2 guests suffice only for direct-peer controls). No VM WAN adapter, host bridge, host management interface, external forwarding, route to the real Internet or shared ambient credential directory. Prefer signed, pinned Debian/Ubuntu guest image, snapshot overlay per guest, ephemeral credential provisioning, fixed private per-guest IPs, and separate terminal/log capture. The sender and receiver must run the **actual final Go binary** (same SHA as installed release). Router R controls private source policy, MTU, delay/loss and simulated path differences. Verify host route/sysctl baseline before and after and task-owned VM shutdown. Linux network namespaces are a useful extra kernel test but are **not VMs** and cannot replace the VM gate.

For a scenario to be **PASS**: report exact source SHA, release SHA, OS/kernel/arch, three guest identities, topology/isolation proof, inputs, expected observation, actual sender log, independently captured A egress and B ingress, signed receipt, run ID, sample counts, verdict and cleanup. A signed zero-observation receipt is `INCONCLUSIVE` unless independent evidence identifies a specific drop point. Missing control/receipt is **not** evidence of blocked source IP.

## Scenario families (execute with bounded, private addresses and synthetic traffic)

| ID | Variation / fault injected | Required discriminating evidence | Current gate |
| --- | --- | --- | --- |
| N01 | A→R→B baseline admitted private candidate | A capture + R forwarding + B capture + matching signed B receipt | VM acceptance pending |
| N02 | B→R→A reverse independent direction | distinct identity, policy and reverse receipt | VM acceptance pending |
| N03 | one candidate accepted, one rejected by R source ACL | separate counters; only admitted identity in signed receipt | VM acceptance pending |
| N04 | all candidates denied | explicit no-success, no fabricated negative IP verdict | VM acceptance pending |
| N05 | R policy epoch changed during run | evidence tied to actual epoch; prior results not reused | VM acceptance pending |
| N06 | R ingress source-validation / B rp_filter modes | strict, loose, disabled; independent drop observability | VM acceptance pending |
| N07 | missing return route or R egress path | distinguish successful forward observation from failed return | VM acceptance pending |
| N08 | asymmetric A→B pass, B→A drop | directional matrix; no inferred symmetry | VM acceptance pending |
| N09 | A packet source differs from signed candidate | B rejects and logs reason without success | VM acceptance pending |
| N10 | changing destination without re-signing plan | sender/receiver reject | unit PASS; VM pending |
| N11 | zero candidates, duplicate, wrong direction, public IP in private plan | input error; **zero emissions** | unit PASS |
| N12 | wrong peer certificate/CA, expired cert, wrong peer role | connection/evidence refused | targeted tests partially PASS |
| N13 | stale challenge, replay, duplicated sample, signature/HMAC tamper | rejects; no success counter | unit PASS; VM pending |
| N14 | zero observed, partial delivery, timeout, recipient down | `INCONCLUSIVE` / `PARTIAL`; no fake failure origin | unit PASS; VM pending |
| N15 | policy drop, random loss, delay, reordering, duplication | rates, duration and provenance separate | VM pending |
| N16 | MTU/DF, small/large payload, fragmentation and checksum behavior | exact packet size, MTU and independent capture | VM pending |
| N17 | UDP port blocked, listener wrong address/port, busy port | actionable error + no false reachability | VM pending |
| N18 | R path switch, multi-interface and asymmetric RPF | symmetric/asymmetric path identity and no unapproved host mutation | VM pending |
| N19 | A/B process stopped or killed mid-session | clear incomplete outcome; safe restart and no orphan listener | VM pending |
| N20 | clock skew and certificate/plan expiry | explicit time-invalid outcome, new challenge path | VM pending |
| N21 | missing CAP_NET_RAW, interface down/renamed, wrong namespace | specific preflight refusal and corrective action | unit partially PASS; VM pending |
| N22 | cannot reach mTLS control but offline signed evidence possible | file-based challenge/receipt succeeds or remains inconclusive | loopback PASS; VM pending |
| N23 | receiver B reachable but return observer C unreachable | no implicit proof of sender-return path | design/proof pending |
| N24 | independent tests after reboot and disk/state preservation | no replay-ledger reset, predictable resume | VM pending |
| I01 | offline fresh install without Go or network | installed binary runs; no downloads, correct arch/version | disposable-root PASS; VM pending |
| I02 | upgrade, verified rollback, safe uninstall, repeat operations | integrity/ownership checked; private state survives | disposable-root PASS; VM pending |
| I03 | broken/archive tamper, wrong architecture, symlink/foreign owner | fail before writes; safe explainable error | disposable-root PASS; VM pending |
| I04 | interrupted install, concurrent install, disk full, read-only partition | atomicity/recovery and no foreign deletion | pending |
| I05 | online pinned bootstrap via trusted origin, blocked network, HTTPS failure | same offline engine, explicit integrity and no execution on download error | pending |
| I06 | artifact signature/provenance failure, wrong tag / stale latest | stop with clear expected vs actual, no execution | pending |
| I07 | Debian/Ubuntu supported guest and amd64/arm64 compatibility | distro/kernel/architecture positive and negative evidence | VM / cross-arch pending |
| U01 | menu header, no-color/nonTTY, invalid selections, malformed paths | stable controls, bounded output, actionable errors; menu remains active | pending |
| U02 | source list/add/import/remove/replace and empty inventory | independent direction identity; no packets emitted | local unit PASS, menu pending |
| U03 | menu challenge/receipt verify and export, positive and tampered files | no secret exposure; explicit evidence layer | pending |
| O01 | packet captures, timestamp/correlation, exports and peer signatures | machine-readable trace sufficient for fresh reviewer | partial |
| O02 | no host/STL side effects, teardown of VMs/files/ports | before-after snapshots, no orphaned resources | namespace infrastructure PASS; VM pending |
| O03 | independently review code, reproducible exact-binary tests, CI | fresh-author read-only review + SHA-pinned result | pending |
| O04 | two licensed real hosts with ISP source-identity consent | **NOT_TESTED / external approval and provider gate** | not a lab claim |

This matrix is a requirement ledger, not a claim that tests were executed. Record exact test evidence in CI/PR/#125 when a scenario is actually run. Do not mark a scenario PASS based on a different program, previous commit, namespace-only ping or unverifiable user report.

## Prioritization and completion

1. Fix existing failing CI before treating the candidate as releasable. Complete finite local source-inventory workflow and interactive-menu recovery.
2. Ship one self-contained offline archive per supported architecture; prove fresh installed binary behavior, upgrade/rollback/uninstall and cold-start without any Go/Python/network on guest.
3. Build a testable online bootstrap with pinned identity and full failure matrix. It must be *functionally tested* against a controlled local artifact endpoint before publishing a GitHub one-line command; a hypothetical `releases/latest` URL is not a tested installer.
4. Build and boot actual isolated VMs, run positive and negative policy scenarios, collect independent packet captures and signed receipts, and correct code in bounded cycles. Do not confuse an A–R–B namespace baseline with VM evidence.
5. Independently review stable diff; inspect release provenance and Owner merge/release gates. Preserve the historical Python prototype until exact-Go feature parity is demonstrated; then remove only proven-unneeded code with reviewable evidence. Keep primary STL README a short pointer to the standalone tool, not an unsafe unverified installer.

**Real-host answer criterion:** Only when the exact released artifact implements and securely authenticates the intended authorized cross-host mode, can be configured on two independent approved hosts, handles provider/OS prerequisites and has passed relevant isolated acceptance is it reasonable to call the program *candidate-ready for a permissioned trial*. It is **never scientifically valid** to promise real provider success from VM results. The experimental `netns-*` adapter is explicitly not a field-ready executable.
