# Field Diagnostics validation and evidence ledger

**Scope:** new Field selected-source implementation on a feature branch.
**Current Owner decision (2026-10-19):** run normal automated builds, Go tests,
race checks, static analysis, installer checks and CI without artificial
restrictions. Do NOT infer real-world forged-source Field reachability or
provider acceptance; a real public-network Field trial was not requested.

| Gate | Status | What is and is not established |
| --- | --- | --- |
| Source refactor and obsolete lab commands removed | IMPLEMENTED IN SOURCE | Deletion alone is not runtime validation |
| Source inventory / exact directional candidates | LOCAL PASS on source candidate | Both directions and multiple exact addresses exercised offline; provider network not tested |
| Sender-signed plan and receiver-signed grant | LOCAL PASS on source candidate | Offline identity, signed A→B/B→A challenge and receiver grant exercised; no packets emitted |
| Normal UDP bind to an assigned selected IP | IMPLEMENTED IN SOURCE | No host or provider socket test |
| Raw IPv4 header with selected source and explicit peer | IMPLEMENTED IN SOURCE | No CAP_NET_RAW or public-WAN test |
| Receiver signed actual socket-source observations | IMPLEMENTED IN SOURCE | No real peer packet received |
| Signed receipt comparison / replay protection | UNIT TESTED | Signed receipt pairing, overclaim/tamper controls and duplicate run ledger checked; no real peer ingress |
| Go formatting / static analysis | LOCAL PASS on source candidate | Exact pushed-HEAD acceptance and CI are separate evidence |
| Automated Go unit and race suites | LOCAL PASS on source candidate; CI PENDING | CI must run on exact final PR HEAD; not public-WAN proof |
| Real-network Field packet capture | NOT_REQUESTED | Previous isolated lab results are unrelated; normal automated tests remain allowed |
| Real two-host A↔B selective-source tests | NOT_RUN by Owner request | No connectivity evidence |
| Provider source prefix consent / acceptance | NOT_VERIFIED | Separate external authorization needed |
| Sender physical NIC egress / NAT rewrite | NOT_TESTED | Independent observer required |
| Sender return path / true private L3 | NOT_TESTED | Out of scope for current diagnostic |
| Debian/Ubuntu ARM64 runtime compatibility | NOT_TESTED for new candidate | Source target only |
| Installer / upgrade / rollback / release candidate | LOCAL package/install/uninstall and online fixture PASS; final-HEAD CI PENDING | Earlier releases/CI do not validate these code changes |
| Independent exact-HEAD security review | PENDING | Not ready to integrate / publish |

The previous RFC1918-only detached-network-namespace and KVM tests
are historical evidence for a different, now-retired engine. In that
older experiment a multiple-candidate run produced conflicting
router and receipt counts. The anomaly remains INCONCLUSIVE.
Read [LOCAL-LAB-ACCEPTANCE.md](LOCAL-LAB-ACCEPTANCE.md); it must not
be used to claim public Field acceptance.

The Draft SpoofDiag prerelease and the pending separate installer
PR are not a tested public release of this new Field implementation.
