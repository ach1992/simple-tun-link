# Field Diagnostics validation and evidence ledger

**Scope:** new Field selected-source implementation on a feature branch.
**Owner instruction:** do **not** run tests now; implement theoretical
behavior and preserve truthful evidence boundaries.

| Gate | Status | What is and is not established |
| --- | --- | --- |
| Source refactor and obsolete lab commands removed | IMPLEMENTED IN SOURCE | Deletion alone is not runtime validation |
| Source inventory / exact directional candidates | IMPLEMENTED IN SOURCE | No CLI scenario executed |
| Sender-signed plan and receiver-signed grant | IMPLEMENTED IN SOURCE | Signatures not tested end-to-end |
| Normal UDP bind to an assigned selected IP | IMPLEMENTED IN SOURCE | No host or provider socket test |
| Raw IPv4 header with selected source and explicit peer | IMPLEMENTED IN SOURCE | No CAP_NET_RAW or public-WAN test |
| Receiver signed actual socket-source observations | IMPLEMENTED IN SOURCE | No real peer packet received |
| Signed receipt comparison / replay protection | IMPLEMENTED IN SOURCE | No execution of replay/negative cases |
| Go formatting and compile-only check | COMPILE-ONLY | Not a test of correctness or behavior |
| Automated Go unit and integration suite | NOT_RUN by Owner request | No pass/fail claim |
| Linux namespaces / local packet capture | NOT_RUN by Owner request | Previous lab results are unrelated |
| Real two-host A↔B selective-source tests | NOT_RUN by Owner request | No connectivity evidence |
| Provider source prefix consent / acceptance | NOT_VERIFIED | Separate external authorization needed |
| Sender physical NIC egress / NAT rewrite | NOT_TESTED | Independent observer required |
| Sender return path / true private L3 | NOT_TESTED | Out of scope for current diagnostic |
| Debian/Ubuntu ARM64 runtime compatibility | NOT_TESTED for new candidate | Source target only |
| Installer / upgrade / rollback / release candidate | NOT_RUN for new candidate | Earlier releases/CI do not validate these code changes |
| Independent exact-HEAD security review | PENDING | Not ready to integrate / publish |

The previous RFC1918-only detached-network-namespace and KVM tests
are historical evidence for a different, now-retired engine. In that
older experiment a multiple-candidate run produced conflicting
router and receipt counts. The anomaly remains INCONCLUSIVE.
Read [LOCAL-LAB-ACCEPTANCE.md](LOCAL-LAB-ACCEPTANCE.md); it must not
be used to claim public Field acceptance.

The Draft SpoofDiag prerelease and the pending separate installer
PR are not a tested public release of this new Field implementation.
