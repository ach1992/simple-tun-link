# Field Diagnostics validation and evidence ledger

**Scope:** standalone Field diagnostic source integrated in `dev-spoof` by PR #140,
and published as experimental `spoofdiag-v0.1.0-rc.3`.
**Current Owner decision (2026-10-19):** run normal automated builds, Go tests,
race checks, static analysis, installer checks and CI without artificial
restrictions. Do NOT infer real-world forged-source Field reachability or
provider acceptance; a real public-network Field trial was not requested.

| Gate | Status | What is and is not established |
| --- | --- | --- |
| Source refactor and obsolete lab commands removed | IMPLEMENTED IN SOURCE | Deletion alone is not runtime validation |
| RC3 implementation: guided campaign receiver menu | SOURCE IMPLEMENTED; OFFLINE REGRESSION ADDED | Menu option 19 prompts for receiver-owned allowlist, identity, optional bind and explicit LISTEN_ONE consent. No socket or real A/B test has been run for this UI flow |
| RC3 implementation: campaign partitioning and progress | PURE OFFLINE UNIT PASS | 1,536 exact owned IP fixture split into 48 bounded batches; verified signed completion/resumption, expiry and explicit retry without network traffic |
| RC3 implementation: partial sender/receiver evidence | PURE OFFLINE UNIT PASS | Fault injection preserves signed sender progress and receiver snapshots; no live host socket proof |
| RC3 implementation: receiver DNAT consent and raw checksum | PURE OFFLINE UNIT PASS | Locally signed bind mismatch and checksum tested with fixture data; real forwarding/provider acceptance NOT_TESTED |
| Source inventory / exact directional candidates | LOCAL PASS on source candidate | Both directions and multiple exact addresses exercised offline; provider network not tested |
| Sender-signed plan and receiver-signed grant | LOCAL PASS on source candidate | Offline identity, signed A→B/B→A challenge and receiver grant exercised; no packets emitted |
| Normal UDP bind to an assigned selected IP | IMPLEMENTED IN SOURCE | No host or provider socket test |
| Raw IPv4 header with selected source and explicit peer | IMPLEMENTED IN SOURCE | No CAP_NET_RAW or public-WAN test |
| Receiver signed actual socket-source observations | IMPLEMENTED IN SOURCE | No real peer packet received |
| Signed receipt comparison / replay protection | UNIT TESTED | Signed receipt pairing, overclaim/tamper controls and duplicate run ledger checked; no real peer ingress |
| Repeated per-IP signed samples / stats | OFFLINE UNIT PASS | Independent packet indices, replay rejection, partial/rewritten/missing counters, legacy one-sample plans and maximum-size artifacts checked; no real transport evidence |
| Go formatting / static analysis | APPROVED SOURCE TREE; CI SUCCESS | Independent review approved the original HEAD `01d795a`; squash merge `08dc870` preserved identical Git tree `820af2cb` |
| Automated Go unit and race suites | OFFLINE LOCAL PASS; EXACT REVIEWED HEAD CI SUCCESS | Dedicated SpoofDiag CI [#39279675617](https://github.com/ach1992/simple-tun-link/actions/runs/39279675617) and generic CI [#39279675672](https://github.com/ach1992/simple-tun-link/actions/runs/39279675672) succeeded. This proves neither WAN ingress nor host end-to-end behavior |
| Real-network Field packet capture | NOT_REQUESTED | Previous isolated lab results are unrelated; normal automated tests remain allowed |
| Real two-host A↔B selective-source tests | NOT_RUN by Owner request | No connectivity evidence |
| Provider source prefix consent / acceptance | NOT_VERIFIED | Separate external authorization needed |
| Sender physical NIC egress / NAT rewrite | NOT_TESTED | Independent observer required |
| Sender return path / true private L3 | NOT_TESTED | Out of scope for current diagnostic |
| Debian/Ubuntu ARM64 runtime compatibility | NOT_TESTED for new candidate | Source target only |
| Installer / upgrade / rollback / release candidate | RC3 GITHUB PRE-RELEASE PUBLISHED; ASSET SHA256 VERIFIED | Tag `spoofdiag-v0.1.0-rc.3` resolves to merge commit `08dc870`; seven remote assets redownloaded and verified against source-built artifacts; AMD64 package verify and version output PASS, ARM64 manifest/architecture/checksums PASS but ARM64 host runtime UNTESTED |
| External author-separated review | COMPLETE / APPROVE for dev-spoof integration | Reviewed source HEAD `01d795a` / tree `820af2cb`; F1–F4 including F3-R1 RESOLVED. Reviewer explicitly did not certify real network, SSH durability, provider acceptance or production readiness |

The previous RFC1918-only detached-network-namespace and KVM tests
are historical evidence for a different, now-retired engine. In that
older experiment a multiple-candidate run produced conflicting
router and receipt counts. The anomaly remains INCONCLUSIVE.
Read [LOCAL-LAB-ACCEPTANCE.md](LOCAL-LAB-ACCEPTANCE.md); it must not
be used to claim public Field acceptance.

Release identity and download readiness must be checked against the live
`spoofdiag-v*` tagged pre-release and `dev-spoof` release channel, not
against the historical Draft RC1 or an unrelated STL `v*` release.
Both live two-host Field behavior and provider/return-path acceptance remain
UNTESTED even after offline build and CI pass.


## Offline evidence exchange (RC3 integrated via PR #140)

**Merged and included in experimental RC3.** These results belong to
standalone SpoofDiag's development/release lineage, not STL `main` or
the older RC2 binary. The independent code review was development-scoped.

| Gate | Status | Evidence / limitation |
| --- | --- | --- |
| Four signer-authenticated portable ZIP roles; arbitrary filenames/order | OFFLINE UNIT PASS | Both independent directions, two batches/direction, stable report across reordered/renamed files |
| Run/sample evidence joins | OFFLINE UNIT PASS | Per-index sender syscall vs receiver observation; missing sender proof is not treated as confirmed submit |
| Explicit import; archive/rejected; no inbox deletion | OFFLINE UNIT PASS | Valid and invalid imports, idempotence, symlink rejection; no listener/transmitter called |
| Malicious ZIP, tampered bytes and cross-case conflict | OFFLINE UNIT PASS | Traversal, symlink entries, corrupted archives, wrong-role manifest, conflicting signed snapshots |
| Large exact source inventory | OFFLINE UNIT PASS | 1,536 exact IPs, 48 offline Campaign batches; export/verify; no network traffic |
| Final verified JSON / HTML / CSV | OFFLINE UNIT PASS | Signer and ZIP provenance, missing inputs, safe HTML escaping/CSV cell prefix, idempotent report recreation |
| Pre-run durable joint signed Case and operator activation | NOT_IMPLEMENTED | V2 schema/crypto/slot commitments proposed in OFFLINE-EXCHANGE.md; current v1 runtime still short-TTL |
| Simultaneous live peer readiness | PHYSICALLY UNKNOWN | No zero-channel cryptographic proof of other host currently listening; needs operator timing/clock plan |
| Real A/B Field packets, external NIC capture, return path or tunnel | NOT_RUN | No live network tests requested/authorized in this handoff |
| Full Go tests, vet, race, Linux amd64/arm64 cross-build | LOCAL PASS and EXACT-HEAD CI SUCCESS | Formatting, tests, vet, race and static builds passed on reviewed candidate; nested Go/installer and Bootstrap dedicated CI passed on same SHA |
| Offline installer and channel/legacy layout | LOCAL LOOPBACK FIXTURE PASS | Dedicated bootstrap test verified install-to-temp, wrong digests, rejection paths, old and new docs layouts; not a public download or production install |
| Independent author-separated exact-candidate review | APPROVE (DEV INTEGRATION ONLY) | Approved exact source tree later squash-merged to `dev-spoof`; Owner separately authorized experimental RC3 publication. No real Field or production certification |
