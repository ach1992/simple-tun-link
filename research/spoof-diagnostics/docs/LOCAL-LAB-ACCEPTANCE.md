# Fully isolated local acceptance plan — Go diagnostic instrument

Status: **full raw/VM acceptance plan, NOT completed**. A partial Go implementation now performs real mutually authenticated **127.0.0.1** two-agent control/UDP exchange, verifies signed peer receipts and supports out-of-band Ed25519-signed challenges and UDP observations. Local source-IP admission, netns/raw packet egress, asymmetric routing and actual encrypted L3 remain **NOT_RUN**. Prior Python/inline labs are not Go acceptance evidence.

## Environment

Prefer three disposable Linux guests: **A** test sender, **R** simulated provider/router, **B** owned test receiver. A two-guest setup plus a dedicated private router network namespace is an acceptable equivalent *when* independent interfaces/policies/captures remain inspectable. Add observer **C** only to distinguish a reply to a separate owned address from a genuine return to sender A.

- Linux AMD64 and Linux ARM64 compile checks; test actual execution on available representative Linux kernel families (5.15 and 6.x where available).
- Only RFC1918 links; no Internet-facing NIC inside trial network, **no route to public Internet**, no NAT to host default route, no public candidate pool, no bridge to management network. Recorded network namespace/VM identities must show this containment.
- Only dedicated test-owned capture, router rules, raw socket privileges and short-lived listeners; never host-level global firewall, sysctl, conntrack, native routes, existing STL Links or production services.
- Record exact code SHA, binary build identity, guest OS/kernel, interface addresses, local time window, test Case ID, packet sizes, expected and observed counters from BOTH endpoints. Exit and teardown evidence, not a simulated all-green summary.

## Suites and acceptance

| Family | Controlled variation | Required observation / negative control |
| --- | --- | --- |
| Build/package | offline Go module cache disabled; AMD64+ARM64 bundle | static binaries, manifest+archive SHA match, no package downloads at install |
| Install | fresh disposable disk, manually supplied archive | binary installed outside /root inbox; `version` matches exact package; STL unmodified |
| Install integrity | wrong checksum, wrong arch, altered manifest, foreign symlink/launcher, failure injection | fail closed, preserve foreign path and old version/state, report actionable error |
| Menu/CLI | interactive and JSON/CSV paths, manual source entry, invalid/duplicate/reserved addresses | same engine verdict; no network on `plan`/`report`; clear errors |
| Two-agent identity | true independent processes with mutual peer auth and wrong CA/cert/EKU cases | only identified peer accepted; replay/tampering rejected |
| Real raw private packets | A raw packet uses an unassigned RFC1918 source; R routes; B observes separately | **A actual kernel egress capture** and B independent peer capture, not only `sendto` success |
| Source ACL | one candidate accepted; other source denied at R | selected set consistent with independent captures |
| Asymmetry | A→B allowed for source X; B→A allowed for Y; alternative recipient C for return | distinct directional candidate sets; C return does **not** qualify A's return |
| Return ACL/rp_filter | inbound permitted, reverse dropped; strict rp_filter | `PEER_OBSERVED` can coexist with `RETURN_NOT_OBSERVED`; no false bidirectional readiness |
| Packet size/MTU | small accepted, large dropped/fragmented | eligibility scoped to measured size; no global source PASS |
| Policy drift | candidate previously admitted becomes blocked | exact epoch binding; stale evidence not reused; fail closed if all disallowed |
| Failure/recovery | control unavailable, interrupted receiver, timeout, malformed report, invalid signature, replay | `INCONCLUSIVE`/`NOT_RUN` distinguished from packet-filter FAIL; cleanup on interruption |
| Upgrade/rollback | identical install, exact newer version, earlier verified artifact, failed partial update | no ambiguous binary/current-link identity; private config preserved |
| Uninstall | tool-owned files only, keep/explicitly delete private data | no STL or unrelated processes/files affected; ownership verified |
| Public field gate | public plan without actual provider/source-prefix/tool approvals | no public packets, no arbitrary scan, actionable `BLOCKED_BY_PERMISSION` |

## Result schema and evidence provenance

Each packet sample is keyed by `run_id`, `sample_id`, direction, origin, peer, source candidate, destination, packet size and policy epoch. At least separate:

- `sender_submitted` (local API attempt).
- `sender_egress_observed` (separate actual packet capture).
- `peer_ingress_observed` and `peer_authenticated`.
- `return_observer_id`, `return_authenticated`, `actual_sender_return`.
- `private_L3` (only an actual authenticated, encrypted, bidirectional L3 acceptance may set PASS).

Signatures, session identity, wall-time window, independent capture identity and missingness need explicit verification in the final Go tool. A user-supplied JSON boolean alone has `UNVERIFIED_INPUT_DECLARATION` status and cannot become cryptographic proof.

Do not conflate an echo/UDP proof with WireGuard or STL Link availability. In a future authorized field trial, do not infer permission from endpoint control; only explicit source-address/network/provider/platform rights allow any genuine public source-forgery attempt.

## Acceptance gates / reporting

A candidate may be called **LAB_VERIFIED** only after exact proposed Go sender/receiver binary does real private-kernel packet E2E, directional return cases, negative tamper/auth tests, clean teardown, and offline install/recovery E2E. A CI green for Go unit tests + offline installation smoke is **PARTIAL**, not a replacement for those kernel/network/guest tests.

Publish no release, integrate no STL backend, and change no physical test host until separate Owner approval and project/platform gates. Evidence belongs in [Issue #125](https://github.com/ach1992/simple-tun-link/issues/125); parent architecture choice remains [#123](https://github.com/ach1992/simple-tun-link/issues/123).
