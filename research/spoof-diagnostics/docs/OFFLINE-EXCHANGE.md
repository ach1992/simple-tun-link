# SpoofDiag offline evidence exchange — v1 implementation and v2 readiness design

**Scope:** standalone research tool on the independent `dev-spoof` line. No STL backend, installed service, network scan, autonomous test, tunnel, or public-source spoof trial is authorized. Owner's accepted direction: [#135](https://github.com/ach1992/simple-tun-link/issues/135). Prior signed Field evidence and bounded Campaign Manager: [PR #134](https://github.com/ach1992/simple-tun-link/pull/134). This is a stacked, **unmerged** follow-on feature: the existing RC2 public release does **not** contain it.

## Precisely what exists in this candidate

`exchange` is a **strictly offline, explicitly invoked command family** and menu actions. It consumes existing Campaign and independently signed Field evidence. It does not call `campaign next`, `field send`, `field listen`, `campaign receive`, nor initiate a network operation.

The `sdx-evidence-v1` portable ZIP uses `SDX-MANIFEST.json` with a freshly node-signed Ed25519 manifest:

- 32-lowercase-hex `case_id` shared by the operator for two independent directional Campaigns; the immutable `campaign_id` and hash of `campaign.json`; `direction`, `node`, `role`, and exporter's declared time;
- an ordered exact list of whitelisted relative paths, sizes and SHA-256 digests for `campaign.json`, all immutable `batches/*.json`, signed `challenge.json` and `grant.json` where present, and **only that node's** sender `sender.json` or receiver `receipt.json` where present;
- certificate and cryptographic signature over the manifest. Signing private keys, CA private keys, unrelated configuration, and other private material are never included.

The four logical slots are:

| Direction | Signing node | Bundle role | Suggested portable filename |
| --- | --- | --- | --- |
| `A_TO_B` | A | `sender` | `SDX-<case-id>-AB-A-send.zip` |
| `A_TO_B` | B | `receiver` | `SDX-<case-id>-AB-B-recv.zip` |
| `B_TO_A` | B | `sender` | `SDX-<case-id>-BA-B-send.zip` |
| `B_TO_A` | A | `receiver` | `SDX-<case-id>-BA-A-recv.zip` |

**ZIP names are informational only.** The verifier always uses the signed internal manifest. Multiple signed bounded runs and batches can be contained in one slot. `case_id` is **presently signed only on evidence export**; it is not part of the older PR #134 challenge/grant. Thus v1 has cryptographically authenticated *post-run grouping*, **not cryptographically authorized pre-run cross-direction Case agreement**. Do not treat `exchange new-case` as peer consent.

### Default private operator layout

`/root/stl-spoofdiag/exchange/`, configurable via `--base`, contains `inbox/`, `outbox/`, `reports/`, `archive/` and `rejected/`.

`exchange init` creates/checks private directories (0700). Exports and report files use mode 0600, refuse conflicting overwrite, and perform atomic staging. `exchange import` scans inbox or explicit `--file` paths, validates the signed manifest, trusted local CA, contained checksums, campaign shape and independently present run proofs, then **copies** accepted data by hash to `archive/` or bounded invalid regular data to `rejected/`. User files in `inbox/` are never removed and nothing executes. Repeated identical imports are idempotent. Unsafe symlink/non-regular files are rejected **without following or copying them**. No data transfer daemon is installed.

`exchange analyze` accepts four arbitrary `--file` paths in any order, or scans a private inbox, groups solely by *validated signed identities*, rejects dissimilar signed manifests in the same logical role, and correlates same immutable Campaign ID, exact run ID, sample index, sample candidate source and peer observation. It produces deterministic:
- `SDX-<case-id>-verified.json`: signed input ZIP SHA-256, signer-certificate and manifest fingerprints, chosen public CA file digest, directional/run/sample/source facts, missing/conflicting inputs, explicit limitations;
- `SDX-<case-id>-results.csv`: sortable source counts, with spreadsheet-formula escaping;
- `SDX-<case-id>-final.html`: escaped, no remote resources/scripts.

If an exact same report exists, analysis is idempotent. A different report is *never* silently replaced. A crash after writing one of three reports can be recovered by re-running the same analysis; no previous output is deleted.

### Offline operator demonstration — only with existing authorized evidence

These commands **do not run a test**; a completed Field Campaign from the prior protocol must already be available. This is a post-run evidence exchange walkthrough, not authorization to transmit diagnostic packets.

1. On A and B separately, or on a third Linux analyzer:
   `stl-spoofdiag exchange init` (add `--base /absolute/private/path` for a nonroot machine).
2. Generate a label on one operator machine: `stl-spoofdiag exchange new-case`. Securely convey the printed Case ID to the other machine. No live A↔B channel is needed.
3. Retain both directionally distinct *existing* Campaign directories; each exporter must possess the identical immutable Campaign metadata for its direction and that endpoint's own independently signed evidence. Existing campaign directories are **not** automatically synchronized by this v1 CLI.
4. On A, export two slots (different campaign dirs and roles):
   `stl-spoofdiag exchange export --case-id CASE --campaign-dir /private/AB-campaign --role sender --cert /private/A.crt --key /private/A.key --ca /private/ca.crt`
   `stl-spoofdiag exchange export --case-id CASE --campaign-dir /private/BA-campaign --role receiver --cert /private/A.crt --key /private/A.key --ca /private/ca.crt`
5. On B, export its two slots:
   `stl-spoofdiag exchange export --case-id CASE --campaign-dir /private/AB-campaign --role receiver --cert /private/B.crt --key /private/B.key --ca /private/ca.crt`
   `stl-spoofdiag exchange export --case-id CASE --campaign-dir /private/BA-campaign --role sender --cert /private/B.crt --key /private/B.key --ca /private/ca.crt`
6. The operator manually copies each new ZIP from its `outbox/` to the analyzer's `inbox/`. Names can change. Transfer **only the public CA trust anchor** to the analyzer, never node or CA private keys.
7. Explicitly verify/quarantine copied files using `stl-spoofdiag exchange import --case-id CASE --ca /private/ca.crt`. Then run `stl-spoofdiag exchange analyze --case-id CASE --ca /private/ca.crt`. Use `--inbox /private/path` or repeated `--file /path/to/anything` and `--reports /private/report-dir` when desired; for non-default private root add `--base`.
8. Inspect `reports/`. `INCOMPLETE` means the evidence cannot support a complete four-slot signed comparison. `COMPLETE_SIGNED_EVIDENCE_NOT_CONNECTIVITY_PROOF` **only means all expected signed declarations were consistently present**.

### Trust, archive and completeness limitations

- Independently provision trust roots on a trusted operator machine. The analyzer **never trusts a CA inside the ZIP**. Local signer certificates are verified for the claimed node role against the separately supplied public trust anchor; certificate validity is checked at signer's declared export time (not trusted wall-clock timestamp authority; no OCSP/CRL online check). The JSON report contains the public trust file's SHA-256 so it can be reproduced.
- Existing signed Challenge/Grant/Receipt and Sender evidence are revalidated using the established Field signatures and immutable Campaign batch digests; absent or partial runs are not fabricated. No private signing keys in bundles or reports.
- Archive inputs are untrusted: reject traversal, malformed JSON, symlinks, nonregular entries, duplicate ZIP names, unknown relative paths, entry size/hash differences and unsupported `format`. Extraction to operator-selected filesystem paths is forbidden; safe staging uses only whitelisted JSON names in a private randomly created temporary directory. No included code is executed.
- Current resource policy: maximum 50,000 ZIP entries, 1 GiB total uncompressed bytes, 8 MiB campaign manifest and manifest metadata, current Field per-run JSON maximum 256 KiB. These are deliberate **memory/disk security budgets**, **not limits of 256 source candidates**: Campaign batching was tested with 1,536 exact sources. Very large archives should use a future segmented/streamed format with configurable policy rather than removing safety checks.
- A signed `SUBMITTED` sender syscall record is **not** a physical NIC egress capture. Signed authenticated B observation is **not** independent provider authorization. Missing B observations are *inconclusive*, not proven packet loss/blocked IP. A→B and B→A may involve unrelated source identities and **two one-way observations are not a verified same-flow return path**. A useful encrypted private L3 link is not tested.
- Existing PR #134's fresh 60–900 second Challenge and 120-second maximum listener readiness still expire during slow human file exchange. This evidence-only v1 change **does not change the active Field protocol or fix that activation defect**. This is the controlling next architecture gate.

## Next protocol design: durable preparation vs bounded activation

The existing protocol is v1. **v2 below is an explicit design proposal, not yet enabled, frozen, implemented, or field-tested.** Maintain backward reader support for v1 signed records, and use a separate `sdx-case-v2` / `sdx-preparation-v2` schema rather than reinterpret v1's `ExpiresUnix`.

1. **PREPARE:** create immutable shared Case definition (random 128-bit Case ID, A/B signing identities and trust roots, two independent direction Campaign IDs/hashes and exact source inventory hashes, destinations/ports/transports, bounded sample/attempt limits, optional finite prearranged run slots and global authorization expiry). Bind the entire definition to versioned canonical bytes. A and B independently sign the **same hash** on their separate machines. This phase never starts a short Challenge or opens a socket. A transferable preparation bundle contains only public scopes/signatures.
2. **IMPORT_AND_VALIDATE:** each endpoint independently checks peer signature, own source allowlist and consent, policy/authorization scope, certificate identity, local capability and compatible version. Importing this artifact is passive: no listener, send or implicit `START`. Untrusted CA material cannot be self-authorized. Peer signed `PREPARED` proves a past declaration, **not current live readiness**.
3. **LOCAL_READY:** explicit, read-only local preflight records what is true *now* (ownership/bind/source inventory, interface availability, clock uncertainty, already consumed slot/run ID, permissions). Keep local and last *reported* peer readiness separate, including its timestamp. Fail closed with a specific missing condition.
4. **ARM/START:** with no active channel, the operator must arrange a shared activation time or separately trigger both ends through an authorized outside management path. Prepare bounded, independently signed **one-time slot commitments** and both endpoint nonces **before manual transfer**; use their cryptographic digests to bind future activation to exactly one prior authorized batch/role/endpoint. The receiver foreground operation locally arms and listens in a fixed allowed slot only on explicit consent. The sender explicitly starts the same slot only after local preflight; neither side needs a **new** interactive peer signature after the clock starts. Enforce pre-authorized earliest/latest slot UTC boundaries, bounded listening/send times, clock-skew policy, immutable candidate set, quota and one-use durable replay ledger. Critical: the legacy `field grant` tied to the newly created Challenge **cannot be reused as this v2 conditional grant**. Define, review and test this new signature contract **before** wiring it to Field transport.
5. **COMPLETE/PARTIAL/EXPIRED:** consume a slot before irreversible local operation so an interrupted process cannot silently replay it. Preserve signed partial evidence. Retry requires an independently authorized *different* slot/run identity with a new bounded local consent; no automatic retry. Fail closed if time uncertainty exceeds preapproved skew, signed permission expired, role or slot differs, local checks fail, or user has not manually started.

**Physical limit:** no communication path means neither peer can verify that the other is presently listening. A scheduled slot and separate operator starts do not create a handshake. The report must state `PEER_CURRENTLY_LISTENING_UNKNOWN` and distinguish absence of evidence from failed delivery. If the operator cannot coordinate clocks or trigger both ends, operation is **NOT_READY**, not indefinitely rearmed. Clock skew, stale transfers, delayed signed receipts, crash recovery and isolated no-network simulations require dedicated v2 tests.

## Next implementation/acceptance gate

Keep v1 portable evidence exchange backward-compatible and separate. Before enabling v2 traffic, define and independently review exact canonical Case/Preparation/Slot schemas, role-authenticated signatures, epoch/clock policy, replay ledger, cancellation/terminal states, interop/migration, and user-visible start/consent UX; verify deterministic offline negative/positive fixtures. Do not claim a live peer or successful public spoof trials from those fixtures. [#135](https://github.com/ach1992/simple-tun-link/issues/135) owns this unfinished activation design. Do not merge, release, or install this candidate absent Owner approval and required review.
