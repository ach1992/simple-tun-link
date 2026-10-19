# Go Field CLI reference — offline-validated, not field-proven

The old `lab` command, loopback two-agent mode and detached private
namespace adapter are **removed** from the current source. The tool's
name, independent offline installer, per-version rollback and operator
directory structure remain.

## Commands

```text
stl-spoofdiag version
stl-spoofdiag preflight
stl-spoofdiag sources add|list|import|remove|replace ...
stl-spoofdiag plan --file PATH
stl-spoofdiag report --file PATH
stl-spoofdiag field identity --dir NEW_PRIVATE_DIR
stl-spoofdiag field challenge --file ALLOWLIST --cert A.crt --key A.key \
  --ca ca.crt --sender A --receiver B --transport field_raw_ipv4 \
  --destination-ip RECEIVER_IP --data-port 24572 \
  --samples-per-source 5 --out challenge.json
stl-spoofdiag field grant --file RECEIVER_ALLOWLIST \
  --challenge challenge.json --cert B.crt --key B.key \
  --ca ca.crt --sender A --receiver B --out grant.json
stl-spoofdiag field listen --file RECEIVER_ALLOWLIST \
  --challenge challenge.json --grant grant.json \
  --cert B.crt --key B.key --ca ca.crt \
  --sender A --receiver B --destination-ip RECEIVER_IP \
  --bind-ip RECEIVER_IP --data-port 24572 \
  --state-dir PRIVATE_0700_LEDGER --out receipt.json
stl-spoofdiag field accept --file RECEIVER_ALLOWLIST \
  --challenge challenge.json --cert B.crt --key B.key --ca ca.crt \
  --grant-out grant.json --ready-out ready.json \
  --out receipt.json --state-dir PRIVATE_0700_LEDGER
stl-spoofdiag field send --ready ready.json --file SENDER_ALLOWLIST \
  --challenge challenge.json --grant grant.json \
  --cert A.crt --key A.key --ca ca.crt \
  --sender A --receiver B --destination-ip RECEIVER_IP \
  --data-port 24572 --interface EGRESS_NIC --provider-authorized \
  --out sender.json
stl-spoofdiag field verify --challenge challenge.json \
  --grant grant.json --receipt receipt.json --ca ca.crt \
  --sender-report sender.json
stl-spoofdiag field check --role sender --challenge challenge.json \
  --grant grant.json --file ALLOWLIST --cert A.crt --key A.key \
  --ca ca.crt --sender A --receiver B --destination-ip RECEIVER_IP
stl-spoofdiag campaign create --file EXACT_IP_INVENTORY --dir NEW_PRIVATE_DIR \
  --direction A_TO_B --destination-ip RECEIVER_IP --transport field_udp_bound
stl-spoofdiag campaign next --dir EXISTING_CAMPAIGN \
  --cert A.crt --key A.key --ca ca.crt
# Receiver B needs a transferred campaign directory AND an independently
# approved allowlist before considering an individual bounded challenge.
stl-spoofdiag campaign receive --dir RECEIVER_COPY_OF_CAMPAIGN \
  --file B-owned-allowlist.json --cert B.crt --key B.key --ca ca.crt
# campaign send requires independently B-signed grant.json AND ready.json
# copied to the current campaign attempt, after B actually binds
stl-spoofdiag campaign send --dir EXISTING_CAMPAIGN \
  --cert A.crt --key A.key --ca ca.crt
stl-spoofdiag campaign report --dir EXISTING_CAMPAIGN --ca ca.crt
stl-spoofdiag menu
```

Menu option 19 provides a guided receiver-side version of `campaign receive`.
The operator must type `LISTEN_ONE` before starting one finite receiver
operation. Campaign files and B's independently owned allowlist remain
separate. This is a UI code path, not evidence of live peer reachability.

These are documentation **examples**, not tests performed or
instructions to send public forged-source traffic without permission.
`--provider-authorized` is an operator acknowledgement and is insufficient
without separately confirmed Owner, peer and provider authority.

For a legitimate locally assigned source-address experiment, create
the challenge with `--transport field_udp_bound` and omit the raw
`--interface` / `--provider-authorized` arguments when sending.

## Candidate JSON and CSV

JSON schema version 1 uses `mode:"field_candidates"` and an array of
`{ip,direction,sender,receiver}` objects. Only exact IPv4 addresses
are accepted. `sender/receiver` must be A/B or B/A and direction must
match. Duplicates are rejected. CSV columns are
`ip,direction,sender,receiver` and imply `field_candidates`.
`sources` management persists private (0600) local JSON inventories;
`plan` is network-free.

The receiver directly binds the signed destination by default. A DNAT or
1:1-forwarded externally advertised destination requires B to sign its
**locally assigned** `--bind-ip` with `--allow-forwarded-destination`,
and to use that exact bind again when listening. No forwarding, host route
or firewall mutation is performed; actual NAT reachability remains untested.
The operator must independently manage each peer's allowlist and
provision CA and node keys on a trusted offline machine. `field identity`
places the CA secret and both node secrets together in a new 0700
provisioning directory for deliberate split distribution; do **not**
copy those extra secrets to individual server hosts.

## Signed Field session internals

- Challenge signed by A (Ed25519), valid 60–900 seconds; default
  600 seconds, 1–32 **distinct source IPs per run** with 1–10 independent
  signed samples per IP (default 5), at most 320 total packets. Each sample
  has an independent index and random nonce, and sample rounds are interleaved
  over the selected IPs. Older omitted sample-count metadata means 1.
- Receiver-signed grant is bound to the challenge SHA256 digest, run ID,
  destination IPv4, UDP port and receiver role. Neither signed artifact
  independently proves IP-prefix rights or provider permission.
- Sender checks its own key matches the challenge and receiver's valid
  grant, and checks its local exact source list.
- Receiver checks the same signed run and its **own** source list,
  verifies A's packet signatures and consumes the run ID in a private
  replay ledger; reception window defaults to an automatic finite value
  derived from the signed sample count at 5 packets/second plus a bounded
  45-second grant-transfer/startup margin, capped at 120 seconds. `--window-seconds` may explicitly
  override it (1–120), but a too-short window or too-near expiry fails
  before the receiver claims the run.
- B may emit an optional B-signed `ready.json` **only after the socket
  binds**. Campaign send requires such a signed, unexpired readiness file
  in addition to a matching independent B grant; local readiness is
  never proof of public reachability or still-running peer process.
- A campaign may advance only when a completed B-signed receipt **and** a
  matching complete A-signed sender report are independently verifiable;
  this does not prove NIC transmission or a return path.
- Sender durably signs per-index `ATTEMPTED_UNKNOWN`, `SUBMITTED` and
  `FAILED` syscall records; a crash retains the last atomic snapshot and
  can never be mistaken for proof of NIC egress.
- Receiver publishes an initial signed `IN_PROGRESS` receipt before
  consuming its Run ID; each independently authenticated packet updates
  that receipt atomically. A crash preserves partial observations, while
  completed finite observation windows are marked `COMPLETE`.
- Receiver signs actual IPv4 socket source, chosen source, per-sample
  comparison, epoch, packet size and role/direction. Zero receipt
  observations are still signed, but are inconclusive.
- Archived verification checks cryptographic consistency at declared
  artifact times, **not** independent wall-clock truth or physical egress.
  The `per_source` result reports planned, authenticated peer-observed,
  exact-source, different-source and planned-but-unobserved counts, plus
  percentages relative to the signed plan and received samples.
  **These percentages are not independently verified packet-loss rates**:
  absent sender-submission evidence prevents that conclusion.

Raw IPv4 on Linux requires `CAP_NET_RAW`, an UP non-loopback explicit NIC
and separate provider permission. The IPv4 packet has a standard IPv4
header, UDP port 24101 source / signed destination UDP port, DF and
TTL 64, bounded payload, and a nonzero IPv4 UDP pseudoheader checksum over the exact signed source
and receiver destination.
The raw sockaddr port is zero as required by the Linux raw(7) API; the destination UDP port is encoded inside the UDP header. No host firewall, route, default interface or sysctl is modified. See https://man7.org/linux/man-pages/man7/raw.7.html for Linux IP_HDRINCL checksum and capability semantics.
`Sendto` success is reported only as `SUBMITTED_ONLY`.

The new Field runtime has offline Go/CI validation but **not** real public
provider or two-host Field acceptance. Automated verification is not proof
of actual packet delivery, NAT behavior, permission to use a source prefix,
source validity at an upstream provider or return paths.

## Independent installation

Refer to [README.md](../README.md) for beginner-ready online and offline
procedures. No Go, Python, package-manager or Internet access is
required on the destination for a verified offline bundle. Build artifacts
remain separate from STL stable version/release namespace.

The live `dev-spoof` `release-channel.txt` is authoritative for the general
installer. RC2 was published and its channel digest pinned on 2026-10-19.
Later unreleased source/PR improvements are not installable from RC2 until
separately reviewed, integrated and published. The old RC1 Draft contains
a different source SHA and cannot validate the current Field candidate.
