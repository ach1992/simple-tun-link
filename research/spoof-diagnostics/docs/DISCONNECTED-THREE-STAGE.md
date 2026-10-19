# Spoof Diagnostics — disconnected three-stage workflow (development only)

Status: **unmerged feature candidate** targeting `dev-spoof`. This does not
install or modify STL, does not enable public-network forged-source trials,
and is **not** proof of link or tunnel readiness. Requirements and acceptance:
[Issue #139](https://github.com/ach1992/simple-tun-link/issues/139).
Historical strict Field and Campaign workflows remain separate/compatible.

## Invariant: A and B have no control connection

There is no A-to-B SSH/API, grant request, synchronization, download or
live state query. The **only** ordinary cross-host action is manual,
operator-controlled file transfer when the stage calls for it. Diagnostic
UDP may or may not arrive; it cannot serve as a dependable control plane.

### Stage 1 — A sends; B independently receives

- B only supplies its own locally assigned bind IPv4, UDP port, finite
  receive duration, packet-record ceiling, its own B signing certificate
  and key, public CA, and private output path. **No A source list, Challenge,
  Grant or Ready file is required on B.** The resulting signed receiver
  artifact is `OBSERVED_UNVERIFIED` until paired with the sender's signed
  evidence. A third party can flood B's passive capture with SDF2-looking
  frames, but they are never marked authenticated merely by capturing them.
- A independently prepares its own finite, signed sender plan and evidence.
  **IMPORTANT current implementation gap:** the strict
  `field send` / `campaign send` commands still require a prior signed
  B Grant. Removing that requirement in an arbitrary raw IPv4 source sender
  would be a security change, and is **not implemented or approved** in
  this candidate. Do not mistake the new passive receiver for a fully
  field-operational no-control-path raw sender. Existing independently
  authorized/local-interface UDP and raw sender behavior is unchanged.
- Operators must separately arrange time windows; there is no guarantee
  either host was listening when its peer tried to send. Missing packets
  remain inconclusive.

The following example *only starts B's finite passive receiver*. It sends
nothing, creates no persistent network daemon, and requires an available
Linux systemd manager (root system instance, or user instance with explicit
administrator-approved linger):

```sh
stl-spoofdiag job start -- field observe --receiver B \
  --bind-ip 10.40.0.8 --data-port 24572 \
  --window-seconds 120 --max-packets 1024 \
  --cert B.crt --key B.key --ca ca.crt \
  --out /private/B-ab-observation.json

stl-spoofdiag job status --unit sdx-EXACT_ID_FROM_OUTPUT.service
stl-spoofdiag job logs --unit sdx-EXACT_ID_FROM_OUTPUT.service
stl-spoofdiag job stop --unit sdx-EXACT_ID_FROM_OUTPUT.service
```

Use exact paths and the exact generated unit ID. After SSH closes, an
already accepted transient `systemd` **system** job continues; unprivileged
user managers must have linger enabled or the tool rejects the launch.
Starting a unit only proves the job was requested, **not that the UDP
socket bound or that A is reachable**. `job status` and signed files show
what actually happened. A failed/interrupted run is never automatically
retried on boot, time expiration or service restart. The receiver is
limited to 1–14,400 seconds and 1–2,048 diagnostic frames per invocation.
Once recorded, every new eligible observation is included in an atomic
Ed25519-signed snapshot; an abrupt SIGKILL or power loss preserves the
most recently published snapshot, but can lose in-flight data.

## Stage 2 — operator moves A data to B, then B→A independently

The operator manually transfers A's signed Stage-1 `challenge.json`
and (when available) signed `sender.json` to a B analysis directory.
**Never transfer the sender's or CA's private keys.**

B can compare its own passive observations with the A-signed plan *offline*
using a public trust anchor, without trusting filenames or any live A status:

```sh
stl-spoofdiag field correlate \
  --challenge /private/A-challenge.json \
  --capture /private/B-ab-observation.json \
  --sender-report /private/A-sender.json \
  --ca /private/ca.crt
```

To prioritize B's **separate, locally authorized B_TO_A inventory**
before creating reverse batches, use:

```sh
stl-spoofdiag campaign prioritize \
  --file /private/B-ip.txt \
  --hint-challenge /private/A-challenge.json \
  --hint-capture /private/B-ab-observation.json \
  --hint-sender /private/A-sender.json \
  --ca /private/ca.crt \
  --out /private/B-prioritized.json
```

This produces a new `field_candidates` JSON and an adjacent
`B-prioritized.ranking.json` audit. Candidate identity, scope and
original source file are not modified. **Only exact matching IPs in B's own
approved list** can be reordered, using authenticated A→B observations.
If there is no exact overlap or no verified hint, original order is
preserved. This is exploratory decision support, **not a numerically
justified reverse success probability**, and cannot grant B permission to
send from A's chosen addresses. To use the suggested order, supply the
new inventory to the normal `campaign create --file` command; its
existing finite Batch division and original source hash remain auditable.

For B→A, B becomes sender with a new independently authorized source
set and Run ID while A passively listens with its own local options;
neither requires a live B-to-A control channel. Stop after an authorized
Batch, manually exchange available A receiver evidence, run a
**provisional per-Batch** correlation, and decide whether to authorize the
next Batch. Existing Campaign operations start only one bounded Batch
at a time; the new job manager does not create a continuous sender
loop or replay potentially consumed runs. Untested IPs must remain
`NOT_TESTED`, not failed or successfully connected.

## Stage 3 — collect both hosts' data, final signed-evidence report

After **both** directional trials, manually consolidate:
A→B A-signed plan + sender evidence + B-signed passive capture;
B→A B-signed plan + sender evidence + A-signed passive capture.

For the present **one-Run-per-direction** report mode:

```sh
stl-spoofdiag exchange analyze-passive \
  --case-id 0123456789abcdef0123456789abcdef \
  --ca /private/ca.crt --reports /private/exchange/reports \
  --ab-plan /private/AB-challenge.json \
  --ab-sender /private/AB-sender.json \
  --ab-capture /private/AB-B-capture.json \
  --ba-plan /private/BA-challenge.json \
  --ba-sender /private/BA-sender.json \
  --ba-capture /private/BA-A-capture.json
```

Outputs are `SDX-<case-id>-verified.json`,
`SDX-<case-id>-results.csv`, and `SDX-<case-id>-final.html` in the
pre-existing private 0700 reports directory. Inputs are cryptographically
verified against supplied public CA; repeats are idempotent and conflicting
pre-existing outputs are never overwritten. The Case ID is an
**operator-assigned post-run label**, not proof that A and B negotiated.

`analyze-passive` above remains available for one Run per direction.
Multi-Batch disconnected analysis is provided separately below. The
strict sender Grant/Ready requirement and actual field/systemd validation
remain open; offline analyzer tests do not prove two-host connectivity.


## Operator-controlled Batch checkpoints (no network effects)

The local control commands `campaign status|pause|resume|stop` preserve a
bounded Campaign's operating state. Pause stops **future** `campaign next`
and `campaign send` operations at a Batch boundary, without modifying any
already signed plan, recording synthetic transmissions or starting a network
service. Resume is possible from PAUSED, but STOPPED_BY_OPERATOR is terminal.
To stop a job *currently executing* a Batch, invoke the separate
`job stop --unit ...`, then examine signed partial evidence.

```sh
stl-spoofdiag campaign status --dir /private/campaign
stl-spoofdiag campaign pause --dir /private/campaign --reason "Review first batch"
stl-spoofdiag campaign resume --dir /private/campaign
stl-spoofdiag campaign stop --dir /private/campaign --reason "Operator stopped early"
```

An early stop does **not** establish an accepted network path. Remaining
source IPs are reported as NOT_TESTED. Pausing does not authorize sending,
bypass the existing strict Grant or Ready checks, or replay a consumed Run.

## Stage 2 checkpoint analysis — multiple Runs and captures

The operator manually collects the signed receiver `*.json` artifacts into
an **existing 0700 private directory**. The corresponding sender Campaign
directory contains its immutable Batch inventory and the available signed
Run plans and local sender evidence. The receiver files can contain samples
from several Runs, and multiple receiver windows are supported. The analysis
tool does not initiate traffic or automatically move files between servers.

```sh
stl-spoofdiag exchange preview-campaign \
  --campaign-dir /private/copied-sender-campaign \
  --captures-dir /private/received-observation-json \
  --ca /private/ca.crt
```

Output is expressly PROVISIONAL: it distinguishes locally reported send
syscalls, valid signed receiver observations, duplicates, conflicts, missing
sender evidence, unattempted candidates, and the per-Batch progress state.
The signed Run/sample identity is authenticated after manual evidence
transfer; filenames and untrusted packet metadata are never proof.

## Stage 3 final report — all available Batches in both directions

After **both** independent trials, manually copy A→B Campaign + B captures
and B→A Campaign + A captures to A, B or a third offline analyzer. Then:

```sh
stl-spoofdiag exchange analyze-campaign-passive \
  --case-id 0123456789abcdef0123456789abcdef \
  --ca /private/ca.crt --reports /private/exchange/reports \
  --ab-campaign /private/A-to-B-campaign \
  --ab-captures /private/B-receiver-observations \
  --ba-campaign /private/B-to-A-campaign \
  --ba-captures /private/A-receiver-observations
```

The pre-existing report directory must be an absolute, private `0700`
directory. It produces immutable `SDX-<case-id>-verified.json`,
`SDX-<case-id>-results.csv`, and `SDX-<case-id>-final.html` artifacts.
The outputs include all available signed Runs and Batch coverage as well
as their evidence hashes. Files from a different direction or untrusted
signer are rejected. Exact duplicate captures are not counted twice;
monotonic earlier/later snapshots of one signed capture use the latest
consistent observation set. Conflicting snapshots under one Capture ID
are rejected. Contradictory actual-source claims for the same sample in
different valid windows are reported as AMBIGUOUS, never an extra success.

Per-direction capture input is limited to 128 signed JSON files; at most
2,048 signed attempts are analyzed in one Campaign. The implementation
indexes *untrusted* Run IDs in already validated capture files solely to
avoid scanning unrelated observations. Sample authenticity must still
pass sender signature checks. Input SHA-256 hashes and operator Campaign
IDs are recorded; the Campaign manifest and Case ID are local/operator
scope, not cryptographic proof that A and B negotiated anything.

Re-running identical analysis is idempotent. If newer evidence changes the
report contents, choose another Case ID or separate report directory rather
than silently replacing historical results. All missing observations are
INCONCLUSIVE. No same-flow return path, provider acceptance or viable
tunnel is inferred from two independent one-way results.

**Remaining implementation gates:** Default Raw IPv4 sending is still
Grant/Ready-bound. The requested one-time Campaign authorization for
independent Raw IPv4 transmission remains an unresolved security design
decision and is not enabled by these offline tools. Actual SSH-logout
durability, private-VM network behavior and independent review remain
deferred or pending.

## Evidence meaning and operational safety

- `SUBMITTED`: signed local sender syscall report, not physical NIC egress.
- `OBSERVED_UNVERIFIED`: receiver-signed local socket observations without
  A's signed plan; neither attributable nor authenticated until correlation.
- `AUTHENTICATED_PEER_OBSERVATION`: signed sender sample validated against
  B's captured datagram and the source address B claims it observed.
- No observation: `INCONCLUSIVE`, not proven filtering or packet loss.
- Even when *both* A→B and B→A show valid independent observations, no
  same-flow return to the actual originating endpoint, public provider
  source-prefix permission, or viable STL tunnel has been proved.
- Existing raw source spoof sender requires separately established actual
  Owner/peer/provider permission. This candidate does not allow bypassing
  any authorization gate or initiate any real forged-source field test.
- Real non-loopback listener, systemd disconnect-survival, controlled
  multi-VM acceptance, final PR CI and independent author-separated
  review are distinct gates. Green Go unit tests alone do not satisfy them.
