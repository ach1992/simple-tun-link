# Spoof Diagnostics — standalone Go tool

**A separate Linux diagnostic inside the Simple Tun Link GitHub repository.**
Spoof Diagnostics has its own executable, interactive menu, installation
scripts, documentation, saved configuration and release series. **It is not
STL:** installing it does not install, upgrade, configure or run STL.

- **Product source and documentation:** `research/spoof-diagnostics/`
- **Permanent development branch:** [`dev-spoof`](https://github.com/ach1992/simple-tun-link/tree/dev-spoof)
- **Standalone pre-releases/downloads:** [GitHub Releases](https://github.com/ach1992/simple-tun-link/releases), **only tags beginning with `spoofdiag-v`**. Ignore STL's unprefixed `v*` releases
- **STL's separate branch:** `main`; Spoof Diagnostics changes and PRs target `dev-spoof` and must not be merged into `main` without a new Owner decision

## What the tool does

The current development candidate replaces the former Private Lab runtime
with a **Field** workflow for two explicitly controlled hosts, A and B.
It accepts an **exact, operator-chosen IPv4 candidate list** independently
for A→B and B→A; it does not enumerate CIDR ranges, scan the Internet,
automatically start a service or integrate with STL. A separate unmerged
candidate introduces **explicitly operator-started finite systemd jobs**;
no service is enabled at installation.

Field stages: *sender-signed challenge → receiver-signed grant → bounded
field sender and receiver → receiver-signed receipt → offline verification*.
Every receiver observation records both the claimed source address inside
the signed packet and the **actual socket source address**. A match shows
what that receiver observed, **not** independent provider authorization,
sender NIC egress, a return path, or a usable private L3 link.

Two transport choices are available in the implementation:

- `field_udp_bound`: standard IPv4 UDP; only source IPv4s actually assigned
  to an active local network interface can be chosen. No spoofing.
- `field_raw_ipv4`: Linux CAP_NET_RAW, an explicitly selected UP nonloopback
  interface, and a finite set of individually signed UDP diagnostic samples
  per approved candidate (default five, configurable one to ten). The packet
  source is the exact signed, user-selected IPv4; the signed destination is
  a single cooperating receiver. It is rate- and count-bounded, and requires
  separately verified owner **and provider** permission before any public
  forged-source trial. The command-line acknowledgement is not proof of
  that permission.

**Validation status:** signed-artifact invariants, repeated samples,
installation, packaging and CI have automated coverage. Check the exact
published tag/commit and its GitHub Actions result for release-specific proof.
**No real two-host Field reachability, public forged-source transmission,
provider acceptance, receiver-network test or private-L3 acceptance was
performed for this candidate.** A received packet does not establish
permission to use its Source IP or prove any return path.

The tool source and packaged documentation live under
`research/spoof-diagnostics/` on the independent `dev-spoof` line; only its
dedicated Spoof Diagnostics CI workflow also lives at repository level.
The unrelated STL application, installer, `main` branch and `v*` release
channel are outside this tool's release and integration scope.

## Disconnected A/B three-stage testing (new unmerged follow-on)

The Owner-approved target workflow is **A sends while B independently observes;
the operator later copies A's saved artifacts to B; B independently performs the
reverse test with its own candidate list; only after both tests does an offline
analyzer prepare the final findings**. Neither host can see the other's live
status, and B must not require A's source inventory or Challenge to start
receiving. **This workflow is not yet end-to-end field-ready.**

The new experimental `field observe` command permits a bounded local receiver
capture with no pre-transferred A artifacts. `field correlate` authenticates
these previously **unverified** observations after manual transfer. Finite
`job start|status|logs|stop` operations use transient `systemd` units to
survive SSH logout when the host's systemd/linger prerequisites are satisfied.
An offline `campaign prioritize` action can reorder **only B's existing
authorized B_TO_A source list**, based on verifiable exact-IP overlap with
A_TO_B observation evidence. There is no probabilistic guarantee.

`exchange analyze-passive` still supports **one signed Run per direction**.
For multiple Batches and multiple signed passive receiver windows, use the
**offline-only** `exchange preview-campaign` and
`exchange analyze-campaign-passive` commands. They preserve incomplete
source coverage, deduplicate imported capture snapshots, report signed
observation discrepancies and export JSON/CSV/HTML. Local
`campaign status|pause|resume|stop` operations allow bounded Campaign
checkpoints and terminal stop without triggering traffic. The legacy raw
sender **still requires a signed receiver Grant**, and no unpaired raw-source
transmission or unattended spoofed-source Campaign execution was enabled. Read the
[disconnected three-stage development guide](docs/DISCONNECTED-THREE-STAGE.md)
and [Issue #139](https://github.com/ach1992/simple-tun-link/issues/139)
for exact commands, provenance and outstanding end-to-end gates.

## Offline A/B evidence exchange (unmerged follow-on candidate)

A separate development branch adds **offline-only** `exchange` commands and
menu items 20–25 for the signed Case-evidence exchange; option 26 only
prepares the IP inventory. The exchange exports each endpoint's *existing*
independently signed Campaign/Field evidence to portable four-slot ZIPs; import validates
ZIP signatures and hashes, and an independent analyzer produces JSON, CSV and
HTML reports on A, B or a third Linux machine. File names/order need no manual
normalization. Files can be copied manually through an operator-managed path;
no direct A↔B communication or network daemon is needed **for analysis**.

The default private exchange root is `/root/stl-spoofdiag/exchange/` with
`inbox/`, `outbox/`, `reports/`, `archive/`, `rejected/` and `sources/`, or another
explicit `--base`. `exchange import` is inert: it never executes test traffic
or deletes the inbox source. All ZIPs require externally supplied public CA
trust and each node's signed internal manifest. **Neither private node nor
CA signing keys are exported.** Analysis refuses to call missing packets
blocked sources, and does not claim physical egress, provider permission,
return traffic or private-L3 connectivity.

A separate **unmerged** source-input addition accepts one `ip.txt` with a
`# SDX-IP-LIST v1 direction=A_TO_B` header and one IPv4 per line.
`exchange sources inspect|stage` (menu 26) reuses the existing Campaign
candidate JSON, with no per-IP setup screens and no packet send. The 900-second
limit is per bounded run, not an overall Campaign deadline; see the
[operator TXT instructions](docs/OFFLINE-EXCHANGE.md#simple-source-ip-input-additional-unmerged-offline-candidate).

**Current gate:** this feature is under review/development and **is not in
published RC2**. Existing short Challenge/Readiness TTLs and the manual
pre-run transfer problem **are not yet fixed** by post-run bundle export.
Case ID currently binds the evidence on export, not a new pre-run consent
protocol. A separate bounded v2 preparation/activation design is documented
but has not been wired to sender/receiver traffic. Read the
[full offline exchange reference](docs/OFFLINE-EXCHANGE.md) before relying
on this workflow; no deployment, field packet trial, merge or release is
implied.

**Transport roadmap (not active):** TCP, ICMP and QUIC diagnostics are deferred under [Issue #137](https://github.com/ach1992/simple-tun-link/issues/137), along with any justified additional protocols. The current Field diagnostic remains UDP-only; see [architecture and limitations](docs/ARCHITECTURE.md#future-diagnostic-transport-coverage-owner-parked-not-implemented). No menu option or sender for those future probes exists yet.

## Install online — one general command (no version number)

For the independently published Spoof Diagnostics channel, run this
version-independent command on a Debian/Ubuntu server:

```sh
bash -o pipefail -c 'curl -fsSL --proto "=https" https://raw.githubusercontent.com/ach1992/simple-tun-link/dev-spoof/research/spoof-diagnostics/scripts/install-latest.sh | sudo bash -s -- --accept'
```

**The command never needs a tag or SHA256 copied into it.** The small channel
file at `release-channel.txt` selects only the latest *approved and
published Spoof Diagnostics version*. The installer obtains the versioned
bootstrap and both artifact checksums from this separate channel, verifies
the downloaded bootstrap and the correct AMD64/ARM64 archive, and invokes
the same verified offline installer. It does **not** follow GitHub's
`releases/latest` (that belongs to STL) or download Go, Python or STL.

**Publication status:** the standalone RC2 prerelease channel is published
as of 2026-10-19. Check the [live standalone release channel](https://github.com/ach1992/simple-tun-link/blob/dev-spoof/research/spoof-diagnostics/release-channel.txt)
before installing: new Campaign/Field improvements in a development PR are
**not** included in RC2 until separately reviewed, integrated and released.
If the channel is unpublished, the installer deliberately refuses the download.
The older RC1 Draft belongs to a superseded implementation.
Never substitute an STL `v*` release or an arbitrary development artifact.

The command downloads executable script code over HTTPS from the
publisher-controlled `dev-spoof` branch: **only run it if you trust that
branch and its maintainers**. GitHub HTTPS plus a checksum supplied by
the same publisher are *not* independent publisher-signature verification.
For inspection before execution, open
[install-latest.sh](https://github.com/ach1992/simple-tun-link/blob/dev-spoof/research/spoof-diagnostics/scripts/install-latest.sh),
[online-bootstrap.sh](https://github.com/ach1992/simple-tun-link/blob/dev-spoof/research/spoof-diagnostics/scripts/online-bootstrap.sh) and
[the release channel](https://github.com/ach1992/simple-tun-link/blob/dev-spoof/research/spoof-diagnostics/release-channel.txt). Exact manual
version-and-digest pinning remains available in the
[technical installation reference](docs/INSTALL-AND-RELEASE.md).

After installation:

```sh
stl-spoofdiag version
stl-spoofdiag preflight
stl-spoofdiag menu
```

The online installer retains the **verified downloaded archive** in
`/root/stl-spoofdiag/`. Installation itself goes under
`/opt/stl-spoofdiag/`, with the command at
`/usr/local/bin/stl-spoofdiag`. It does not start background services.

## Install offline — beginner-friendly instructions

You can install without **any Internet connection on the server** and
without Python, Go, Docker or a package manager on the destination.
You need a matching `spoofdiag-v*_linux_*.tar.gz` archive and its
`.tar.gz.sha256` checksum file from the **same reviewed Spoof Diagnostics
release**, downloaded on a trusted computer when available.

### Step 1 — choose the right archive

On the server, type:

```sh
uname -m
```

- `x86_64` → choose the archive ending in `_linux_amd64.tar.gz`.
- `aarch64` → choose the archive ending in `_linux_arm64.tar.gz`.

On your computer, open the [Releases page](https://github.com/ach1992/simple-tun-link/releases).
**Select a published `spoofdiag-v*` release, never an STL `v*`
release.** Download **both** the correct `.tar.gz` file and the
correspondingly named `.tar.gz.sha256` file.

For example, release `spoofdiag-vX.Y.Z-rc.N` on AMD64 has these
two filenames (the X/Y/Z/N letters are **placeholders**, not a live version):

```text
spoofdiag-vX.Y.Z-rc.N_linux_amd64.tar.gz
spoofdiag-vX.Y.Z-rc.N_linux_amd64.tar.gz.sha256
```

Check the archive's expected SHA256 against a trusted, independently
obtained release identity or signature. **The `.sha256` file next to an
archive only detects a mismatch; it is not independent proof of who
published the archive.** A draft is not a download-ready release.

### Step 2 — transfer the two files

Using SFTP/WinSCP or `scp`, upload those **two files** to your normal
account's home directory on the server (for example `/home/youruser/`).
Log in over SSH as that same account.

Replace the example filename below with the **actual file you downloaded**,
then run:

```sh
ARCHIVE='spoofdiag-vX.Y.Z-rc.N_linux_amd64.tar.gz'
sudo install -d -m 700 /root/stl-spoofdiag
sudo install -m 600 "$HOME/$ARCHIVE" "/root/stl-spoofdiag/$ARCHIVE"
sudo install -m 600 "$HOME/$ARCHIVE.sha256" "/root/stl-spoofdiag/$ARCHIVE.sha256"
```

For ARM64, change only `amd64` to `arm64` in `ARCHIVE`.
This copies the files into the private root-owned download folder;
it does not extract them into the system directories.

### Step 3 — verify, unpack and install

Enter a root shell, switch to the download folder, and select the exact
same filename again:

```sh
sudo -i
cd /root/stl-spoofdiag
ARCHIVE='spoofdiag-vX.Y.Z-rc.N_linux_amd64.tar.gz'
sha256sum --check "$ARCHIVE.sha256"
```

**Do not continue unless the check prints `OK`.** First inspect the
archive's file listing; it should contain only files inside a single
`stl-spoofdiag/` directory:

```sh
tar -tzf "$ARCHIVE"
```

Create a **new, version-specific private extraction directory**.
Do not unpack into `/`, `/opt` or directly on top of another version:

```sh
EXTRACT_DIR="extracted-${ARCHIVE%.tar.gz}"
mkdir -m 700 "$EXTRACT_DIR"
tar -xzf "$ARCHIVE" -C "$EXTRACT_DIR" --no-same-owner --no-same-permissions
bash "$EXTRACT_DIR/stl-spoofdiag/install-offline.sh" --verify
bash "$EXTRACT_DIR/stl-spoofdiag/install-offline.sh" --install
```

The installer will ask you to type `YES` to confirm. It checks the
manifest, archive-contained checksums, architecture and existing file
ownership before changing the installation. If any check fails, stop;
**do not force the install or delete unfamiliar files**.

Finally:

```sh
stl-spoofdiag version
stl-spoofdiag preflight
stl-spoofdiag menu
exit
```

`exit` leaves the root shell. The interactive menu is now ready.
**For later versions**, repeat these steps with the new archive; the
installer preserves previously stored verified releases for rollback.

### Where everything goes

| Path | Purpose |
| --- | --- |
| `/root/stl-spoofdiag/` | Private archive/download inbox and your manually extracted package |
| `/opt/stl-spoofdiag/releases/<version>/` | Installed versioned binaries and build metadata |
| `/opt/stl-spoofdiag/current` | Pointer to the selected verified version |
| `/usr/local/bin/stl-spoofdiag` | Command to launch the executable |
| `/etc/stl-spoofdiag/` | Private operator configuration, if created |
| `/var/lib/stl-spoofdiag/` | Private evidence/receipts, if created |

The installed executable doesn't need the downloaded archive to remain in
the inbox, but keeping the verified archive is convenient for recovery.
Uninstalling the program **does not delete** private configuration or
saved evidence. Offline prerequisites are Bash, `tar`, `sha256sum`,
`flock` (util-linux), standard Linux file utilities, and the matching
AMD64/ARM64 architecture.

For verified rollback and tool-only uninstall, consult
[INSTALL-AND-RELEASE.md](docs/INSTALL-AND-RELEASE.md).

## Field menu, selected IPs and signed exchange

`stl-spoofdiag menu` exposes 19 operations including candidate
management, campaign preparation/continuation/reporting, offline plan,
identity provisioning, actual prerequisite checks, Field A/B operations,
and signed receipt verification. **There is no Private Lab menu or netns runtime.**

A field inventory uses the singular `field_candidates` schema, not the
historical `private_lab` or `approved_field_plan` modes:

```json
{
  "schema_version": 1,
  "mode": "field_candidates",
  "candidates": [
    {"ip": "10.40.0.7", "direction": "A_TO_B", "sender": "A", "receiver": "B"}
  ]
}
```

`10.40.0.7` is an example of an operator-owned RFC1918 candidate for
documentation, **not** a public field result. For a public experiment,
replace it with the exact public IPv4 legitimately authorized for the
specific source network and destination. Each receiver also keeps its
own exact source allowlist. Reverse-direction candidates have distinct
`B_TO_A` roles and require a separate signed run.

An inventory CSV/JSON may contain thousands of exact candidates (the
current reader bounds a file to 4 MiB); this is **not** a promise that a
single signed run covers them. Each signed run currently accepts up to 32
distinct IPs and 1–10 samples per IP. `campaign create/next/report` automates offline batching, next-run
preparation, durable continuation and signed-evidence aggregation for large
operator-provided lists. It does **not** discover IPs, transmit by itself,
auto-retry grants or perform unattended high-rate probing. There is no
automatic source-IP discovery.

Source inventory editing and an offline plan never transmit anything:

```sh
stl-spoofdiag sources add --file sources.json --mode field_candidates --ip 10.40.0.7 --direction A_TO_B --sender A --receiver B
stl-spoofdiag sources list --file sources.json
stl-spoofdiag plan --file sources.json
```

### Theoretical two-host procedure (NOT executed)

These commands describe the signed field workflow; **do not run a public
raw-source trial without separately verified owner, peer and provider
authorization**. Use exact IPs, user-controlled ports, and compatible
clocks. The signed plan has a default 10-minute expiration; start the
receiver before the sender and generate a new plan when expired.

Provision identities **on a trusted offline machine**, not directly on an
exposed server:

```sh
stl-spoofdiag field identity --dir /secure/new-field-credentials
```

This produces a private CA key and both A/B node keys. Copy `ca.crt` plus
only `A.crt`/`A.key` to A, and `ca.crt` plus only `B.crt`/`B.key` to B,
using private owner-controlled paths. **Never place `ca.key` or the
opposite node's private key on either field server.** Rotate and revoke
compromised identity material outside the research tool.

On A, with its permitted candidate inventory, create an exact signed plan:

```sh
stl-spoofdiag field challenge --file sources.json \
  --cert A.crt --key A.key --ca ca.crt \
  --sender A --receiver B --transport field_raw_ipv4 \
  --destination-ip RECEIVER_OWNED_IPV4 --data-port 24572 \
  --samples-per-source 5 --out challenge.json
```

Transfer `challenge.json` to B. On B, validate the plan against B's own
independent allowlist and issue a receiver-signed consent grant:

```sh
stl-spoofdiag field grant --file sources.json \
  --challenge challenge.json --cert B.crt --key B.key --ca ca.crt \
  --sender A --receiver B --out grant.json
```

Transfer `grant.json` back to A. On B, start the exact destination-bound,
finite receiver (replace `RECEIVER_OWNED_IPV4` and paths):

```sh
stl-spoofdiag field listen --file sources.json \
  --challenge challenge.json --grant grant.json \
  --cert B.crt --key B.key --ca ca.crt \
  --sender A --receiver B --destination-ip RECEIVER_OWNED_IPV4 \
  --bind-ip RECEIVER_OWNED_IPV4 --data-port 24572 \
  --state-dir /private/field-consumed-runs --out receipt.json
```

On A, **only when required permissions are independently confirmed**, the
raw adapter uses the explicit host NIC and exact signed source inventory:

```sh
stl-spoofdiag field send --file sources.json \
  --challenge challenge.json --grant grant.json \
  --cert A.crt --key A.key --ca ca.crt \
  --sender A --receiver B --destination-ip RECEIVER_OWNED_IPV4 \
  --data-port 24572 --interface SENDER_EGRESS_NIC --provider-authorized \
  --out sender.json
```

`--provider-authorized` records operator acknowledgement but **does not
grant or verify network-provider authority**. Absent actual authorization,
do not send any forged public-source packets. To use only the sender's
locally assigned addresses instead, create the challenge with
`--transport field_udp_bound` and omit `--interface` and
`--provider-authorized` at send time.

**Destination topology:** direct B bind remains the default. If B is
behind an independently owned/configured DNAT or 1:1 forwarding endpoint,
B may explicitly issue the grant with
`--bind-ip RECEIVER_LOCAL_IPV4 --allow-forwarded-destination`, then listen
with the **same signed local bind** and flag. B's local IPv4 must actually
be assigned; the externally advertised destination stays immutable in the
challenge and grant. The program **does not create, verify or prove NAT
forwarding**. No third-party destination is implicitly approved.

After the receiver finishes, independently transfer `receipt.json` to a
trusted machine and check the exact three-way cryptographic binding:

```sh
stl-spoofdiag field verify --challenge challenge.json \
  --grant grant.json --receipt receipt.json --ca ca.crt \
  --sender-report sender.json
```

**Sampling precision:** `--samples-per-source` controls independent packet
identities from 1 to 10 per selected IP (default 5). Samples are interleaved
between selected IPs, rather than emitted in a short burst per IP. The
receiver's default window automatically expands with the signed sample count
(at most 120 seconds). An insufficient window or expiring grant is now
rejected *before* receiving; the sender also checks read-only local
prerequisites before initiating any sample. A signed
run still approves at most 32 distinct selected IPs, hence at most 320 total
datagrams with the current maximum. This is a **per-run bound**, not the
operator's total source inventory capacity. Offline Campaign Manager handles
many bounded runs and transparent signed peer-observation ordering; automatic
source discovery, continuous daemon operation and true link quality ranking
are not implemented.

`field verify` reports per-source `planned_samples`,
`authenticated_peer_observations`, `exact_source_observed`,
`different_source_observed`, `planned_but_not_observed`, the percentage
observed versus the signed plan and the percentage of received samples with
an exact Source IP match. The receiver only knows its own observations:
**planned-but-not-observed is not a proven packet loss**, because a sender
might not have submitted all planned samples. Five observations are
preliminary diagnostic evidence, not statistical proof of path reliability.

`SUBMITTED_ONLY` is a sender syscall outcome, not packet delivery.
A signed receiver observation is not proof of upstream provider admission,
physical NIC capture, sender return routing, private L3 or source authorization.
A valid receipt with zero packets is **inconclusive**, not proof that an
address is blocked.

## Campaign Manager — many exact IPs, one bounded approved run at a time

The following commands prepare files and verify records **without sending any
network packets**. The values are examples of test-owned addresses, not proven
real-network results. Generate a separate campaign for reverse `B_TO_A`
direction with the receiver on A.

On the sender A, create a private immutable campaign from an operator-owned
source file, then sign the **first** short-lived batch when ready:

```sh
stl-spoofdiag campaign create --file sources.json \
  --dir /private/campaign-A-to-B --direction A_TO_B \
  --destination-ip RECEIVER_OWNED_IPV4 --transport field_udp_bound
stl-spoofdiag campaign next --dir /private/campaign-A-to-B \
  --cert A.crt --key A.key --ca ca.crt
```

`campaign next` prints an exact batch source file and signed challenge path.
Transfer the immutable batch source file and signed challenge to B. B must
independently approve the same exact candidates in its **own** allowlist.
For an operator-authorized run, B can use a single foreground command to
issue the B-signed grant and start its finite listener:

```sh
stl-spoofdiag field accept --file B-owned-allowlist.json \
  --challenge challenge.json --cert B.crt --key B.key --ca ca.crt \
  --grant-out grant.json --ready-out ready.json \
  --state-dir /private/consumed-runs --out receipt.json
```

The guided **menu option 19** runs the receiving side of one campaign batch.
An equivalent receiver-side command is available once an immutable copy of
the campaign directory, including its signed challenge, has been transferred
to B:

```sh
stl-spoofdiag campaign receive --dir /private/B-campaign-copy \
  --file B-owned-allowlist.json --cert B.crt --key B.key --ca ca.crt
```

This operation is foreground-only: B uses its independent allowlist,
approves one challenge and publishes signed grant, readiness and receipt
artifacts under the receiver's copy of the run directory. Any artifacts
needed by A still require operator-managed secure transfer. The menu
requires an explicit `LISTEN_ONE` confirmation; neither the command
nor an offline preparation step sends diagnostic traffic from A. No such
receiver operation was run on live hosts in this development cycle.

Transfer the B-signed `grant.json` **and** B-signed `ready.json` to the A
campaign attempt directory; `ready.json` is written only after B binds its
finite listener. B must remain listening. The ready file has a short expiry,
so expired sessions require a new challenge and independent B approval.
`field check --role sender|receiver` assesses interface, capability,
cryptographic identity and expiry prerequisites **without opening sockets**.
For an authorized sender action, A can invoke exactly **one** granted batch
(no automatic continuation or provider-permission bypass):

```sh
stl-spoofdiag campaign send --dir /private/campaign-A-to-B \
  --cert A.crt --key A.key --ca ca.crt
```

For `field_raw_ipv4`, `campaign send` also requires an explicitly selected
`--interface` and `--provider-authorized`, with separately verified genuine
permission. No field sends or listeners were executed during development.
B's receipt is stored or copied to the `receipt.json` path printed by
`campaign next`; A keeps `sender.json` in the same run directory. File transfer
is currently operator-managed: there is **no always-on remote control agent
and no background job**. A B-signed grant approves the plan and a B-signed readiness file records
successful local listener binding, **not** a guarantee B remains reachable
when A sends.

To summarize verified evidence and prepare the **next** 32-IP-or-smaller batch:

```sh
stl-spoofdiag campaign report --dir /private/campaign-A-to-B --ca ca.crt
stl-spoofdiag campaign next --dir /private/campaign-A-to-B \
  --cert A.crt --key A.key --ca ca.crt
```

A batch does not advance without both its cryptographically valid completed
receiver receipt **and** the matching completed signed sender syscall report.
This proves consistency of both endpoint declarations, not physical delivery. An expired/incomplete run remains preserved and requires
a **fresh, separately consented challenge** with the explicit
`campaign next ... --retry-expired` option; the tool does not auto-replay it.
The same directory can be resumed after CLI interruption, without a separate
database or background service.

The report preserves counts for planned samples, authenticated peer sightings,
exact source matches and rewritten source addresses. Any observation-based
ordering is **not** proof of physical egress, provider policy, a viable return
route, statistical packet loss, or a future tunnel.

## Debian / Ubuntu compatibility

**Target distribution baseline:** Debian 11+ and Ubuntu 22.04+,
Linux `amd64`/`arm64`. An *older private-lab version*, not this new Field engine, was exercised on
Debian **12 AMD64 VMs** and in a disposable installation root on a
Debian **13 AMD64** host. GitHub's Ubuntu CI tests build/package
functionality but do **not** replace independent Ubuntu guest acceptance.
ARM64 binaries build, but full booted ARM64 guest tests are still pending.
The new `field_raw_ipv4` mode requires Linux raw-socket privileges and
explicit network/provider permission. Its public-WAN compatibility is
**NOT_TESTED**; historical VM evidence for a retired Private Lab version is
in [LOCAL-LAB-ACCEPTANCE.md](docs/LOCAL-LAB-ACCEPTANCE.md), not proof for
this Field release.

## Technical documentation

- [Versioned Go CLI and signed-receipt reference](docs/GO-REFERENCE.md)
- [Architecture, guards and evidence semantics](docs/ARCHITECTURE.md)
- [Installer, release channel, rollback and uninstall](docs/INSTALL-AND-RELEASE.md)
- [Test/acceptance matrix](docs/VALIDATION-MATRIX.md)
- [Historical isolated VM evidence](docs/LOCAL-LAB-ACCEPTANCE.md)

The historical Python experiment remains accessible through Git history,
but is **not** part of this standalone Go product or its runtime.
