# Spoof Diagnostics — standalone Go tool

**A separate Linux diagnostic inside the Simple Tun Link GitHub repository.**
Spoof Diagnostics has its own executable, interactive menu, installation
scripts, documentation, saved configuration and release series. **It is not
STL:** installing it does not install, upgrade, configure or run STL.

- **Product source and documentation:** `research/spoof-diagnostics/`
- **Permanent development branch:** [`dev-spoof`](https://github.com/ach1992/simple-tun-link/tree/dev-spoof)
- **Future standalone downloads:** [GitHub Releases](https://github.com/ach1992/simple-tun-link/releases), **only tags beginning with `spoofdiag-v`**
- **STL's separate branch:** `main`; Spoof Diagnostics changes and PRs target `dev-spoof` and must not be merged into `main` without a new Owner decision

## What the tool does

The current development candidate replaces the former Private Lab runtime
with a **Field** workflow for two explicitly controlled hosts, A and B.
It accepts an **exact, operator-chosen IPv4 candidate list** independently
for A→B and B→A; it does not enumerate CIDR ranges, scan the Internet,
open services in the background or integrate with STL.

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
  interface, and one raw IPv4 UDP packet per approved candidate. The packet
  source is the exact signed, user-selected IPv4; the signed destination is
  a single cooperating receiver. It is rate- and count-bounded, and requires
  separately verified owner **and provider** permission before any public
  forged-source trial. The command-line acknowledgement is not proof of
  that permission.

**Validation status of this candidate:** source edited and compilation
reviewed only. **NO real two-host test, public spoof packet, provider
acceptance test, receiver test, or L3 test has been executed.** Nothing here
should be described as confirmed field reachability or production readiness.

The source, documentation and installation package live only under
`research/spoof-diagnostics/` on the independent development line. The
existing unrelated STL product and its stable `main` branch are untouched.

## Install online — one general command (no version number)

When the Spoof Diagnostics channel has its **first reviewed, published**
release, run this one command on the Debian/Ubuntu server:

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

**Publication status:** the first Spoof Diagnostics release candidate is
currently a **GitHub Draft**, not a public download, and the channel is
`status=unpublished`. Until it is independently reviewed and published,
the command intentionally stops with
`NO_PUBLIC_SPOOFDIAG_RELEASE` **without installing anything**. Do not
substitute STL's release or an arbitrary development artifact.

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

`stl-spoofdiag menu` now shows 12 choices including candidate management,
offline plan, identity provisioning, challenge/grant, field receiver/sender,
and receipt verification. **There is no Private Lab menu or netns runtime.**

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
  --out challenge.json
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
  --data-port 24572 --interface SENDER_EGRESS_NIC --provider-authorized
```

`--provider-authorized` records operator acknowledgement but **does not
grant or verify network-provider authority**. Absent actual authorization,
do not send any forged public-source packets. To use only the sender's
locally assigned addresses instead, create the challenge with
`--transport field_udp_bound` and omit `--interface` and
`--provider-authorized` at send time.

**Current field restriction:** the signed destination IPv4 must be assigned directly to the receiving host interface; server-side DNAT/1:1 public-to-private forwarding is not yet modeled and must not be represented as supported. Both the grant and listener check direct ownership before operating.

After the receiver finishes, independently transfer `receipt.json` to a
trusted machine and check the exact three-way cryptographic binding:

```sh
stl-spoofdiag field verify --challenge challenge.json \
  --grant grant.json --receipt receipt.json --ca ca.crt
```

`SUBMITTED_ONLY` is a sender syscall outcome, not packet delivery.
A signed receiver observation is not proof of upstream provider admission,
physical NIC capture, sender return routing, or private L3. A valid receipt
with zero packets is **inconclusive**, not proof that an address is blocked.

## Debian / Ubuntu compatibility

**Target distribution baseline:** Debian 11+ and Ubuntu 22.04+,
Linux `amd64`/`arm64`. An *older private-lab version*, not this new Field engine, was exercised on
Debian **12 AMD64 VMs** and in a disposable installation root on a
Debian **13 AMD64** host. GitHub's Ubuntu CI tests build/package
functionality but do **not** replace independent Ubuntu guest acceptance.
ARM64 binaries build, but full booted ARM64 guest tests are still pending.
The new `field_raw_ipv4` mode requires Linux raw-socket privileges and
explicit network/provider permission. Its public-WAN compatibility is
**NOT_TESTED**; the historical VM evidence below applies to a different
retired lab candidate.

For **STL itself**, not this tool, the separate documented baseline is
Ubuntu 22.04+, Debian 11+, kernel 5.4+ and iproute2 5.1+; its available
backends depend on each host's kernel and packages.

## Technical documentation

- [Versioned Go CLI and signed-receipt reference](docs/GO-REFERENCE.md)
- [Architecture, guards and evidence semantics](docs/ARCHITECTURE.md)
- [Installer, release channel, rollback and uninstall](docs/INSTALL-AND-RELEASE.md)
- [Test/acceptance matrix](docs/VALIDATION-MATRIX.md)
- [Historical isolated VM evidence](docs/LOCAL-LAB-ACCEPTANCE.md)

The historical Python experiment remains accessible through Git history,
but is **not** part of this standalone Go product or its runtime.
