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

It lets you list exact IPv4 source-address candidates for two separate
directions (A→B and B→A), create an **offline plan** without transmitting
anything, run local authenticated diagnostics, and verify receiver-signed
evidence. Its results carefully separate *packet submitted*, *observed by
receiver*, *return path observed* and *usable private L3*; one stage does
not prove the next.

**Current limits:** TLS/UDP peer tests run locally on loopback. Its raw IPv4
sender runs only inside a separately isolated, private RFC1918 Linux network
namespace; it is **not** a ready-to-use public-WAN source-spoofing tool.
Recording a public IP in an offline plan does **not** send a packet. Real
provider compatibility, return routing and usable private L3 are unverified.
See the [test evidence and outstanding checks](docs/VALIDATION-MATRIX.md).

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

## Interactive menu and offline planning

Run `stl-spoofdiag menu` to see 15 choices. The menu includes build
information, prerequisite checks, managing exact source candidates,
validating plans, signed challenges/receipts, disposable local test
credentials, local TLS/UDP peers and an advanced **private namespace**
laboratory option. Invalid input returns to the menu.

To create a direction-specific **private offline plan**, for example:

```sh
stl-spoofdiag sources add --file ./sources.json --mode private_lab --ip 10.91.1.77 --direction A_TO_B --sender A --receiver B
stl-spoofdiag sources list --file ./sources.json
stl-spoofdiag plan --file ./sources.json
```

The `approved_field_plan` mode accepts eligible globally routable IPv4
candidates **as offline records only**; it does not activate public sending.
The separate `report` command evaluates declared evidence and labels
that declaration `UNVERIFIED_INPUT_DECLARATION`; cryptographic receipt
verification uses `lab verify` or `lab offline-verify` instead.

## Debian / Ubuntu compatibility

**Target distribution baseline:** Debian 11+ and Ubuntu 22.04+,
Linux `amd64`/`arm64`. An actual offline package has been tested on
Debian **12 AMD64 VMs** and in a disposable installation root on a
Debian **13 AMD64** host. GitHub's Ubuntu CI tests build/package
functionality but do **not** replace independent Ubuntu guest acceptance.
ARM64 binaries build, but full booted ARM64 guest tests are still pending.
The advanced raw-namespace mode additionally depends on kernel-specific
features; compatibility of any public WAN path is not established.

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
