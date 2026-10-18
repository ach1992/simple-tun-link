# STL Spoof Diagnostics

**A standalone Linux network diagnostic, implemented in Go.** It lives in this
repository for development convenience, but has its **own binary, menu,
installation scripts, configuration, and release lifecycle**. Installing or
removing this tool does not install, update, or modify Simple Tun Link (STL).

## What it does

The tool records a finite list of exact IPv4 source candidates separately for
each direction (A→B / B→A), creates a test plan, and distinguishes these
independent stages:

1. **Configured:** a candidate is listed; no packet has been sent.
2. **Submitted:** a local sender attempted a sample; admission is still unknown.
3. **Peer observed:** a separate receiver authenticated and signed what it saw.
4. **Return path / private L3:** separate observations are required. Receiving
   a sample does not prove that applications can communicate bidirectionally.

The prototype includes signed challenge/receipt files, local TLS 1.3 mutual
authentication and UDP tests, offline report verification, and an experimental
raw IPv4 laboratory adapter. **The currently executable raw adapter is
restricted to detached, private-address network namespaces. It does not
operate as a general public-network source-spoofing tool.** Real two-host
provider compatibility, return paths, and end-to-end L3 have not been tested
or established.

No server permissions, provider behavior, usable source addresses, or route
availability can be inferred from a successful installation or a saved plan.

## Current delivery status

| Component | Status |
| --- | --- |
| Go CLI, interactive menu, source inventory, local test and signed evidence | Implemented |
| Offline archives for Linux **amd64** and **arm64**, without Go/Python on the target | CI-built development artifacts |
| Reinstall, upgrade, verified rollback, uninstall, preserve private data | Implemented; additional failure-injection tests pending |
| Online downloader invoking the same offline installer | Implemented and locally tested with a test artifact server |
| Dedicated public, immutable, authenticated tool Release | **Not published** |
| Public IP selection for an **offline plan** | Implemented; no traffic |
| General Internet/public-IP raw sending or real-server operation | **Not implemented or validated** |
| Two actual isolated Debian 12 VMs, earlier signed raw private-lab receipts | Partially verified; unresolved capture discrepancy |

The source branch is not a public release. See the exact
[validation matrix](docs/VALIDATION-MATRIX.md) and
[lab evidence](docs/LOCAL-LAB-ACCEPTANCE.md) for the distinction between
PASS, PARTIAL, NOT_RUN and blocked tests.

## Install — self-contained, no Go or Python on the destination

The **download/inbox directory** is `/root/stl-spoofdiag/`, while the executable
is installed separately under `/opt/stl-spoofdiag/` with a launcher at
`/usr/local/bin/stl-spoofdiag`. Your private configuration and receipts live
outside the versioned binary and survive an executable update or uninstall.
The installer never downloads compilers, pip packages, or STL packages.

### One-line online install (after the first dedicated release)

Once a **dedicated `spoofdiag-vX.Y.Z` Release** and its independently trusted
archive SHA256 have been published, the operator command, **from this tool's
source directory**, is one line:

```sh
sudo bash scripts/online-bootstrap.sh --version spoofdiag-vX.Y.Z --sha256 INDEPENDENTLY_VERIFIED_64_HEX_ARCHIVE_SHA256 --install
```

The script selects Linux amd64/arm64, downloads the exact architecture's
archive over HTTPS, checks its supplied trusted SHA256 and members, then invokes
the same offline installer. It does **not** use the repository's
`releases/latest` (which belongs to STL), download Go/Python, or download
unverified scripts from `main`.

**This is the implemented one-command interface, not a currently functioning
public download link:** the required tool-specific Release and trusted digest
are not yet available. Do not substitute the STL release tag or invent an
archive hash. The bootstrap can be exercised in a disposable local test root;
see [installation and release details](docs/INSTALL-AND-RELEASE.md).

### Offline install (works with a verified current development archive)

Copy a complete architecture-matching, independently verified snapshot archive
to `/root/stl-spoofdiag/`, and extract it in that private directory. Inside it
is a directory named `stl-spoofdiag/` containing the executable, its checksums,
manifest, and canonical offline installer. Then **one command** verifies
the complete bundle and installs it after an interactive confirmation:

```sh
sudo bash /root/stl-spoofdiag/stl-spoofdiag/install-offline.sh --verify && sudo bash /root/stl-spoofdiag/stl-spoofdiag/install-offline.sh --install
```

The exact extraction and manifest-integrity checks are described in
[INSTALL-AND-RELEASE.md](docs/INSTALL-AND-RELEASE.md). An archive checksum
provided by the same download source is not, by itself, independent proof of
publisher identity.

After installation:

```sh
stl-spoofdiag version
stl-spoofdiag preflight
stl-spoofdiag menu
```

Target baseline: compatible Linux amd64/arm64 with Bash, tar, sha256sum,
standard file utilities and `flock`. **No Go toolchain, Python interpreter,
Internet access, package manager or containers are needed for offline use.**

## Interactive menu

Run `stl-spoofdiag menu`. It displays product/build identity, environment,
current capabilities, and the following actions; a failed action returns to
the menu rather than terminating the session:

- Inspect version and local prerequisites.
- List, add, import, remove, and replace exact source candidates.
- Validate an offline candidate plan; review declared evidence.
- Generate disposable identities for local tests (private keys remain local).
- Create and verify signed challenge/receipt files.
- Start a loopback receiver and sender, including the signed offline path.
- Verify a local TLS receiver's signed receipt; see contextual help and exit.
- Access guarded raw IPv4 private-namespace test actions through an advanced submenu.

The menu does not automatically alter routes, firewalls or STL services.
For automation, use the equivalent CLI commands and JSON; do not parse terminal
menus. A raw private-namespace test remains an explicitly selected advanced
operation with the same underlying CLI validation, never an unattended default.

## Plan candidate addresses without sending traffic

`sources`, `plan`, and `report` do not send packets. For the currently
supported **private laboratory** inventory:

```sh
stl-spoofdiag sources add --file ./sources.json --mode private_lab --ip 10.91.1.77 --direction A_TO_B --sender A --receiver B
stl-spoofdiag sources list --file ./sources.json
stl-spoofdiag plan --file ./sources.json
```

For **offline public-address planning only**, `sources add --mode
approved_field_plan` accepts a real, operator-entered, globally routable exact
IPv4 (not a reserved example or private address), with direction and peer
identities. This does **not** enable sending to/from that address. Empty plans,
duplicates, malformed addresses and role inconsistencies are rejected.
CSV input defaults to `private_lab`; use JSON when saving a field plan.

## Documentation and maintenance

- [Go reference: existing laboratory commands and signed receipts](docs/GO-REFERENCE.md)
- [Architecture and safeguards](docs/ARCHITECTURE.md)
- [Install, upgrade, rollback, uninstall and release contract](docs/INSTALL-AND-RELEASE.md)
- [Validation matrix and outstanding tests](docs/VALIDATION-MATRIX.md)
- [Reproducible VM acceptance](docs/LOCAL-LAB-ACCEPTANCE.md)
- Source: `cmd/stl-spoofdiag/`; own packaging and install code: `scripts/`.

The previous Python prototype is no longer part of the active source tree or
runtime; its research history remains recoverable from Git. Go remains the
single product implementation. No code under the STL runtime, STL installers,
or protected `main` is modified by this standalone tool.
