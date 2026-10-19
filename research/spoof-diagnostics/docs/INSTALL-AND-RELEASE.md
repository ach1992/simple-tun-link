# Standalone Spoof Diagnostics — installation and release reference

**Scope:** `research/spoof-diagnostics/` on the permanent
[`dev-spoof`](https://github.com/ach1992/simple-tun-link/tree/dev-spoof)
branch. This tool has **no automatic merge to STL `main`** and no dependency
on STL's installer, `v*` tags or stable release/update workflow.

**Historical candidate:** `spoofdiag-v0.1.0-rc.1` was assembled as an
unpublished Draft from an older implementation. It is not the current Field
release and must not be selected as a public installation endpoint. The
source commit, tag, release assets and current channel must agree before any
new download is advertised. The earlier RC2 had an Owner-approved internal
review exception. **RC3** code received independent approval **for
integration into `dev-spoof`**; this does not establish field-network,
production or runtime ARM64 readiness. The experimental RC3 pre-release
has separately verified asset SHA-256, tag and source identities.

For non-developers, the canonical step-by-step instructions are the
[tool-local README](../README.md). This document owns the exact command,
download, artifact, directory and publisher-channel contracts.

## 1. Versionless online installation

**Public command, only after the channel says `status=published`:**

```sh
bash -o pipefail -c 'curl -fsSL --proto "=https" https://raw.githubusercontent.com/ach1992/simple-tun-link/dev-spoof/research/spoof-diagnostics/scripts/install-latest.sh | sudo bash -s -- --accept'
```

The command takes no version or SHA from the operator. Its current behavior
depends on the live `dev-spoof` channel, not when this README was built. It fetches
[`release-channel.txt`](https://github.com/ach1992/simple-tun-link/blob/dev-spoof/research/spoof-diagnostics/release-channel.txt) over GitHub HTTPS. Check that live file for the
currently selected release. **Before a release is published**, the channel
has exactly one line:

```text
status=unpublished
```

While the channel remains in that state, the command **fails closed** with
`NO_PUBLIC_SPOOFDIAG_RELEASE` without any archive install, and it must
not fall back to the STL version at `releases/latest`. This is an
intended pre-publication result, not a defective one-liner.

After a tool-specific prerelease is approved under the active Owner review
policy, published and its immutable asset hashes reconciled, a separate
**exact-commit-validated PR targeting `dev-spoof`** updates the five-line
channel to:

```text
status=published
version=spoofdiag-vX.Y.Z-rc.N
linux_amd64_sha256=<64 lowercase hex characters>
linux_arm64_sha256=<64 lowercase hex characters>
bootstrap_sha256=<64 lowercase hex characters>
```

These are a **schema illustration, not valid published values**. Values
must come from the final release asset bytes and the exact
`scripts/online-bootstrap.sh` version at the channel commit. Do not
use the content of an unreviewed Draft, guessed SHA, a local snapshot or
the STL tag series. The updated channel must have exactly five keys in
this order; unknown, duplicated, missing or malformed fields are
rejected. The channel records one selected **approved SpoofDiag**
version, not a public-IP scanning procedure.

### What actually runs

1. `scripts/install-latest.sh` obtains the exact channel, selects
   Linux AMD64 or ARM64 and independently compares the downloaded
   pinned bootstrap bytes to the channel's bootstrap SHA256.
2. The existing `scripts/online-bootstrap.sh` requests an **exact
   `spoofdiag-v*` tag** from
   `https://github.com/ach1992/simple-tun-link/releases/download/<tag>/`.
   It never uses `releases/latest`, `main`, or an ambiguous `latest`
   version.
3. The bootstrap downloads only the matching
   `<tag>_linux_<arch>.tar.gz` archive, compares it to the channel's
   expected SHA256, checks the archive's exact member list and types,
   verifies the *bundle's* product/build identity fields and internal
   checksums, and delegates installation to the same
   `install-offline.sh` engine used offline.
4. After validation, the verified archive is retained under
   `/root/stl-spoofdiag/` for offline re-use, while the installed program
   goes under `/opt/stl-spoofdiag/`.
5. Installation only changes tool-owned executable resources, and never
   downloads Go/Python, starts a listener or edits STL network state.

The one-line command uses HTTPS and the GitHub publisher-controlled
branch as its initial **code trust root**. Checksums from that same
publisher provide integrity and source consistency, **not independent
publisher-signature attestation**. Users should inspect or
independently authenticate the bootstrap source before running it as
root; public distribution additionally requires the separately
recorded project provenance review.

### Exact-version advanced command

Users who have an **independently trusted archive SHA256** may bypass
channel selection and invoke the reviewed version-pinned engine from
the checked-out tool directory (or a separately authenticated copy
of `online-bootstrap.sh`):

```sh
sudo bash scripts/online-bootstrap.sh \
  --version spoofdiag-vX.Y.Z-rc.N \
  --sha256 INDEPENDENTLY_VERIFIED_64_HEX_ARCHIVE_SHA256 \
  --install
```

This is deliberately the **advanced option**, not the ordinary
installation instruction. The source code, version and checksum are
placeholders until a corresponding artifact is actually published.

The online downloader additionally accepts `--verify-only`, `--accept`
and `--inbox /existing/private/path`. `--destdir /existing/test-root`
and `--local-url http://127.0.0.1:PORT` are developer/test-only;
the local HTTP case is restricted to a `dev-*` test archive and requires
an explicit private `--inbox`. No production HTTP downgrade.

## 2. Offline installation with no server Internet

The **operator-facing numbered procedure and commands** are in the
[README's offline installation section](../README.md#install-offline--beginner-friendly-instructions).
It explains how to:

1. Identify your architecture with `uname -m`;
2. Download the matching tool-specific release `.tar.gz` and
   `.tar.gz.sha256` files to a trusted personal computer;
3. Upload both via SSH/SFTP and copy them into
   `/root/stl-spoofdiag/` with private permissions;
4. Check the archive's SHA256, review its member list and extract into
   a new private `extracted-<archive-name>/stl-spoofdiag/` directory;
5. Run the **included** installer with `--verify` and `--install`;
6. Run `stl-spoofdiag version`, `preflight` and `menu`.

For example, after unpacking an independently authenticated archive:

```sh
bash /root/stl-spoofdiag/extracted-<archive-name>/stl-spoofdiag/install-offline.sh --verify
bash /root/stl-spoofdiag/extracted-<archive-name>/stl-spoofdiag/install-offline.sh --install
```

Here `<archive-name>` is derived from the exact extracted archive
name, **not** a literal filename or a directory the installer creates
automatically. The README's `EXTRACT_DIR` variable makes this explicit.

An offline host needs Bash, `tar`, `sha256sum`, `flock` from util-linux,
standard file utilities, a compatible Linux kernel and the correct
prebuilt AMD64/ARM64 binary. **No `apt`, Go, Python, `pip`, Docker,
DNS, `curl` or `wget` is required for offline installation.**

### Directory ownership

| Location | Contents |
| --- | --- |
| `/root/stl-spoofdiag/` | Private download/archive inbox, operator-extracted packages |
| `/opt/stl-spoofdiag/releases/<version>/` | Installed executable, exact build manifest and checksums |
| `/opt/stl-spoofdiag/current` | Version-selecting symlink |
| `/usr/local/bin/stl-spoofdiag` | Launcher symlink |
| `/etc/stl-spoofdiag/` | Reserved private operator config (preserved) |
| `/var/lib/stl-spoofdiag/` | Reserved private evidence/receipts (preserved) |

A filename under `/root` is **not** an executable installation path.
The canonical offline installer rejects unknown files, symlinks and
foreign-owned paths; no STL binaries, Links, systemd units, routes,
firewalls, sysctls, or stable-branch artifacts are touched. The
downloaded archive is *retained* for optional future offline recovery.

## 3. Upgrade, rollback, uninstall

- **Upgrade:** obtain a newer verified archive, extract to a **new**
  directory and execute its included `install-offline.sh --verify`
  followed by `--install`. Older verified versions remain stored.
- **Rollback:** with a locally verified extracted installer, run
  `bash install-offline.sh --rollback --to EXACT_STORED_VERSION`
  and confirm `YES`. Only installed versions whose manifests and
  binary checksums verify can be selected.
- **Uninstall:** with a locally verified extracted installer, run
  `bash install-offline.sh --uninstall`, confirm `YES`.
  It removes **only tool-owned binaries and links**; data in
  `/etc/stl-spoofdiag/` and `/var/lib/stl-spoofdiag/` remains.
- `--accept` is an explicit non-interactive confirmation primarily
  for automation; otherwise the installer asks for `YES`.
- A per-destination `flock` prevents concurrent state switches,
  complete version directories are switched atomically, and only
  strictly verified tool-owned interrupted stages are recoverable.
  Actual VM power-loss, full-disk and read-only filesystem acceptance
  remains outstanding; never delete foreign material to force recovery.

The installed executable includes `version`, `preflight`,
`menu`, `sources`, `plan`, `report` and `field` commands.
`field` provides `identity`, `challenge`, `grant`, `listen`, `send` and
`verify`; the old `lab` command was removed. `reports` and `diagnostics`
are **not** additional verbs. Menu and CLI invoke the same Go engine.

## 4. Developer and maintainer release procedure

**Persistent branch:** `dev-spoof`; all new tool PRs must target this
branch. Its deletion is blocked by the repository branch ruleset.
STL's development and normal releases continue separately on `main`.

**Release namespace:** `spoofdiag-vX.Y.Z`, with
`spoofdiag-vX.Y.Z-rc.N` for experimental release candidates.
A release must originate from an **exact reviewed SHA** in the
`dev-spoof` lineage, not the default `main` HEAD or an unrelated
STL tag. During this research period, publish only as GitHub
**Pre-release**, never as the stable `latest` release.

On a clean checkout of the accepted source, from the **tool root**:

```sh
bash scripts/prepare-release.sh spoofdiag-vX.Y.Z-rc.N /existing/parent/fresh-tool-release-dir
```

This script prepares, checksums, and retains exactly seven **tool-only**
asset files. It does not create tags, Releases, or deployments:

```text
spoofdiag-vX.Y.Z-rc.N_linux_amd64.tar.gz
spoofdiag-vX.Y.Z-rc.N_linux_amd64.tar.gz.sha256
spoofdiag-vX.Y.Z-rc.N_linux_arm64.tar.gz
spoofdiag-vX.Y.Z-rc.N_linux_arm64.tar.gz.sha256
SHA256SUMS
RELEASE-SOURCE.txt
online-bootstrap.sh
```

The tag `spoofdiag-v*` is **already the archive filename prefix**;
never generate `spoofdiag-spoofdiag-v*`. Unreleased `dev-*`
snapshots instead carry filenames like `spoofdiag-dev-ci_linux_amd64.tar.gz`.

Before public publication, reconcile the exact commit, tag and asset
SHA256 identities, successful exact-source CI and the review required for
that particular release, then verify Owner delivery authorization.
The earlier RC2 Owner exception for internal Master self-review was
release-specific; do not misrepresent it as independent approval.
For RC3, the independently reviewed integration tree matches the
squash-merged `dev-spoof` tree, its tool-only release assets were checked,
and the Owner specifically authorized an **experimental SpoofDiag
Pre-release**. Neither approval certifies two-host Field operation or
production suitability. Future releases retain their own approval gates.
A Release created as **Draft** is not a public tagged download and does
**not** make the channel `status=published`. After publication, update the
channel only through a separate verified, approved PR; never point it at
nonexistent, Draft, superseded or unauthorized assets.

GitHub has **one** `releases/latest` endpoint for the repository.
SpoofDiag uses only its prefixed immutable tag series and an explicit
channel pointer. The stable STL `releases/latest` entry and ordinary
STL installer are never redirected. Future integration with STL is a
**separate Owner-controlled architecture and review decision**.
