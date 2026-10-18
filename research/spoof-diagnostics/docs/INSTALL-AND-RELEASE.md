# Independent installer, offline package and release contract

**Partially implemented contract.** A buildable standalone offline Go archive and a verifying/idempotent install script exist for local release-candidate testing; owned-path/symlink negative controls were exercised in disposable test roots. **No public tool release or validated online one-liner exists.** Upgrade, rollback and uninstall were exercised both in disposable roots and on two isolated Debian 12 guests, including foreign-file refusal, private-state retention and user-accessible launcher verification. A simulated aborted staging directory was safely recovered and concurrent installer attempts were serialized on the same destination; unknown staging content was preserved and refused. Independent publisher signature verification, actual power-loss/disk-full recovery and broader guest coverage remain acceptance gaps; do not mistake current install smoke for full lifecycle acceptance.

## Permanent tool branch and release identity

`dev-spoof` is the persistent independent SpoofDiag development branch.
SpoofDiag topic branches and pull requests **target `dev-spoof`**. They
must not target or automatically integrate into STL `main`; `dev-spoof`
must not be deleted as a routine branch cleanup. STL releases (`v*`)
remain exclusively owned by the normal STL main branch process.

For an approved release candidate, from a clean current `dev-spoof`
checkout, with a new, tool-only prefixed tag:

```sh
bash scripts/prepare-release.sh spoofdiag-vX.Y.Z-rc.N /existing/parent/new-release-dir
```

This generates exactly these standalone release assets:

```text
spoofdiag-vX.Y.Z-rc.N_linux_amd64.tar.gz
spoofdiag-vX.Y.Z-rc.N_linux_amd64.tar.gz.sha256
spoofdiag-vX.Y.Z-rc.N_linux_arm64.tar.gz
spoofdiag-vX.Y.Z-rc.N_linux_arm64.tar.gz.sha256
online-bootstrap.sh
SHA256SUMS
RELEASE-SOURCE.txt
```

**Important naming:** the official `spoofdiag-v*` tag is already the
filename prefix. The build and online bootstrap must **not** generate
`spoofdiag-spoofdiag-v*` double prefixes. Development snapshots named
`dev-*` retain the historical `spoofdiag-dev-*` filenames.

Release source MUST resolve to a specific commit on `dev-spoof`, not
automatically to STL `main`. Prepare the exact files and obtain a fresh
independent review before creating a publicly visible GitHub **Pre-release**,
verify checksum and provenance, and explicitly mark `prerelease: true`
so it cannot displace the stable STL `releases/latest`. Do not invent
remote artifacts or automatically publish from a branch push. The tool
build script never creates tags, Release objects or deployments.
A release tag remains immutable after publication; later changes use a
new tool-specific version.

## 1. Download/storage location on each authorized server

The operator explicitly wants to upload/download the **entire release archive** into root's home directory (not the filesystem `/`):

```text
/root/stl-spoofdiag/
  spoofdiag-vX.Y.Z_linux_amd64.tar.gz    # downloaded/uploaded bytes
  SHA256SUMS                              # if distributed alongside archive
```

Keep this as a **staging/inbox** directory. Do not unzip arbitrary untrusted archives into `/` or `/root`. Do not assume `/root` itself is the executable installation location.

The installer may install only its own files:

```text
/opt/stl-spoofdiag/releases/<exact-version>/  # binaries+version metadata, tool-owned
/opt/stl-spoofdiag/current                   # exact currently accepted version
/usr/local/bin/stl-spoofdiag                  # managed launch alias only if unowned
/etc/stl-spoofdiag/                          # operator-owned private config, 0700
/var/lib/stl-spoofdiag/                      # operator evidence and reports, 0700
```

Installation paths are defaults, not a reason to overwrite a foreign file, symlink or service. Config and private keys **survive** executable upgrades; they are NEVER embedded in public assets. No `stl` binary, Link state, STL installer, systemd unit, default route, iptables, nftables, sysctl or ownership record may be touched.

## 2. No Internet during installation or operation

Target deliverable: one per-architecture **self-contained archive** `spoofdiag-vX.Y.Z_linux_<arch>.tar.gz` containing:

- `stl-spoofdiag` statically linked Linux executable (Go, `CGO_ENABLED=0`, stdlib-only dependencies where possible).
- `install-offline.sh` — canonical audited installer; `--verify`, `--install`, `--rollback --to VERSION`, `--uninstall`, `--accept` and optional `--destdir ROOT` as implemented. There is no `--prefix`, `--update`, or private-state purge flag.
- `BUILD-MANIFEST.txt` with exact product, version, Git commit, arch, Go version and built artifact identity.
- `SHA256SUMS`, source `LICENSE`, tool `README.md`, architecture/operations information and example *non-secret* configuration.
- Optional detached signature/attestation artifact with independently provisioned trusted verification identity; a SHA file served by the same account is not an independent authenticity proof.

The installer must require **zero** `apt`, `pip`, `curl`, `wget`, Go toolchain or DNS. On supported Debian/Ubuntu Linux, `bash` (not merely `/bin/sh`), `tar`, `sha256sum`, `flock` from standard util-linux, core file/permissions utilities and a compatible kernel are explicit local baseline prerequisites; fail with an actionable message when missing. The Go compiler, Python, package manager and DNS are NOT install-time prerequisites. Build/download prerequisites are **CI-side**, not host-side. No external repository/package setup is allowed.

## 3. Online installation uses the SAME offline engine

Current prototype: `scripts/online-bootstrap.sh` takes a **pinned exact** prefixed tag and an independently authenticated archive digest, downloads with HTTPS, rejects unknown archive members, and invokes the offline installer. The local `--local-url http://127.0.0.1:PORT` test route cannot be used with a published release tag and does not permit external HTTP. Verified in a temporary test-root with local HTTP: correct archive verified/installed twice; digest mismatch, invalid URL/version and network failure rejected. **No public tagged tool release, independently signed manifest, or trustworthy one-line command is presently published.** Do not advertise a working `releases/latest` alias for the standalone diagnostic.

## 3a. One-line online installation (version-pinned CLI, after publication)

From a checked-out version of this tool, after the dedicated release and its
archive digest have been authenticated, the online installer is a one-command
interface:

```sh
sudo bash scripts/online-bootstrap.sh --version spoofdiag-vX.Y.Z --sha256 INDEPENDENTLY_VERIFIED_64_HEX_ARCHIVE_SHA256 --install
```

The placeholders are not real release coordinates, and this is **not**
currently a working remote-public installation. A future remote one-liner
must fetch an immutable, independently authenticated bootstrap script or
equivalent trusted release asset before invoking this same installer.
The regular STL stable tag and `releases/latest` are never substituted.

### Requirements for public remote one-liner

Future online bootstrap, only after the tool's first validated release:

1. Fetch an **explicitly selected immutable `spoofdiag-v*` tag** or a trusted manifest resolver that never conflates STL `v*` tags with tool tags.
2. Download the exact archive and its independent verification materials to `/root/stl-spoofdiag/`, using HTTPS with bounded timeouts and no shell execution of an unverified response.
3. Verify product/tag/arch checksums and expected identity; refuse mismatches.
4. Invoke the **same** `install-offline.sh` shipped within the verified archive.

The GitHub repository has one `releases/latest` pointer. Tool releases must use **separate prefixed tags**, should remain prereleases during research and must explicitly avoid taking over STL's `latest` designation. A human-facing "install latest spoofdiag" command must resolve only the **tool's** vetted version series, never blindly use `releases/latest`.

No one-liner is promised or offered as executable until exact published assets/verification have been validated. A command that downloads an arbitrary `main` shell script and immediately runs it as root is not acceptable.

## 4. Offline operator sequence (after validated bundle is available)

```sh
# Copy the official complete archive from a trusted computer to the authorized host:
sudo mkdir -p /root/stl-spoofdiag
sudo chmod 700 /root/stl-spoofdiag
# Example uploaded path:
# /root/stl-spoofdiag/spoofdiag-vX.Y.Z_linux_amd64.tar.gz
# Verify trusted release identity BEFORE unpacking/installing.
# Extract ONLY into a new tool-specific temporary staging subdir,
# verify manifest+checksum+archive paths, then run install-offline.sh --verify.
# Run install-offline.sh --install only after reviewing the exact plan.
```

Don't invent a bare install command tied to a nonexistent published release. Once scripts exist, this page must include exact verified commands with no placeholders except the user-chosen existing archive name.

The installed executable offers `version`, `menu`, `preflight`,
`plan`, `sources`, `report` and `lab`. A general field transport
is not implemented; `reports`/`diagnostics` are not separate CLI verbs. The interactive menu is a presentation layer over the same engine as CLI and versioned JSON machine output.

## 5. Upgrade, rollback, uninstall

- Offline archive remains in `/root/stl-spoofdiag/`; an update stages a new complete version and switches tool-owned executable identity **only after** all integrity and compatible schema checks pass.
- Previously installed versions remain in an explicitly tool-owned release directory. `--rollback --to EXACT_STORED_VERSION` verifies that stored executable's checksum and manifest before atomically switching `current`; it does not fetch packages. `--uninstall` preflights every recognized file and refuses foreign artifacts, then removes only verified tool binary/link assets and retains private state.
- Refuse foreign/unverifiable installation resources and incomplete ownership metadata. Stop only **tool-owned** short-lived sessions; never kill arbitrary named processes.
- Protect config/private material as explicit operator-owned state. Current `--uninstall` always retains `/etc/stl-spoofdiag` and `/var/lib/stl-spoofdiag`; deleting them is a separate deliberate manual operator action, not an automated purge.
- No automatic updates, cron jobs, persistent listeners or unattended field tests by default. Repeat install/update/remove on disposable guests and verify recovery after injected failures.

## 6. Release procedure and acceptance

Build separately for linux/amd64 and linux/arm64; reproducible source/manifest + strict archive contents allowlist and test asset checksum. Install artifacts on fresh supported offline VM, run menu/preflight, exercise bounded *private-only* two/three-VM kernel lab, negative permission and packet-capture evidence, report export/import, update/rollback/uninstall, verify unchanged STL and host network.

Release workflow is **independent** of `scripts/build-artifacts.sh` and `scripts/install.sh` for STL; do not edit the canonical embedded Go/installer byte-identity pair. Publication/merge require the independent review, exact accepted source SHA, CI and Owner release gate. Until then, `LOCAL_CANDIDATE_ONLY` / `NOT_RELEASED`.
