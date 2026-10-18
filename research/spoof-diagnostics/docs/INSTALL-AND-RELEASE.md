# Independent installer, offline package and release contract

**Partially implemented contract.** A buildable standalone offline Go archive and a verifying/idempotent install script exist for local release-candidate testing; owned-path/symlink negative controls were exercised in disposable test roots. **No public tool release or validated online one-liner exists.** Upgrade, rollback and uninstall were exercised on disposable roots with foreign-file refusal and private-state preservation; independent publisher signature verification and full failure-injected fresh-guest recovery remain acceptance gaps; do not mistake current install smoke for full lifecycle acceptance.

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

The installer must require **zero** `apt`, `pip`, `curl`, `wget`, Go toolchain or DNS. On supported Linux, `/bin/sh`, `tar`, `sha256sum`, file/permissions utilities and a compatible kernel are explicit baseline prerequisites; verify before changing files. Build/download prerequisites are **CI-side**, not host-side. No external repository/package setup is allowed.

## 3. Online one-line installation uses the SAME offline engine

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

The *installed executable* must offer `version`, `menu`, `preflight`, `plan`, `sources`, `reports` and `diagnostics`; future field-probe actions remain permission gated. The interactive menu is a presentation layer over the same engine as CLI and versioned JSON machine output.

## 5. Upgrade, rollback, uninstall

- Offline archive remains in `/root/stl-spoofdiag/`; an update stages a new complete version and switches tool-owned executable identity **only after** all integrity and compatible schema checks pass.
- Previously installed versions remain in an explicitly tool-owned release directory. `--rollback --to EXACT_STORED_VERSION` verifies that stored executable's checksum and manifest before atomically switching `current`; it does not fetch packages. `--uninstall` preflights every recognized file and refuses foreign artifacts, then removes only verified tool binary/link assets and retains private state.
- Refuse foreign/unverifiable installation resources and incomplete ownership metadata. Stop only **tool-owned** short-lived sessions; never kill arbitrary named processes.
- Protect config/private material as explicit operator-owned state. Current `--uninstall` always retains `/etc/stl-spoofdiag` and `/var/lib/stl-spoofdiag`; deleting them is a separate deliberate manual operator action, not an automated purge.
- No automatic updates, cron jobs, persistent listeners or unattended field tests by default. Repeat install/update/remove on disposable guests and verify recovery after injected failures.

## 6. Release procedure and acceptance

Build separately for linux/amd64 and linux/arm64; reproducible source/manifest + strict archive contents allowlist and test asset checksum. Install artifacts on fresh supported offline VM, run menu/preflight, exercise bounded *private-only* two/three-VM kernel lab, negative permission and packet-capture evidence, report export/import, update/rollback/uninstall, verify unchanged STL and host network.

Release workflow is **independent** of `scripts/build-artifacts.sh` and `scripts/install.sh` for STL; do not edit the canonical embedded Go/installer byte-identity pair. Publication/merge require the independent review, exact accepted source SHA, CI and Owner release gate. Until then, `LOCAL_CANDIDATE_ONLY` / `NOT_RELEASED`.
