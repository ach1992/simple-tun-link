# Self-hosted HTTPS mirror (no GitHub access on the destination)

An STL mirror is a **static directory** hosted on an operator-controlled HTTPS
domain, for example `https://stl.example.com`. The destination server needs
only that domain, a trusted TLS certificate, and any already configured,
appropriately signed OS package repositories. It does **not** need
`github.com`, `api.github.com`, `raw.githubusercontent.com`, Git or
any other international download service for the default STL core install
or Update. No mirror service or server-side script runtime is required.

The mirror is an **alternative distribution transport**, not a different STL
installer: `scripts/install.sh` still owns installation, maintenance locking,
existing-install ownership checks, APT qualification, rollback, and installed
binary metadata. Unlike a blind mirror URL switch, both the canonical
installer and its release-wide `SHA256SUMS` are pinned into the generated
bootstrap before uploading anything.

## 1. Prepare files on a device that can reach GitHub

1. On a **trusted Internet-connected** device, obtain an exact **immutable
   published Stable** release from
   [the official GitHub Releases page](https://github.com/ach1992/simple-tun-link/releases).
   Obtain the two `stl_vX.Y.Z_linux_*_local-install.tar.gz` archives, the two
   matching `stl_vX.Y.Z_linux_amd64/arm64` binaries, `LICENSE`,
   `BUILD-MANIFEST.txt`, `stl-bootstrap.sh`, and `SHA256SUMS`
   from the **same exact release**.
2. Independently confirm the GitHub publisher, tag and release identity.
   Record the SHA-256 digest of the authentic, **official**
   `SHA256SUMS` file as the trusted checksum. A checksum downloaded from
   the *same untrusted mirror* is not independent authentication.
3. Check out the **exact published source/tag** containing this version of
   `scripts/prepare-mirror.sh`, `scripts/quick-install.sh`, and
   `scripts/install.sh`. The generator compares these files against the
   officially hashed bootstrap and archived installer, and refuses mixed
   release/source versions. Then run (replace paths, version and digest):

```bash
sha256sum /trusted/stl-release/SHA256SUMS

bash scripts/prepare-mirror.sh \
  --tag vX.Y.Z \
  --release-dir /trusted/stl-release \
  --trusted-sums-sha256 TRUSTED_64_CHARACTER_HEX \
  --url https://stl.example.com \
  --output /new/stl-webroot
```

This generator verifies the supplied trusted manifest digest, each required
official asset, the tag and source-commit identity, and that both officially
hashed archives contain the **same canonical installer**. It refuses
repackaged/incomplete or legacy releases without mirror support. It does
not fetch from the Internet, write into an existing output, install STL or
change networking. Basic self-hosted Mirror support first shipped in
reviewed Stable `v0.1.22`; the hardened bootstrap and installed local/Mirror
Update selector first shipped in `v0.1.23`. Historical `v0.1.21` assets
remain unchanged and predate Mirror support.

## 2. Upload the generated static tree to your HTTPS web root

Upload **the contents** of `/new/stl-webroot/` to the document root for
`https://stl.example.com`, preserving relative paths:

```text
https://stl.example.com/install.sh
https://stl.example.com/releases/vX.Y.Z/install.sh
https://stl.example.com/releases/vX.Y.Z/stl-bootstrap.sh
https://stl.example.com/releases/vX.Y.Z/SHA256SUMS
https://stl.example.com/releases/vX.Y.Z/BUILD-MANIFEST.txt
https://stl.example.com/releases/vX.Y.Z/LICENSE
https://stl.example.com/releases/vX.Y.Z/stl_vX.Y.Z_linux_amd64
https://stl.example.com/releases/vX.Y.Z/stl_vX.Y.Z_linux_arm64
https://stl.example.com/releases/vX.Y.Z/stl_vX.Y.Z_linux_amd64_local-install.tar.gz
https://stl.example.com/releases/vX.Y.Z/stl_vX.Y.Z_linux_arm64_local-install.tar.gz
```

The root `install.sh` contains exact version, canonical-installer digest,
trusted release `SHA256SUMS` digest, and the configured mirror HTTPS URL.
**Its own SHA256** is computed from the validated private staging artifact
**before** publication and then printed by `prepare-mirror.sh` for the
independently pinned first-hop command; the published path is never rehashed
to create a trust anchor. The output parent must be controlled by the
preparing administrator and not group/other writable. Protect this
output as part of your trust anchor.
Only after **all** versioned files are present and accessible should the
operator publish or replace the root `install.sh`. Keep old version
directories if active clients or rollback workflows still need them. Do not
rewrite a previously advertised version's files. Use valid TLS; remove any
HTML login pages, redirects, Cloudflare challenges, or authenticated
downloads from these static paths.

From a server that **can reach the mirror**, verify its first-hop response
is a shell script, not HTML, before running anything:

```bash
curl -fsS https://stl.example.com/install.sh | head -n 3
```

## 3. Clean install and explicit Update

### Use a Mirror you independently trust

STL does **not** prescribe a default or shared HTTPS Mirror endpoint. Any
operator can prepare and host the **same verified official Stable assets**
under their own HTTPS domain by following this runbook. Supply your own
Mirror URL and the **independently prepared** first-hop SHA256. A Mirror is
never used as an automatic fallback.

As of 2026-11-12, the latest immutable official Stable is
[v0.1.24](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.24).
The operator must regenerate the version-pinned Mirror bootstrap and its trust
pin for each new release; a digest for an older version cannot authenticate
a newer `install.sh`. Publication of a release on GitHub does not
automatically update any independently hosted Mirror.

Maintainer-specific publication checks and historical release pins are
recorded in [installer/distribution Issue #146](https://github.com/ach1992/simple-tun-link/issues/146),
not as a default endpoint in this operator runbook. Neither a successful
Mirror download nor an isolated test proves a fresh physical installation
with GitHub blocked or signed regional APT recovery.

On an eligible Linux host that reaches **only your mirror**:

**Fresh installation:**

```bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM:-dumb}" ${NO_COLOR+NO_COLOR=1} /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fsSs --proto "=https" --max-redirs 0 --connect-timeout 10 --max-time 45 https://stl.example.com/install.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && { [ "$(/usr/bin/sha256sum < "$f")" = "TRUSTED_BOOTSTRAP_SHA256  -" ] || { echo "STL: mirror bootstrap SHA256 mismatch" >&2; exit 1; }; } && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl
```

**Update of an existing installer-owned STL:** On an **already installed**
release that supports the new `stl update` CLI, the short, independently
pinned API-free command is:

```bash
sudo stl update --mirror https://stl.example.com/install.sh --sha256 TRUSTED_BOOTSTRAP_SHA256
```

On installed STL `v0.1.23` or later containing the source-selector menu,
operators may instead open `sudo stl menu` → **Update → Trusted HTTPS
mirror**, enter `https://stl.example.com/install.sh` and the independently
verified `BOOTSTRAP_SHA256`, review them and type `UPDATE`. This is
the same bounded `stl update --mirror` flow, **not** a second installer.
The selected Mirror path does not query GitHub, remember Mirror authority
or install optional helpers. The older published `v0.1.22` does not have
this menu or CLI; use the guarded fallback below until a verified upgrade.

Supply the exact `BOOTSTRAP_SHA256` from the **trusted preparation machine**,
not a checksum read back from the Mirror. This CLI was first published in
Stable `v0.1.23`; an older installed binary does not gain it automatically.
For **older installations** (including published `v0.1.22`), use the existing generated, independently
pinned `UPDATE_COMMAND` instead:

```bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM:-dumb}" ${NO_COLOR+NO_COLOR=1} /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fsSs --proto "=https" --max-redirs 0 --connect-timeout 10 --max-time 45 https://stl.example.com/install.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && { [ "$(/usr/bin/sha256sum < "$f")" = "TRUSTED_BOOTSTRAP_SHA256  -" ] || { echo "STL: mirror bootstrap SHA256 mismatch" >&2; exit 1; }; } && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl update
```

These examples require replacing `TRUSTED_BOOTSTRAP_SHA256` with the
`BOOTSTRAP_SHA256` printed by `prepare-mirror.sh` on your **trusted
preparation device**. The preparer also prints the exact ready-to-paste
`INSTALL_COMMAND` and `UPDATE_COMMAND`; prefer those and keep the printed
digest in a trusted record, not a checksum fetched from the untrusted target
mirror. All 64 hexadecimal characters must match. **Do not execute the
placeholder as-is.** A replaced or compromised mirror first-hop script fails
SHA256 before its first instruction executes.

These generated commands preserve the invoking terminal's `TERM` and the
**presence** of `NO_COLOR` for post-success menu presentation, including
a non-root `sudo` handoff. If `NO_COLOR` was unset, the command does not
invent it; an empty but present value still disables ANSI. Neither flag
permits inheriting shell startup hooks, unrestricted PATH or other runtime
environment into the root installer. A missing/dumb terminal type remains
non-ANSI.

The commands begin with `/usr/bin/env -i` before Bash, reject inherited
`BASH_ENV`, exported functions and unsafe PATH lookups, and use the absolute
system SHA256 binary for the first-hop pin. If the target needs a private CA
or reviewed HTTPS proxy, insert `CURL_CA_BUNDLE=/absolute/trusted/ca.pem`,
`HTTPS_PROXY=...` and/or `NO_PROXY=...` **after `PATH=...` and before
`/bin/bash`**. Only these selected transport values carry into the
privileged phase; avoid putting proxy passwords in commands/history, and
do not use `sudo -E`. Keep APT distribution signing and its separate proxy
configuration intact. This root-private snapshot/clean-env behavior first
shipped in `v0.1.23`, not in the historical `v0.1.22` assets.

These commands download the **whole** first script into a private temporary
file with a 45-second deadline and a 128-KiB streaming limit (including
chunked responses), then require exact first-hop SHA256 and Bash syntax.
The temporary file is removed on failure and success. They do not rely on
`curl --max-filesize`, which does not enforce an unknown-length transfer
limit on older supported curl versions. A bare `curl | bash` is
shorter but loses the first-hop completion guarantee; do **not** use it
for an administrative installation. Running `install` against a different
existing verified STL will **not** silently upgrade; it prints a specific
Update instruction. Same-artifact reinstall remains an idempotent no-op.

**Offline Update uses the Mirror command or selected menu choice above.**
Starting with installed `v0.1.23`, the menu separately offers Official
GitHub releases, Verified local file and Trusted HTTPS Mirror. **Only**
the official release picker queries GitHub's API; the two pinned offline
choices work on Mirror-restricted hosts. An older installed `v0.1.22`
menu still requires GitHub for its original picker and must use the
guarded manual Update fallback. No Mirror URL is silently persisted as
a future update authority.

The mirror bootstrap fetches only `https://stl.example.com/releases/vX.Y.Z/`
files, with **no GitHub/API fallback or redirects**. It verifies the canonical
shell source digest before executing it. **Downstream Mirror transfers are
also bounded while streaming**, not only the initial 128-KiB first hop:
the canonical `install.sh` is limited to 1 MiB, `SHA256SUMS`,
`BUILD-MANIFEST.txt` and `LICENSE` to 64 KiB each, and the
architecture-specific STL executable to 128 MiB. The receiver uses the
declared-size curl safeguard plus an independent streaming byte cap,
including for chunked responses and older supported curl versions. An
oversized, incomplete or mismatched download fails before replacing an
installed binary; private incomplete download stages are cleaned without
discarding legitimate **COMMITTED** transaction-recovery journals.
The canonical installer verifies
the release checksum manifest against the **independently pinned** digest,
then validates the requested architecture's executable, manifest and
version/commit identity, and the existing STL ownership/transaction rules.
The optional WSS/QUIC companions are **not** silently installed.

After installation, check:

```bash
sudo stl version --json
sudo stl menu
```

## 4. Real offline limitations and safe failure behavior

- **OS prerequisites:** If `iproute2`, `iptables`, `kmod`,
  `wireguard-tools` or other *selected* packages are missing, Debian/Ubuntu
  APT needs an accessible **signed and trusted** distro repository (possibly
  a domestic provider or local APT mirror). STL reuses installed packages and
  does not overwrite APT sources, disable signature verification or secretly
  contact an international fallback. If packages cannot be obtained, install
  correctly fails with a diagnosis; a mirror of STL binaries does not mirror
  Debian/Ubuntu packages.
- **Optional WSS and QUIC:** The extra `wstunnel` and `Hysteria`
  companions are separately version/hash-pinned. The core bootstrap does
  not install them. For a fully isolated host that needs these transports,
  independently verify and transfer the official companion files via
  an accessible location, then select the **local file** path in their
  guided installation. Do not expect their optional online download path
  to work when foreign Internet is blocked.
- **Trust:** Control HTTPS/TLS and who may upload or replace scripts.
  The trust anchor is the **operator's independently verified official release
  digest and the prepared bootstrap**, not a self-reported checksum served
  alongside arbitrary mirror content. A compromised root `install.sh`
  could execute arbitrary shell; HTTPS and checksums alone are not an
  independent publisher signature. Inspect and authenticate the uploaded
  bootstrap, restrict write access, and test it before running as root.
- **No silent fallback:** A missing file, wrong architecture, corrupted
  installer, checksum mismatch or untrusted TLS fails closed. Do not
  compensate by disabling TLS verification or package signatures.
- **No environment changes implied:** Generating the tree does not provision
  `stl.example.com`, modify a real DNS record, deploy a server or authorize
  a physical-host installation.

Run the offline mirror regressions with `bash scripts/test-mirror-install.sh`,
and the ordinary official Stable regressions with
`bash scripts/test-quick-install.sh`.
