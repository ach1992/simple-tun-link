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
change networking. The first version supporting this facility must be
published after its normal independent review/release gates; **v0.1.21 does
not contain this new mirror-aware canonical installer**.

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

On an eligible Linux host that reaches **only your mirror**:

**Fresh installation:**

```bash
bash -c 's=$(curl -fsS https://stl.example.com/install.sh) && test -n "$s" && bash -n <<<"$s" && bash -c "$s" stl "$@"' stl
```

**Update of an existing installer-owned STL:**

```bash
bash -c 's=$(curl -fsS https://stl.example.com/install.sh) && test -n "$s" && bash -n <<<"$s" && bash -c "$s" stl "$@"' stl update
```

These one-liners download the **whole** first script successfully and
syntax-check it before running any part of it. A bare `curl | bash` is
shorter but loses the first-hop completion guarantee; do **not** use it
for an administrative installation. Running `install` against a different
existing verified STL will **not** silently upgrade; it prints a specific
Update instruction. Same-artifact reinstall remains an idempotent no-op.

**Offline Update uses the mirror command above.** The existing built-in
`sudo stl menu` → `Update` screen still queries GitHub's releases API,
so it is **not available** on a host restricted to your mirror. The ordinary
menu remains usable for other tunnel-management operations. No mirror URL
is silently persisted as a future update authority.

The mirror bootstrap fetches only `https://stl.example.com/releases/vX.Y.Z/`
files, with **no GitHub/API fallback or redirects**. It verifies the canonical
shell source digest before executing it. The canonical installer verifies
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
