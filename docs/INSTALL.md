# Install, update, and uninstall (Issue #11)

STL is **pre-release** until an authorized, tagged GitHub release is actually
published. The commands below use a placeholder `vX.Y.Z`; replace it with an
**existing** released tag after publication. No installer runs during a clone,
build, or ordinary `go test`.

## Supported deployment shape

- Linux amd64 or arm64; Ubuntu 22.04+ and Debian 11+ are supported installer targets. Derivatives are not assumed compatible.
- Root-owned `/usr/local/bin/stl` is the single executable.
  `/usr/local/bin/stlink` is a relative symlink to `stl`, not another binary.
- Installer bookkeeping is root-owned in
  `/usr/local/lib/simple-tun-link/install-record` (plus a retained lock file).
- The canonical Engine still owns every Link, `/var/lib/simple-tun-link`,
  network resource, and `simple-tun-link-restore.service`. The installer does
  **not** manage those resources or install a second systemd service.
- On real `/usr/local` installs/updates, the installer identifies the OS from
  `/etc/os-release` as data, validates Ubuntu >=22.04 or Debian >=11, checks
  installed APT package identities via `dpkg-query`, and installs ONLY missing
  distro packages with `apt-get` from the host's existing repositories.
  Default `--backends native` selects `iproute2` + `iptables` for GRE/IPIP.
  `--backends native,wireguard` adds `wireguard-tools`;
  `--backends native,ipsec` adds `charon-systemd`,
  `strongswan-swanctl` and `libstrongswan-standard-plugins`
  (OpenSSL/GCM algorithm backends, not guaranteed by `--no-install-recommends`).
  `--backends all` opts in to every backend dependency.
- Installing `charon-systemd` can enable/start the daemon. To preserve foreign
  VPN service ownership, optional IPsec dependency installation requires
  explicit `--backends ipsec` / `--backends all` selection and refuses an
  existing `strongswan-starter` or `charon-systemd` package whenever an IPsec package change is required, or a running
  `charon` daemon. The installer NEVER
  loads/removes IKE configs, changes firewall/routes or enables global tuning.
- Only missing packages are requested; the installer never upgrades the entire
  host or edits repositories. Host APT package installation is not covered by
  the STL binary rollback transaction, and STL uninstall never uninstalls host
  packages. On error it reports the partial-package-management limitation.
- Offline `--bundle --prefix /private/test` installs cannot install real host
  packages. Use the non-mutating `requirements` command to preview the exact
  packages before invoking privileged install.
- Debian 11 LTS security support ended 2026-08-31. The requested minimum
  remains supported **if working, signed, maintained APT package repositories
  are configured on the host**, but the default Bullseye security mirror has
  returned HTTP 404 for previously indexed packages since LTS expiry. The
  installer fails with a specific error rather than disabling signature/expiry
  checks, downgrading packages or silently rewriting repositories. Choose
  Debian 12+ or an independently maintained Debian 11/ELTS source.
- Kernel modules, iproute2 XFRM features and strongSwan runtime behavior remain
  capability-gated; distro/package detection does not prove real tunnel traffic
  or release qualification (Issue #12).

## Install from an official released tag

Read the [installer source](../scripts/install.sh) before running it as root.
For a single-command install, with an explicit released tag:

~~~sh
bash -c 'set -euo pipefail; umask 077; t=$(mktemp); trap '\''rm -f -- "$t"'\'' EXIT; curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 -o "$t" https://raw.githubusercontent.com/ach1992/simple-tun-link/vX.Y.Z/scripts/install.sh; bash -n "$t"; sudo bash "$t" install --version vX.Y.Z'
~~~

The default one-command example installs only the native GRE/IPIP
dependencies. To provision all backend packages automatically, append
`--backends all` to the `sudo bash "$t" install --version vX.Y.Z` invocation
in that wrapper, after checking existing strongSwan services. A fetched
installer cannot bootstrap its own download client: `curl` is needed for the
one-command wrapper on the host before package provisioning starts.
To preview without changing anything:
```sh
bash scripts/install.sh requirements --backends all
```

The one-command wrapper completes and syntax-checks the exact-tag installer download into a private temporary file **before invoking sudo**; a partial/failed download is never streamed into a privileged shell. The downloaded installer then fetches `SHA256SUMS`, `BUILD-MANIFEST.txt`, `LICENSE`, and the one
architecture-specific `stl_vX.Y.Z_linux_<arch>` executable from the **fixed
project GitHub release URL** over HTTPS. It checks the relevant SHA-256 entries,
MIT/commit/version metadata, and the executable's `version --json` identity
**before** publication. No caller-provided download URL is accepted.

For `--bundle` system-wide installs, use a private administrator-controlled
bundle source; bundle-local checksums do not authenticate a hostile source.

SHA-256 checksums protect against accidental damage/mismatched bytes, **not**
against a compromised release account or replacement of checksums and binaries
together. Trust the GitHub project/tag and review the script; pinned tags and
HTTPS do not make the checksum file an independent signature.

For an auditable two-step alternative, download the script from the exact tag
into a private location, inspect it, then run:

~~~sh
sudo bash ./install.sh install --version vX.Y.Z
stl version --json
stlink version --json
~~~

No public tag/release is being created by these instructions.

## Update

The interactive `stl menu` Update task is a **guided, read-only handoff**:
it accepts only a safe published-version tag and displays the pinned release
and installer source. It never downloads or runs a remote script itself.
The actual replacement is owned exclusively by this separately verified
installer; the menu does not duplicate any install/update lifecycle.

Download the installer from the **intended new released tag**, inspect it, and
run `sudo bash ./install.sh update --version vX.Y.Z` (or use the same one-command
pattern with `update`). The installer refuses a foreign or locally modified
`stl`, an unrecognized/missing `stlink`, or malformed installation metadata.

- Each installer is serialized with `flock`.
- A verified executable is staged on the **same filesystem** as canonical
  `stl`; `mv -T` publishes it by atomic rename, never truncating in place.
- The old executable is retained in a private transaction directory until
  the new binary, alias, and ownership record have been checked and synced.
  Ordinary post-rename failures attempt identity-guarded restoration of the
  previous binary/record. Uncertain recovery **fails with an explicit path**
  to retained private material, never reports success.
- Update does not restart systemd, change the kernel, or reapply Links.
  Runtime/backend/state compatibility must be reviewed before each release.

A fatal interruption (power loss, `SIGKILL`) between rename and record sync
may require manual reconciliation. The installer synchronizes prepared binaries and rollback sources before
publication, syncs canonical identities and directories after rename, and
retains a durable `COMMITTED` transaction journal for safe subsequent retirement.
At the next invocation, it removes a committed journal only if the current
binary, alias and ownership record still prove the recorded operation. A
non-committed journal always requires explicit manual reconciliation.

The `COMMITTED` v1 journal contains **exactly three newline-terminated
fields**, in this order: `status=committed`, `operation=install|update|uninstall`,
and `sha256=<64 lowercase hexadecimal characters>`. The Installer and the
Engine maintenance gate both reject incomplete, malformed or identity-
inconsistent journals; the marker filename alone is not commit proof.
For install/update, the recorded hash must match both the current canonical
executable and its valid installer ownership record, with the exact
`stlink -> stl` alias. For uninstall, all three installed identities must
be absent. After securing a separate durable recovery copy, uninstall
**unlinks** the canonical executable rather than moving its live inode into
the recovery directory; a running stale process therefore retains the
`stl (deleted)` identity and must be denied before any Engine mutation.

If the installer retains a
`/usr/local/bin/.stl-install.*` recovery directory, **do not delete or blindly
restore it**: inspect the installed binary hash, installation record, unit and
Links, then choose an explicit recovery/roll-forward. Check executable identity
again before retrying. Unreconciled `.stl-install.*` recovery directories block all
further installer transactions; inspect and reconcile the binary, record and
retained evidence before explicitly retiring any recovery material.
Never blindly delete a journal, or reuse the recorded old binary without
checking state schema and Engine compatibility.

## Uninstall: never tear down live Links implicitly

The interactive `stl menu` Uninstall task only guides a human operator.
When saved Links remain it lists their stable IDs and the existing
`stl link remove` command, but never performs removal or prints
untrusted display names. With no saved Links it explicitly says that
the count is **not** proof of safe uninstall; the installer still performs
the canonical Go preflight under exclusive maintenance locking.

First quiesce concurrent Link operators and inspect the saved Links:

~~~sh
sudo stl link list --json
~~~

For each existing Link ID, explicitly inspect it, then remove it through
`stl link remove <link-id> --confirm <link-id>`; the canonical Engine owns
resource and persistence cleanup. Verify no Links remain. A failed removal,
ambiguous state, or remaining `simple-tun-link-restore.service` requires
resolution via the Link/Engine workflow **before** uninstall. Do **not** delete
interfaces, route/firewall rules, or the restore unit manually as a shortcut.

After the Link state is proven empty and the Engine-owned restore unit is gone:

~~~sh
sudo bash ./install.sh uninstall
~~~

Uninstall calls `stl maintenance pre-uninstall --json` under the exclusive
maintenance lock. That Go command distinguishes a never-used host from a
missing state snapshot in an existing root and uses the canonical systemd
installed/enabled checks. Missing, malformed, symlinked or otherwise ambiguous
state fails closed. Uninstall removes only the hash-verified installer-owned canonical executable,
its exact `stlink -> stl` symlink, and the installer ownership record. It keeps
the installer lock and does **not** delete `/var/lib/simple-tun-link`, other
systemd units, network resources, arbitrary `stl` files, or host packages.
This deliberate separation prevents an installer from inventing a second
Link-removal lifecycle. Empty historic state may be archived or retired later
through a distinct explicit audited operation, not silent uninstall.

If any state read or ownership check is inconclusive, uninstall fails closed.
The installer holds an **exclusive maintenance flock** across the read-only
canonical Go pre-uninstall check and entire uninstall transaction. Ordinary
Engine mutations hold shared locks and stale queued binaries are rejected after
update/uninstall. Multiple unrelated Links still mutate concurrently.

## Offline/disposable validation

~~~sh
bash scripts/test-install-requirements.sh
bash scripts/test-install.sh
~~~

The nonprivileged test uses disposable prefixes and locally generated fake
release bundles. It covers checksum refusal, foreign ownership, install,
update/idempotence, post-swap failure recovery, modified-binary refusal,
Link-presence refusal, uninstall and uninstall failure recovery. It neither
accesses production releases nor performs privileged networking/systemd
operations. To test an actual build bundle without publication:

~~~sh
bash scripts/install.sh install --bundle /path/to/build-bundle --prefix /path/to/private/test-prefix
~~~

The test prefix must already contain `bin` and `lib` directories. An offline
snapshot bundle is not a supported public release. Do not claim these fake
bundle tests prove arm64 execution, real distro support, service restart,
firewall safety, or kernel traffic. Issue #12 owns that release-quality E2E
proof. A real public release/tag is a separate human authorization gate.
