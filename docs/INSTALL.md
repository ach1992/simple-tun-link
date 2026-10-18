# Install, update, and uninstall

For normal two-server setup start with the [README](../README.md).
This runbook documents **current operations and recovery safeguards**,
not the history of earlier release candidates. The active Stable
release and its exact tag/commit are resolved from
[GitHub Releases](https://github.com/ach1992/simple-tun-link/releases/latest)
and verified with `stl version --json`, `BUILD-MANIFEST.txt` and
`SHA256SUMS`; do not hardcode an old version as "current".

A public release and a disposable CI pass are not evidence that a
specific real pair of WAN/NAT hosts has passed field acceptance; that
independent Owner gate is tracked in
[Issue #93](https://github.com/ach1992/simple-tun-link/issues/93).
Commands using `vX.Y.Z` require a **real published** tag.

## Installation and runtime ownership

- Supported installer environments are listed in
  [SUPPORTED-ENVIRONMENTS.md](SUPPORTED-ENVIRONMENTS.md): Linux amd64/arm64,
  initially Ubuntu 22.04+ and Debian 11+, with actual capability checks.
- The supported installed executable is the root-owned
  `/usr/local/bin/stl`. `/usr/local/bin/stlink` is an exact relative
  alias to that executable, not a separate product. The installer
  records its ownership in
  `/usr/local/lib/simple-tun-link/install-record`.
- The **Engine**, not the binary installer, owns Links, private State
  (`/var/lib/simple-tun-link`), kernel resources, and the
  `simple-tun-link-restore.service` lifecycle. The native IPsec
  provisioner owns its separately attested private strongSwan runtime
  under the same Engine/maintenance authority; neither component
  may adopt a foreign unit.
- The installer selects only approved missing packages from the
  configured signed distro repositories. The default native GRE/IPIP
  set needs `iproute2`, `iptables` and `kmod`; WireGuard adds
  `wireguard-tools`; IPsec may need `charon-systemd`,
  `strongswan-swanctl` and
  `libstrongswan-standard-plugins`. `--backends all`
  selects prerequisites, **not** permission to bypass existing
  IPsec service/package safety constraints.
- The canonical direct installer `install`/`update`/`prepare`
  interface never performs uncontrolled service takeover. If
  missing IPsec packages cannot be safely installed in that
  context, it refuses before APT; use the guided, separately
  confirmed IPsec Create/Advanced flow on a positively qualified
  supported host. It plans the complete signed distro package
  transaction and prepares the private runtime only after fresh
  `PREPARE`. Actual Link creation still requires separate `YES`.
  The workflow can disclose and normalize a *newly introduced*
  vendor service under exact transaction attribution; do not
  describe this as atomically rolled back with Link creation.
- A **pre-existing official distro** `strongswan.service` may
  be stopped/disabled only after independently proving its precise
  package/runtime/service/port identity, warning of immediate VPN
  disruption, and obtaining a distinct exact
  `STOP strongswan.service` confirmation. The full eligibility
  check is repeated under the exclusive maintenance lock.
  A private service `LOAD=not-found/inactive/dead` placeholder
  is not a real service conflict. Unknown/other foreign services,
  config, ports or incomplete APT state require manual remediation
  and `RECHECK`, never a generic PREPARE takeover.
- The installed menu reuses a byte-identical bundled canonical
  installer to check selected missing prerequisites. Native/WireGuard
  preparation and qualified kernel-module loading are opt-in, not
  automatic effects of viewing a menu or running diagnostics.
  Missing selected modules can be loaded only under their verified
  scoped approval and safely restored for a committed Link; STL
  does not globally install a persistent modules-load rule or
  auto-unload drivers potentially used by other software.
- Signed package-manager mutations can persist after an interrupted
  transaction. No whole-host upgrade, APT trust bypass or repository
  rewriting is permitted. `uninstall` does **not** remove distro
  packages, State, credentials or unrelated units/resources.
- When another process holds `/var/lib/apt/lists/lock`, the canonical
  installer makes at most **12 APT index-refresh attempts**, with up to
  **55 seconds of explicit retry sleeps** (excluding the time spent inside
  individual APT invocations), **only** for positively identified exclusive
  lists-lock diagnostics. Unexpected warnings or repository failures stop
  immediately. It neither deletes locks nor terminates other
  APT processes. `DPkg::Lock::Timeout=60` is used for package installation
  but does not replace the special lists-lock retry. If the lock persists,
  wait for the legitimate package manager to finish and rerun the intended
  `install` or `prepare` operation. Repository signing, broken sources,
  unsupported dependency plans, and uncertain package transactions still
  stop immediately. Do **not** run `apt upgrade` simply to clear a lock.

To view missing prerequisites without mutation, use the canonical
installer `requirements` action from a verified release or source
checkout. A qualified already installed host can use the verified
installer's `prepare` action for selected **supported** prerequisites:

~~~sh
bash scripts/install.sh requirements --backends all
sudo bash /path/to/verified/install.sh prepare --backends wireguard
~~~

Offline `--bundle --prefix /private/test` installs do not mutate
real system packages. On Debian 11, working maintained/signed APT
repositories are required after its LTS expiry; prefer supported
maintained newer releases where feasible. Never disable signature
validation to make an unsupported repository pass.

## Read-only diagnosis of setup or persistence failure

If Create or Import reports a failure at `persistence`, an unconfirmed
rollback or an unfamiliar systemd state, **do not infer that the tunnel
traffic, GRE, peer firewall or packet routing is at fault**. Both
workflows depend on the same owned restore-unit transaction.

On the affected, authorized host gather only safe observations:

~~~sh
stl version --json
ps -p 1 -o comm=
systemctl --version | head -n 1
systemctl is-enabled simple-tun-link-restore.service
printf 'is-enabled exit=%s\n' "$?"
systemctl show simple-tun-link-restore.service --no-pager -p LoadState -p UnitFileState -p FragmentPath -p Result
namei -l /usr/local/bin/stl
namei -l /etc/systemd/system/simple-tun-link-restore.service
~~~

Capture the exact return status **and stdout**: on some supported
systemd versions a missing restore unit yields exit 1 with empty
stdout and must be independently confirmed with
`LoadState=not-found` plus empty unit-file/fragment properties.
An incomplete/failed read, foreign unit or unexpected root-owned
path does not become an absent resource. A successful cleanup
return without independent host-state verification may still mean
rollback is **unconfirmed**.

Never manually overwrite, enable, disable or delete an uncertain
systemd unit, rewrite private State, flush network rules, or blindly
repeat a mutating operation. Refer to
[OPERATOR-RECOVERY.md](OPERATOR-RECOVERY.md) and provide
redacted observations only—never private Setup Links or keys.

## Private receiver handoffs and backup

Guided WireGuard/IPsec Create retains the original SENSITIVE
receiver Setup Link separately in
`/var/lib/simple-tun-link/receiver-handoffs/` with private
`0700` directory and `0600` Link-identity-bound file.
Only a fresh real-terminal `SHOW` displays a retained offer;
`DELETE` independently retires just that offer and not the
active Link or local credentials. Link removal/uninstall does
not silently delete retained receiver secrets. Explicit
noninteractive creators use their own operator-specified private
`--output` path; the menu does not invent or search those files.

A consistent operator-owned backup must include private State,
the separate credentials store and retained handoffs where needed.
Do not share these bytes in Issue/PR/CI logs, and do not wildcard
delete leftover protected temporary material.

## Install from an official released tag

**Source trust:** a tag name, successful `bash -n`, HTTPS or
a checksum from the same downloaded release is not an independent
signature of the publisher. Before root execution, confirm the
official tag's immutable publication, source commit and
`BUILD-MANIFEST.txt`, inspect the exact-tag installer and
cross-check the published artifact `SHA256SUMS`.
Unverified or mutable releases require manual review and are not
eligible for automatic privileged menu update.

Read the [installer source](../scripts/install.sh) before running it as root.
For a single-command install, with an explicit released tag **only after
the above independent source verification**:

~~~sh
bash -c 'set -euo pipefail; umask 077; t=$(mktemp); trap '\''rm -f -- "$t"'\'' EXIT; curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 -o "$t" https://raw.githubusercontent.com/ach1992/simple-tun-link/vX.Y.Z/scripts/install.sh; bash -n "$t"; sudo bash "$t" install --version vX.Y.Z'
~~~

### Permanent one-line install (latest Stable only)

The version-free `releases/latest/download/stl-bootstrap.sh` URL selects
the newest published **Stable**, excluding RC and draft releases. GitHub
serves a tag-bound immutable bootstrap asset generated from the reviewed
quick installer source. That bootstrap pins its own exact release tag
before downloading the canonical installer; it does not execute a mutable
`main` script as root. Inspect source, SHA256SUMS and official release
identity before installing. The public command stays unchanged:

~~~sh
bash -c 'set -e; umask 077; d=$(mktemp -d); trap '"'"'rm -rf -- "$d"'"'"' EXIT; curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 --connect-timeout 10 --max-time 120 -o "$d/stl-bootstrap.sh" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl-bootstrap.sh"; bash -n "$d/stl-bootstrap.sh"; bash "$d/stl-bootstrap.sh"'
~~~

The **first hop is downloaded to a private temporary directory**. Only
after curl completes successfully and the file is nonempty and passes
Bash syntax validation can it execute. Failed or partial transfers
never execute the downloaded script; the private directory is removed
on exit. The verified bootstrap then downloads the canonical exact-tag
installer and checks its syntax before
invoking root; the installer validates release SHA256SUMS, binary metadata
and ownership/rollback rules. It reattaches a real /dev/tty to open the
menu after installation. Without a TTY, use `sudo stl menu`.
Default prerequisites are native and WireGuard. To update an existing
installer-owned STL, **do not run install again**: use this equally fixed
update command:

~~~sh
bash -c 'set -e; umask 077; d=$(mktemp -d); trap '"'"'rm -rf -- "$d"'"'"' EXIT; curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 --connect-timeout 10 --max-time 120 -o "$d/stl-bootstrap.sh" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl-bootstrap.sh"; bash -n "$d/stl-bootstrap.sh"; bash "$d/stl-bootstrap.sh" update'
~~~

This selects the unchanged canonical installer update transaction,
including identity-verified existing ownership and rollback journals.
The two permanent commands use the default native,wireguard prerequisites.
An advanced operator who separately obtains and verifies the immutable
bootstrap asset may invoke it as `bash ./stl-bootstrap.sh native update`
for a narrower backend selection. **Do not append a version or extra
arguments to the public one-liners.** The installer refuses foreign or
inconsistent installed state rather than silently replacing it.
Confirm rollback-compatible
State and backups before starting.

These Stable commands contain no changing version string or variable.
The selected release still carries its exact-version manifest. No RC is
selected by `releases/latest`. On a supported, positively qualified clean
host, **interactive** IPsec PREPARE may install signed distribution packages
and provision only the verified STL-exclusive service; it will not adopt
foreign VPN resources. The bootstrap itself does not provision IPsec. The read-only
`sudo stl doctor ipsec --json` report now includes the independent
`provisioning_readiness` check on a real host. Installed but
**inactive and disabled** vendor StrongSwan is not by itself a
request to stop a service; incomplete systemd ownership, an
occupied socket/port, foreign daemon or private publication can
still block the separate STL-exclusive runtime. The IPsec
menu shows the specific failed preflight reason and safe next step.
A failed `RECHECK` does not repair anything; prefer investigating
the reported blocker over repeating `PREPARE`.
Offline bootstrap failure/PTY tests: bash scripts/test-quick-install.sh.

The longer direct canonical-installer example above selects native
GRE/IPIP prerequisites. `--backends all` requests every dependency
family, but it does **not** authorize unsafe IPsec package/service
preparation: absent qualifying strongSwan prerequisites may stop the
direct installer with a guided alternative. For qualified
interactive IPsec preparation use the reviewed PREPARE path,
with a separate actual Create confirmation. `curl` is required
for the one-command wrapper before host package preparation.

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

## Update

The menu reads official release metadata. **Only an installed executable
that already contains the newer Stable-patch menu gate** can automatically
delegate a forward same-major/minor Stable patch update. For example,
`v0.1.7` → `v0.1.8` would be eligible *if both releases existed and
the installed `v0.1.7` binary contained this fix*. These are illustrative
version numbers, not a claim that those releases have been published.

**Legacy migration (one time):** already-published `v0.1.4` and `v0.1.6`
executables contain the original **RC-only** menu gate. They cannot
automatically update Stable → Stable themselves, even if the target release
is immutable or has this fix. On such hosts, first perform one independently
verified update using the canonical manual installer instructions below.
After installing the first release that includes this newer menu, eligible
subsequent Stable patch releases can be selected directly in Update.

All automatic menu updates additionally require positively verified
`immutable:true` official releases, an installed-root/TTY check, and
fresh `UPDATE` consent. Forward same-line RC transitions remain supported.
Major/minor jumps, RC-to-Stable, downgrades, releases with
`immutable:false` or unknown immutability, and unverified exact tags use
the separately verified **manual update** route below after reviewing State
compatibility.
The menu delegates to the same canonical installer and rollback machinery;
it does not implement a second installation engine. No menu selection is an implicit
privileged mutable-tag download or a waiver of State backups.

For manual operations, verify the intended source commit and published
tag against the release manifest, verify the selected artifact against
`SHA256SUMS`, and **inspect the downloaded installer before any privileged
execution**. Never pipe a mutable-tag download directly into a root shell.
After independent verification, use
`sudo bash ./install.sh update --version vX.Y.Z`. The installer refuses
a foreign or locally modified
`stl`, an unrecognized/missing `stlink`, or malformed installation metadata.
A failed **initial install** that stopped before binary publication has no
`install-record`; calling `update` on that incomplete installation must
fail closed. Inspect both canonical executable and alias paths plus retained
recovery material. Use the official `install` action only after proving no
existing installer-owned, foreign or uncertain installation remains; never
fabricate the ownership record to make `update` pass.

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

### Persisted State v3: upgrade and safe rollback boundary

The private `/var/lib/simple-tun-link/state.json` format is versioned **separately**
from CLI request/response and Quick Link/pairing formats. State schema **v3**
adds endpoint-local managed MTU. A genuinely valid State v1/v2 document remains
readable by a v3-capable STL executable and its old Links stay **unmanaged**:
reading alone never changes State or host MTU. The first *successful State
mutation* subsequently persists v3. A legacy State document that already
contains an `mtu` field is rejected, not silently granted permission to
change a kernel interface.

**Before updating a host with committed Links**, quiesce concurrent STL
mutations, verify the intended released executable and its source manifest,
and retain a consistent, access-restricted, recoverable backup of the current
State **and any separately protected credentials** through the host's approved
backup mechanism. Never paste State, pairing URLs, keys or secrets into an
issue, terminal transcript or troubleshooting report. Keep an inventory of the
existing Link IDs and the owned restore-unit status without dumping secrets.
A successful installer update by itself neither validates a newly running
Link nor proves persistence after reboot; those are separate Engine/release
acceptance steps.

**Do not treat installer binary rollback as State rollback.** Once any new
runtime has written schema v3, pre-v3 STL executables cannot read that State
and must fail closed. On a failed new-version rollout, prefer a verified
**v3-compatible roll-forward** after reconciling installer transaction journals,
installed executable identity, protected State and systemd/Link ownership. An
older binary may be restored only if an operator has independently established
that the preserved State format and runtime/backend dependencies still match
that binary and no State mutation/uncertain publication has crossed the
compatibility boundary. Never fake a downgrade by editing `schema_version`,
stripping MTU policy fields, discarding state/credentials, or manually deleting
owned network/systemd resources. Escalate unresolved or ambiguous state rather
than reporting a successful rollback.

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
When saved Links remain, it gives a private-handoff KEEP/DELETE decision
**first** for WireGuard/IPsec; a requested `Delete receiver link` must
occur while the exact saved tunnel still exists, with fresh `DELETE`
confirmation. If retained, its separately protected receiver credential
survives both Link removal and uninstall and must be secured or later
retired by the administrator. GRE/IPIP do not require this private step.
Then the menu guides each verified `Remove this tunnel` action, **without
listing opaque IDs or display names**. With no saved Links, a zero count
is **not** proof of safe uninstall; the installer still performs
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
firewall safety, or kernel traffic. Actual backend/platform release evidence belongs to the
reproducible operations runbooks and GitHub release/check records.
Publication remains a separately authorized action.
