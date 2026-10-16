# Install, update, and uninstall

**For everyday installation and connecting two servers, start with the
[README](../README.md)**. This page is the advanced installer/maintenance
runbook, not a required first stop for a new operator.

Current public [Stable release v0.1.0](https://github.com/ach1992/simple-tun-link/releases/latest).
Its integrated selected IPsec preparation and refined one-consent terminal
UX are the reviewed #105/#106 changes beyond the historical immutable
[v0.1.0-rc.6 prerelease](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.0-rc.6).
Prior milestones remain intact: rc.6 on-demand prerequisites and Update,
rc.5 protected handoff/quality, rc.4 systemd 249 compatibility, rc.3
guided Create/Manage, rc.2 IPsec/MTU/State v3. Real WAN/NAT/provider
firewall and physical-host reboot acceptance remain open in
[Issue #93](https://github.com/ach1992/simple-tun-link/issues/93).
Check the published release, SHA256SUMS and exact installed commit
before trusting the update. Earlier rc.2 release evidence and its
limits are in [Issue #12](https://github.com/ach1992/simple-tun-link/issues/12).
Commands below use generic `vX.Y.Z` as a placeholder: replace it with an
**actually published** tag, never a branch name. No installer runs during a
clone, build, or ordinary `go test`.

## Read-only diagnosis when Create AND Import fail at persistence

The published v0.1.0-rc.3 may show state_failed, stage=persistence,
desired_state=no_commit_attempted, and
rollback_completed_unverified. **This does not establish the original
cause.** Both Create and Import require the same strict, owned systemd
restore transaction before durable desired State commit. The final code
is the compensation/reconciliation outcome, not proof of a GRE packet,
peer reachability, or even a specific systemd failure.

The Owner-provided Ubuntu 22.04 / systemd 249 evidence from
2026-10-15 establishes a specific rc.3 compatibility problem:
`is-enabled` wrote **no stdout**, returned exit **1**, and printed
"No such file or directory" on stderr for a missing restore unit.
The same host independently returned `LoadState=not-found` with empty
`UnitFileState` and `FragmentPath`; `namei` showed trusted root-owned
ancestors/binary and a missing unit leaf. The rc.3 parser previously
accepted the missing-unit state only as stdout `not-found` with exit **4**,
so the transaction failed at persistence and rolled back without
committing the requested Link. The rc.4 fix in Issue #93 / PR #94
confirms absence with an additional exact read-only systemd property
inspection, rather than accepting any exit 1 or parsing localized stderr.
This is a **supported-environment code defect**, not proof of an
operational network/GRE or peer-address problem. Real affected-host
acceptance remains Owner-run after the public rc.4 release.

On **the affected host only**, an operator may collect the following
**read-only** observations (no tunnel/systemd/firewall changes):

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

Capture both the **exact is-enabled text and exit status** (including
when the unit is missing). A blank/timeout/error and a verified negative
status are not interchangeable. Verify PID 1, systemd accessibility,
canonical installed stl path ownership, parent directory trust, and
whether a restore unit path is already foreign or ambiguously owned.
These observations narrow the cause; they are not instructions to
change the reported state.

Never run systemctl enable/disable, daemon-reload, delete or replace
a possibly owned service, manually edit State or retry mutation blindly
to "fix" this error. If a unit looks foreign, stop and review ownership
privately before touching it. **Do not post private setup links, keys,
tokens, unredacted private logs, or a full foreign service file.**
Issue #93 includes rc.4's clearer terminal diagnosis and regression
tests. These changes are **not part of rc.3**.

## rc.6 menu maintenance (Issue #99)

[Issue #99](https://github.com/ach1992/simple-tun-link/issues/99)
introduced an operator menu for listing the three newest complete
public releases. Only an official release with explicitly reported
`immutable:true` is eligible for automatic root delegation to the
*existing canonical installer*, after same-line forward update, installed
root/real-TTY and fresh `UPDATE` consent. `immutable:false`, missing,
malformed or otherwise uncertain immutability is **manual-only**: never
execute its tag-downloaded installer as root automatically. Asset names,
Bash syntax and post-install hashes are not pre-execution source trust.
Historical rc.5 reports `immutable:false` and stays unchanged. New
rc.6 releases must use Owner-approved GitHub release immutability before
publication, and the menu only auto-updates from official immutable
releases whose API explicitly reports `immutable:true`.

For Uninstall, the rc.6 screen guides **WireGuard/IPsec receiver
Setup Link KEEP-or-DELETE decisions before removing the committed tunnel**.
If DELETE is chosen, My tunnels -> Delete receiver link needs a fresh
`DELETE` confirmation while Link identity still exists; only then Remove.
If KEEP is chosen, the protected file survives both removal and STL
uninstall and must remain under administrator control. GRE/IPIP need no
private-handoff decision. No credential erasure or mass Link wipe is
automatic. The older rc.5 Update remains read-only guidance; rc.6
applies additional immutable-release and fresh UPDATE-consent gates.

## Protected receiver Setup Link retention (rc.3 guided UI)

The rc.3 guided sender deliberately retains WireGuard and
IPsec receiver Setup Links in the STL private state root's
receiver-handoffs/ directory, separate from ordinary State and sender
credentials. Every Link ID has a 0600 identity-bound private file
inside an owned 0700 directory. Back up this directory together
with State and the separately protected sender credentials when
host disaster recovery matters. Keep all copies private.

In rc.5, the freshly YES-confirmed successful real-TTY Create also
displays the original offer immediately; otherwise guided My tunnels
-> Share -> SHOW displays the same offer after fresh real-TTY consent.
Only a separate explicit DELETE erases this receiver file; it does not
remove the active tunnel or local keys.
Link removal or uninstall must not silently delete retained receiver
handoffs. For an already removed Link, the owner must deliberately
inspect and clean any remaining private handoff. The normal system
root is /var/lib/simple-tun-link/receiver-handoffs/; only inspect
files you own and have verified, never use wildcard deletion or
relax owner-only permissions.

Old rc.2 handoffs created with an explicit filename are still in
that original path. The new menu does not search arbitrary old
private paths or reconstruct a lost receiver secret. The normal
noninteractive creator command still requires an explicit --output.

## Supported deployment shape

- Linux amd64 or arm64; Ubuntu 22.04+ and Debian 11+ are supported installer targets. Derivatives are not assumed compatible.
- Root-owned `/usr/local/bin/stl` is the single executable.
  `/usr/local/bin/stlink` is a relative symlink to `stl`, not another binary.
- Installer bookkeeping is root-owned in
  `/usr/local/lib/simple-tun-link/install-record` (plus a retained lock file).
- The canonical Engine still owns every Link, `/var/lib/simple-tun-link`,
  network resource, and `simple-tun-link-restore.service`. The installer does
  **not** manage those resources or currently install a second systemd service.
  Operational IPsec is **conditionally registered** only after the current
  STL-owned native-exclusive strongSwan runtime passes independent ownership
  and capability admission. The installer installs optional packages only;
  it does not publish/adopt an IPsec service/configuration or guarantee
  safe IPsec activation. See [IPsec real E2E](operations/IPSEC-REAL-E2E.md).
- On real `/usr/local` installs/updates, the installer identifies the OS from
  `/etc/os-release` as data, validates Ubuntu >=22.04 or Debian >=11, checks
  installed APT package identities via `dpkg-query`, and installs ONLY missing
  distro packages with `apt-get` from the host's existing repositories.
  Default `--backends native` selects `iproute2`, `iptables` and
  `kmod` for GRE/IPIP and on-demand kernel module inspection/loading
  (no modules are loaded by installation).
  `--backends native,wireguard` adds `wireguard-tools`;
  `--backends native,ipsec` adds `charon-systemd`,
  `strongswan-swanctl` and `libstrongswan-standard-plugins`
  (OpenSSL/GCM algorithm backends, not guaranteed by `--no-install-recommends`).
  `--backends all` opts in to every backend dependency.
- Missing strongSwan/IPsec packages cannot be safely installed by STL:
  APT maintainer hooks can start unknown effective systemd units, aliases,
  generator sources or foreign drop-ins. The rc.6 installer therefore
  **refuses automatic IPsec APT** in `install`, `update` and `prepare` when
  any required strongSwan package is missing. An administrator must verify
  foreign service ownership and install missing packages with normal
  OS package management first. Already installed IPsec dependencies still
  need separate STL-private service publication and runtime admission.

**Stable v0.1.0 / Issue #105 (not included in historical rc.6):** STL now
contains an interactive clean-host IPsec preparation path. In an installed root
terminal, choose **Create tunnel → Advanced types → IPsec ESP/NAT-T**.
STL shows missing packages and the resolved **complete APT dependency/version
plan**, plus the fact that normal distro package hooks may briefly start and
enable a newly introduced vendor strongSwan service. Typing **PREPARE** once
authorizes only that displayed plan and qualified STL-exclusive private-service
setup; it does not create a Link or generate peer secrets. STL rejects a
changed plan, unknown foreign daemon/port/unit/configuration, unsafe APT
upgrades/removals, or unverified package ownership. Every selected package
and dependency version must map to an index whose InRelease verifies with
the official Debian/Ubuntu archive keyring. Third-party repositories are
rejected even when APT trusts their key or their Origin claims Debian/Ubuntu.
Preflight also rejects alias, prefix and generic systemd service drop-ins,
including the strongswan-swanctl alias and attached/transient load paths,
before vendor hooks can execute. STL checks the actual system manager
UnitPath against a bounded supported list; unknown/custom paths stop
preparation rather than pretending that the host is clean. After successful APT, it
stops/disables only the newly installed vendor unit that it can positively
attribute to the approved transaction, verifies that it is inactive and
disabled, then reuses the existing private-service admission and returns to
the **same Create**. An actual tunnel still needs its own **YES**.

Package install/enablement is **not atomic** with STL Link or binary rollback.
If APT, vendor normalization or private-service publication fails, existing
package/service effects or protected partial files may remain. The menu
reports the failed stage and will not create an IPsec Link or blindly adopt
an unknown service. APT failure emits read-only dpkg/package and vendor
active/enabled/alias classifications and blocks blind retry. Use **stl doctor ipsec --json** for a read-only snapshot
and reconcile the specific observed conflict before retrying. Historical rc.6 binaries still require administrator-managed strongSwan
packages. Stable v0.1.0 includes the reviewed selected package/service
preparation but does not authorize mutation on operational hosts without
the operator's own backups and explicit consent.

- Only missing packages are requested; the installer never upgrades the entire
  host or edits repositories. Host APT package installation is not covered by
  the STL binary rollback transaction, and STL uninstall never uninstalls host
  packages. On error it reports the partial-package-management limitation.
- rc.6 (Issue #101) also bundles a byte-identical copy of the
  **canonical** installer inside the Go binary (build and CI refuse drift).
  This allows a real installed `sudo stl menu` to inspect actual missing
  packages using the canonical read-only requirements action, preview the
  selected effects, and invoke that same script's `prepare` action only
  after fresh root/real-terminal confirmation. The installer revalidates
  owner record, lock and packages independently before any APT operation.
  Non-root/redirected Create does not execute packages; the Engine still
  decides actual tunnel readiness. Missing strongSwan packages require
  manual administrator reconciliation, not an unsafe APT acknowledgement;
  private-service provision/admission remains separate.
- After an eligible GRE/IPIP Link is durably committed, canonical
  `link restore --all` may reload only that Link's on-disk, allowlisted
  missing `ip_gre`, `ipip` or `fou` module under existing restore
  maintenance and per-Link locks. No blanket boot module list or global
  module service is installed. A failed/unknown module restore fails the
  affected Link, never claims traffic readiness and never unloads a
  possibly shared driver; actual whole-guest traffic proof is a separate
  acceptance gate.
- rc.6 (Issue #101) adds `prepare --backends native|wireguard|ipsec|all`
  to the byte-identical canonical installer for an existing installer-owned
  `/usr/local/bin/stl`. Eligible missing native/WireGuard packages are
  installed with the existing lock/owner/expected-missing guards, without
  replacing the executable, editing State, loading modules or provisioning
  IPsec services. If any strongSwan package is missing, preparation fails
  **before APT** and guides manual administrator installation. The
  historical rc.5 installer has no `prepare` action.

  After obtaining and reviewing the installer from a **published new release**,
  an already installed operator can run, for example:

  ```sh
  sudo bash /path/to/verified/install.sh prepare --backends wireguard
  ```

  The command does not create a tunnel. Re-enter the Create menu to verify
  selected backend readiness. Do not run this action using the older
  rc.5 installer, which does not recognize `prepare`.
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

**Source-trust warning:** the published rc.5 release reports
`immutable:false`. A tagged URL or `bash -n` syntax check does NOT
make downloaded code safe to run with root privileges, and the release
asset checksum checks occur after the script starts. For manual
install/update on such a release, independently verify that the tag
resolves to the commit in `BUILD-MANIFEST.txt`, review the script at that
**exact commit SHA**, and check the release asset SHA256SUMS before
approving privileged execution. Never treat the convenience one-liners below as a replacement for
source verification. The
rc.6 menu Update specifically **does not** execute scripts from
mutable or unverified GitHub releases.

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
bash -o pipefail -c 'curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | bash'
~~~

The bootstrap is received in full and parsed before its final invocation.
It downloads the canonical exact-tag installer and checks syntax before
invoking root; the installer validates release SHA256SUMS, binary metadata
and ownership/rollback rules. It reattaches a real /dev/tty to open the
menu after installation. Without a TTY, use `sudo stl menu`.
Default prerequisites are native and WireGuard. To update an existing
installer-owned STL, **do not run install again**: use this equally fixed
update command:

~~~sh
bash -o pipefail -c 'curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | bash -s -- update'
~~~

This selects the unchanged canonical installer update transaction,
including identity-verified existing ownership and rollback journals.
For a narrower prerequisite selection, append native update after
the tag. The command refuses foreign or inconsistent installed
state rather than silently replacing it. Confirm rollback-compatible
State and backups before starting.

These Stable commands contain no changing version string or variable.
The selected release still carries its exact-version manifest. No RC is
selected by `releases/latest`. On a supported, positively qualified clean
host, **interactive** IPsec PREPARE may install signed distribution packages
and provision only the verified STL-exclusive service; it will not adopt
foreign VPN resources. The bootstrap itself does not provision IPsec.
Offline bootstrap failure/PTY tests: bash scripts/test-quick-install.sh.

The longer direct canonical-installer example above installs only the native GRE/IPIP
dependencies. `--backends all` selects all backend prerequisites for the
installer; in rc.6, any missing
strongSwan package is a manual administrator prerequisite and causes the
installer to stop before APT. Do not assume `--backends all` installs
IPsec. A fetched installer cannot bootstrap its own download client: `curl` is needed for the
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

The historical **rc.5** `stl menu` Update is read-only guidance.
The **rc.6 and Stable v0.1.0** menu Update fetches official metadata
and may delegate to the canonical installer only when GitHub positively
reports `immutable:true` and a forward **RC-to-RC** transition on the
same line, after root/TTY and fresh `UPDATE` checks. **RC-to-Stable**
must use the permanent **manual update one-liner above** with a protected
State/credential backup and independently checked release; selecting
Stable in the menu does not silently run it. `immutable:false` or unknown is
manual verification guidance only; there is no privileged remote-script
execution for that selection. Enabling release immutability in GitHub
Settings -> Releases affects only releases published afterward.

For manual operations, verify the intended source commit and published
tag against the release manifest, verify the selected artifact against
`SHA256SUMS`, and **inspect the downloaded installer before any privileged
execution**. Never pipe a mutable-tag download directly into a root shell.
After independent verification, use
`sudo bash ./install.sh update --version vX.Y.Z`. The installer refuses
a foreign or locally modified
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
firewall safety, or kernel traffic. Issue #12 owns that release-quality E2E
proof. A real public release/tag is a separate human authorization gate.
