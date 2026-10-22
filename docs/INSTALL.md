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
  lists-lock diagnostics. `APT::Update::Error-Mode=any` treats partial
  mirror/index-download failures as errors instead of silently accepting
  stale indexes. Unexpected warnings or repository failures stop
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

## When installer, selected PREPARE, or Update fails

A failed check is not permission to repair the host automatically. The
operator output identifies the failed stage and one safe next check;
read-only inspection may be repeated after host conditions change, but
package, binary and service mutations require fresh confirmation.

| Stage / operator reason | Read-only next check | Mutation/retry boundary |
| --- | --- | --- |
| Quick install HTTPS download or installer syntax | Confirm the selected official release, HTTPS/DNS reachability to `raw.githubusercontent.com`, and the downloaded installer's authenticity | No installer started; never run an incomplete or mutable download as root |
| `unsupported_or_unverified_os` | `cat /etc/os-release` and [supported hosts](SUPPORTED-ENVIRONMENTS.md) | Do not forge OS fields or modify distribution identity |
| `apt_source_trust_unverified` or `apt_dependency_plan_unverified` | `apt-cache policy iproute2 iptables kmod` and inspect configured distribution sources | No verified dependency plan; never bypass signatures or edit sources automatically |
| `requirements_check_timeout` or `requirements_inventory_unverified` | Check local load and APT metadata, then repeat the read-only Create inventory | A failed preview is not PREPARE consent |
| `github_release_api_limited`, `release_lookup_timeout`, or `release_catalogue_invalid` | Check [official releases](https://github.com/ach1992/simple-tun-link/releases) and HTTPS reachability to `api.github.com` | No binary update began; do not substitute an unverified tag |
| APT lists lock held by another `apt-get` | `ps -ef` for legitimate package-manager activity and `dpkg --audit` | The installer waits a bounded period. Do not delete lock files, kill APT, or run a whole-host upgrade to clear the lock |
| Canonical PREPARE/install package transaction interrupted | `dpkg --audit`, then verify selected installed packages with `dpkg-query -W` | Package/service hooks may persist. Inspect and reconcile before beginning another transaction; never blindly retry |
| `STL ownership record is missing or not regular` on `update` | `namei -l /usr/local/lib/simple-tun-link/install-record` and `stat` the `stl`/`stlink` installation paths | An incomplete first install is not an update; never forge ownership metadata or replace existing foreign binaries |
| Installer partial publication or failed identity verification | Check the reported private recovery directory, installed executable identity and ownership record, without changing them | Stop before another update/uninstall; retained rollback evidence is authoritative |

Avoid posting raw APT source configuration, package logs, State files, or
private Setup Links publicly: they can contain credentials or sensitive
host details. Provide redacted reason codes and relevant command exit
statuses instead. A completed installer alone does not prove that live
Links can reach their peers or survive reboot.

The guided PREPARE and Update menus never forward raw APT, package-hook,
Bash or child-installer stdout/stderr to the terminal. Instead they show
a fixed reason category, the last **reported** stage (not proof of the
actual host effects), the child exit code when available, and a
read-only recovery check. Quick Install likewise suppresses raw download,
syntax-check and installer diagnostics; only fixed progress messages and
a process exit code are displayed. Do not treat missing terminal details
as evidence that packages, vendor services or a swapped binary are intact.
For detailed investigation, inspect trusted host state privately and
redact any command output before sharing it. Do not enable verbose
secret-bearing logs as a workaround for a failed operation.

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

## Local installation: choose a published asset

### One transferred file and one trusted command (new release format)

**[Stable v0.1.9](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.9)
is the first release with the self-contained `*_local-install.sh` format.**
Open the official release on an Internet-connected device and verify its tag,
publisher and exact published asset before privileged use. The matching file
already embeds all required STL core files; no extra STL binary, installer,
manifest or checksum transfer is necessary. Optional future Carrier helpers
are *not* included or supported by this release.

| Server CPU | Exactly ONE file to download | Exact official release asset |
| --- | --- | --- |
| `x86_64` | `stl_v0.1.9_linux_amd64_local-install.sh` | [Download AMD64](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.9/stl_v0.1.9_linux_amd64_local-install.sh) |
| `aarch64` | `stl_v0.1.9_linux_arm64_local-install.sh` | [Download ARM64](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.9/stl_v0.1.9_linux_arm64_local-install.sh) |

Transfer the selected single file
**without renaming, extracting or making it executable** into `/root/stl/`.
Create `/root/stl/` using your SFTP client as root if necessary. No additional
manifest, checksum file, compiler or separate shell helper is required on the
*target*. The folder/file must be owned by root, not group/other writable;
typical root-SFTP file modes `0600`/`0644` work, and the directory must
be root-owned `0700`. With **only one** matching `*_local-install.sh` present,
run the exact command as **root**, or use the separately shown genuine `sudo`
variant from a non-root administrator account:

~~~sh
bash -c 'set -euo pipefail; f=(/root/stl/*_local-install.sh); [[ $EUID == 0 && $(stat -c %u:%a /root) == 0:700 && $(stat -c %u:%a /root/stl) == 0:700 && ${#f[@]} == 1 && -f ${f[0]} && ! -L ${f[0]} && $(stat -c %u:%a "${f[0]}") =~ ^0:(600|644)$ ]] || { echo "STL: unsafe folder/file; require root-owned /root/stl (0700) and one file (0600/0644)" >&2; exit 1; }; n=$(stat -c %s -- "${f[0]}") || exit 1; [[ $n =~ ^[0-9]+$ && $n -gt 0 && $n -le 134250000 ]] || { echo "STL: installer file size must be 1..134250000 bytes" >&2; exit 1; }; d=$(mktemp -d /root/.stl-preflight.XXXXXXXX); trap '\''rm -rf -- "$d"'\'' EXIT; head -c "$n" -- "${f[0]}" > "$d/${f[0]##*/}"; [[ $(stat -c %s -- "$d/${f[0]##*/}") == "$n" ]]; cmp -s -- "${f[0]}" "$d/${f[0]##*/}"; bash "$d/${f[0]##*/}"'
~~~

For a sudo-capable **non-root** administrator, use this command instead
(the user must already have genuine `sudo` access):

~~~sh
sudo bash -c 'set -euo pipefail; f=(/root/stl/*_local-install.sh); [[ $EUID == 0 && $(stat -c %u:%a /root) == 0:700 && $(stat -c %u:%a /root/stl) == 0:700 && ${#f[@]} == 1 && -f ${f[0]} && ! -L ${f[0]} && $(stat -c %u:%a "${f[0]}") =~ ^0:(600|644)$ ]] || { echo "STL: unsafe folder/file; require root-owned /root/stl (0700) and one file (0600/0644)" >&2; exit 1; }; n=$(stat -c %s -- "${f[0]}") || exit 1; [[ $n =~ ^[0-9]+$ && $n -gt 0 && $n -le 134250000 ]] || { echo "STL: installer file size must be 1..134250000 bytes" >&2; exit 1; }; d=$(mktemp -d /root/.stl-preflight.XXXXXXXX); trap '\''rm -rf -- "$d"'\'' EXIT; head -c "$n" -- "${f[0]}" > "$d/${f[0]##*/}"; [[ $(stat -c %s -- "$d/${f[0]##*/}") == "$n" ]]; cmp -s -- "${f[0]}" "$d/${f[0]##*/}"; bash "$d/${f[0]##*/}"'
~~~

These commands verify ownership, source type, modes, installer count and the
1..134250000-byte file-size bound **before** private bounded copying or
execution of transferred shell bytes.
An unsafe folder/file, symlink or extra matching installer is refused, not
run. The trusted command is necessarily longer than directly invoking an
unauthenticated transferred script; it is still one copyable invocation and
requires no checksum variable, unpack, chmod or second installer. It is not
an independent publisher signature: verify the official file before transfer.

A non-interactive success prints `[OK]` and `stl version --json`, followed by
`sudo stl menu` guidance. On an interactive terminal, the normal menu opens.
A new host installs; an existing verified same-version installation is a no-op;
a newer Stable replaces an older installer-owned Stable through the canonical
atomic update. Downgrades and channel changes fail closed and require explicit
reviewed manual canonical action. The launcher **does not modify Links,
credentials, State, unrelated services or networking**, and it does not stage
IPsec/WSS/Paqet. Only genuinely missing selected native and WireGuard distro
packages may trigger the host's configured signed APT path; fully installed
prerequisites require no APT/network operation.

**If it fails:** “wrong file” means download the other architecture; “SHA256
mismatch” means re-download and verify the official publisher/release; an
untrusted folder/file means re-transfer as root to `/root/stl/`; a foreign or
incomplete install requires inspecting the canonical install record/recovery
without overwriting it. If APT cannot fetch **signed** selected packages,
inspect the reported missing package/plan and manually configure an accessible
properly signed distro mirror, then rerun the same command. STL never changes
APT sources or permits `trusted=yes`/signature bypass. See
[signed APT recovery](#signed-regional-apt-recovery-when-required-prerequisites-are-missing).

**Trust boundary:** identify the real publisher (`ach1992/simple-tun-link`),
exact tag/commit and the official release asset *on the downloading device*
using a trusted channel/source review. A release-wide `SHA256SUMS` may also be
checked there but, when delivered by the same publisher, is **not** an
independent digital signature. The generated single-file launcher internally
checks its embedded archive's build-bound SHA256, manifest, exact architecture,
binary identity and safe private extraction. It cannot cryptographically
authenticate a completely replaced malicious launcher whose publisher was
never independently verified; do not execute an unauthenticated mirror.

### Older v0.1.8 release: manual archive transfer

For operators deliberately using the older
[v0.1.8 release](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.8),
installation requires the original manually verified `.tar.gz` process.
That historical release **does not** contain the one-command `.sh` format:

| CPU | Exact official file | Transfer placement |
| --- | --- | --- |
| `x86_64` | [`stl_v0.1.8_linux_amd64_local-install.tar.gz`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.8/stl_v0.1.8_linux_amd64_local-install.tar.gz) | `/root/stl-transfer/` |
| `aarch64` | [`stl_v0.1.8_linux_arm64_local-install.tar.gz`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.8/stl_v0.1.8_linux_arm64_local-install.tar.gz) | `/root/stl-transfer/` |
| Either | [`SHA256SUMS`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.8/SHA256SUMS) | Verify selected archive on the downloading device |

The original [authenticated manual unpack procedure](#verified-archive-unpack-procedure)
remains below for published archives and existing automation. Prefer the
v0.1.9 single-file format above for new installations, after verifying the
published file and its official provenance.

### Legacy manual inventory: v0.1.7 (no local archive)

On a different device with access to GitHub, first choose **one** architecture
from the destination's `uname -m` (`x86_64` = `amd64`, `aarch64` = `arm64`).
Download these exact official files from the immutable, source-reviewed
[`v0.1.7` release](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.7):

| Selected feature | Required download | Official location / transfer placement |
| --- | --- | --- |
| STL core, Linux x86_64 | [`stl_v0.1.7_linux_amd64`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.7/stl_v0.1.7_linux_amd64) | `/root/stl/stl_v0.1.7_linux_amd64` (instead of arm64) |
| STL core, Linux aarch64 | [`stl_v0.1.7_linux_arm64`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.7/stl_v0.1.7_linux_arm64) | `/root/stl/stl_v0.1.7_linux_arm64` (instead of amd64) |
| All selected STL core installations | [`SHA256SUMS`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.7/SHA256SUMS), [`BUILD-MANIFEST.txt`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.7/BUILD-MANIFEST.txt), [`LICENSE`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.7/LICENSE) | All three regular files directly in `/root/stl/` |
| Local canonical installer | [`scripts/install.sh` from tag `v0.1.7`](https://github.com/ach1992/simple-tun-link/blob/v0.1.7/scripts/install.sh) | Save from the exact-tag source as `/root/stl/install.sh`; **not a `v0.1.7` release asset** |
| Stable online bootstrap (not local) | `stl-bootstrap.sh` in the same release | Not required when running `install.sh` locally |

`v0.1.7` has **no** complete prepackaged local archive. Do not download a
made-up `*_local-install.tar.gz` asset under that tag. Review the exact-tag
installer source and independently check trusted published/tag identity before
root execution. `SHA256SUMS` is integrity metadata **from the same release**,
not a publisher signature or a defense against a compromised release account.

Transfer **only** your chosen architecture executable plus `SHA256SUMS`,
`BUILD-MANIFEST.txt`, `LICENSE`, and `install.sh` over SFTP/SCP or removable
storage to a root-owned `0700` directory. For example:

~~~sh
# On the destination as root (sudo -i), before transferring:
install -d -m 0700 /root/stl
# On the OTHER device, after downloading all selected files:
# scp stl_v0.1.7_linux_amd64 SHA256SUMS BUILD-MANIFEST.txt LICENSE install.sh root@TARGET_HOST:/root/stl/
# On the destination as root (sudo -i), after the transfer:
cd /root/stl
ls -la
sha256sum --check --ignore-missing SHA256SUMS
bash -n install.sh
bash ./install.sh install --bundle /root/stl --backends native,wireguard
stl version --json
~~~

The release-wide `SHA256SUMS` includes unused binaries and the online
bootstrap; `--ignore-missing` verifies only the chosen locally transferred
assets. Never interpret this as independent source authenticity. When STL was
already installed by the canonical installer, run `update --bundle /root/stl`
for an explicitly verified newer version rather than a new install. On
releases with the new package support, repeating an identical verified
`install` is a no-op; do not assume this behavior exists in `v0.1.7`.

### Exact optional component checklist

| Enable only if needed | External GitHub downloads | Local/system requirements |
| --- | --- | --- |
| GRE/IPIP Native, FOU/GUE | **None** besides STL core | Locally inspect kernel capability, `iproute2`, `iptables`, `kmod`; install genuinely missing distro packages via signed APT |
| Native kernel WireGuard | **None** besides STL core | Kernel capability and distro `wireguard-tools` (`wg`) if selected |
| Native IPsec/XFRM | **None** besides STL core | Only selected signed distro `charon-systemd`, `strongswan-swanctl`, `libstrongswan-standard-plugins`, under separate exact-plan PREPARE and foreign-service protection; direct `--backends all` is not consent |
| WSS (future, **not shipped**) | **No current STL Carrier asset**; after separate approval, exact pinned `wstunnel` helper tag, arch, checksum/license, compatible STL tag and protected per-Link placement must be published | No helper download or activation yet; upstream `wstunnel v11.0.0` security test alone is not a released runtime |
| Paqet/PCK (research only, **not shipped**) | **None** | Not an STL prerequisite; do not compile or stage it by default |

For an actually published version that contains an architecture-specific
`stl_vX.Y.Z_linux_amd64_local-install.tar.gz` **or**
`stl_vX.Y.Z_linux_arm64_local-install.tar.gz`, the downloadable archive will
contain `install.sh`, the matching single-arch binary, `LICENSE`,
`BUILD-MANIFEST.txt`, `LOCAL-INSTALL.txt`, and a complete internal `SHA256SUMS`.
The *separate* official release-wide `SHA256SUMS` identifies the complete
archive. Verify its exact tag/source and digest against an independently
trusted publisher reference on the Internet-connected device, then transfer
the selected archive into a **root-owned, 0700** `/root/stl-transfer` on the
destination. Do not create `/root/stl` ahead of time: extraction requires a
fresh destination. The following procedure is only for a verified,
actually published archive:

#### Verified archive unpack procedure

~~~sh
# On the destination as root (sudo -i), after transferring the selected archive:
set -euo pipefail
umask 077
cd /root/stl-transfer   # root-owned 0700 transfer directory
archive=stl_vX.Y.Z_linux_amd64_local-install.tar.gz  # use arm64 on aarch64
trusted_sha256=PASTE_INDEPENDENTLY_VERIFIED_64_HEX_SHA256
# First isolate the transferred bytes: an open writer of the original cannot
# modify the private snapshot used for authentication or script execution.
verified_dir=$(mktemp -d /root/stl-verified.XXXXXXXX)
[[ -n "$verified_dir" && "$verified_dir" == /root/stl-verified.* &&
   -d "$verified_dir" && ! -L "$verified_dir" ]] ||
  { printf 'Private verified archive staging failed\n' >&2; exit 1; }
install -m 0600 -- "$archive" "$verified_dir/$archive"
cd -- "$verified_dir"
printf '%s  %s\n' "$trusted_sha256" "$archive" | sha256sum --check -
# Materialize the complete authenticated script privately before execution.
tar -xOzf "$archive" install.sh > ./verified-installer.sh
chmod 0600 ./verified-installer.sh
bash -n ./verified-installer.sh
bash ./verified-installer.sh unpack \
  --archive "$PWD/$archive" --destination /root/stl --sha256 "$trusted_sha256"
cd /root/stl
sha256sum --check SHA256SUMS
bash -n install.sh
bash ./install.sh install --bundle /root/stl --backends native,wireguard
stl version --json
~~~

**Do not execute a script extracted from an archive before independently
confirming its exact publisher identity and SHA256**. The administrator
first makes a new root-owned, mode-`0700` verified directory and a mode-`0600`
copy: never hash a writable transfer and later execute different bytes.
The canonical `unpack` operation also rejects group/world-writable source
archives and untrusted writable ancestors, then authenticates **its own
private immutable-for-operation copy** and uses exactly that copy for every
member inspection and extraction. It validates six exact regular members,
size bounds, owners, a fresh destination, internal checksums and executable
identity. It performs **no** APT or binary installation. For a verified
already installer-owned host, run the existing `update --bundle /root/stl`
instead of silently replacing a different version via `install`.

The archive is an additional release artifact, not a second installation
engine, bundled Carrier set or permission to change host networking.
**No such archive is published at `v0.1.7`.**

### Signed regional APT recovery when required prerequisites are missing

If all selected distro prerequisites are installed, no `apt update`, `apt
install`, distro download or unrelated restart is needed. Otherwise the
canonical installer uses only the host's existing configured, signed
Debian/Ubuntu sources and rejects unauthenticated or upgrade/removal plans.
A failed `APT_INDEX_REFRESH`, `APT_DEPENDENCY_PLAN`, or
`APT_PACKAGE_INSTALL` identifies the missing selected packages and stage.

1. Read `cat /etc/os-release`, `apt-cache policy <missing-package>` and
   inspect `/etc/apt/sources.list` and `/etc/apt/sources.list.d/` without
   changing them. Inspect `dpkg --audit` and running APT tasks first if an
   install may have started; do not blindly retry a partially failed dpkg
   transaction or delete lock files.
2. If connectivity to the existing mirror is the cause, **the operator**
   chooses an accessible Debian/Ubuntu official-archive mirror (an Iranian
   or regional mirror is fine), appropriate to the host distro/codename,
   architecture and enabled security channels. Back up the actual sources
   and edit them manually; preserve distro keyrings and the signed
   `InRelease` / Release verification and official repository identity.
3. Confirm signed metadata/package candidate integrity using the host APT
   tools, then rerun the same verified local STL operation. Never enable
   `trusted=yes`, `AllowUnauthenticated`, disabled signature/expiry checks,
   arbitrary signing keys, or an unattended whole-host upgrade to force
   success. Changing a mirror does **not** independently establish trust.

These are operator-owned system configuration changes, **not** an STL installer
action. Debian 11's expired ordinary security support remains a separate
availability/security limitation; a mirror cannot recreate unsupported
signed packages. See [supported systems](SUPPORTED-ENVIRONMENTS.md) and
existing IPsec recovery and consent procedures below.

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
delegate a forward same-major/minor Stable patch update. A later Stable patch is eligible only when the **installed** executable
contains this newer menu gate *and* the target release passes immutable-tag,
lineage and fresh-consent checks. Publication of a newer version alone never
retroactively adds an update capability to an older executable.

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

## Optional pinned WSS companion (WireGuard over WSS R1 candidate)

Core STL remains the official single-file local installer. WSS is **optional**.
For the R1 development candidate (not a Stable release claim), obtain the
official upstream **wstunnel v11.0.0** Linux archive for the target CPU:
- x86_64: wstunnel_11.0.0_linux_amd64.tar.gz, archive SHA-256
  9708a99717b5a951453c2ff7c14c25d3418d02ca7fcb96fdb382a8f2083bab5e.
- aarch64: wstunnel_11.0.0_linux_arm64.tar.gz, archive SHA-256
  b86abf73e340ed0c3ff9a77a5458aa27213784920ec65513132b36def45edc94.

Upstream source: https://github.com/erebe/wstunnel/releases/tag/v11.0.0.
Do not rename or extract this file. Put it **beside** the official single-file
STL local installer and run the **same single-file installer** with the
explicit --with-wss option. Mere archive presence is not consent to install
an optional Carrier. When selected, the installer detects that exact filename, snapshots the archive into
installer-controlled private staging, validates SHA-256 of the entire archive
and the extracted executable plus exact version, then stages the helper at
/usr/local/libexec/stl/wstunnel with an ownership record. No network download,
helper unpack step, alternate helper installer or WSS effect is required of the
operator. Ordinary STL users, including those leaving an unselected
companion beside the installer, get unchanged core behavior. A bad archive, wrong CPU or foreign target binary fails closed.

The one-command selected-Carrier form is:

~~~sh
sudo bash /root/stl/stl_vX.Y.Z_linux_amd64_local-install.sh --with-wss
~~~

Replace vX.Y.Z with a **real published** version; no WSS R1 Stable
release is claimed. Missing or mismatched selected archives are rejected
before the core installer is started.

For an **already installer-owned** STL candidate, the equivalent standalone
administrator recovery action is available (not the normal first-use path):
~~~sh
sudo bash scripts/install.sh companion-wss --archive /absolute/path/wstunnel_11.0.0_linux_amd64.tar.gz --prefix /usr/local
~~~
Run that action only using the verified canonical installer from the exact
candidate being tested. Never copy binaries into /usr/local/libexec/stl or
forge the installer record manually; the read-only Engine admission checks the
whole trusted executable path, digest and ownership before each activation.

WSS uses real kernel WireGuard plus TLS/mTLS. The selected TCP endpoint must
be reachable across the two servers; kernel WireGuard UDP must **not** be
exposed publicly and is restricted by STL's scoped nftables guard. Conflicts
with other host firewalls/interfaces/services cause refusal, not takeover.
A completed local installation does NOT prove WSS connectivity, mTLS peer
acceptance or a WireGuard handshake. See the exact pairing examples in
[CLI.md](CLI.md), evidence gates in Issue #142 and the scope in
[SECURITY.md](SECURITY.md). Do not deploy an unreleased R1 candidate as a
replacement for an existing Stable production Link.
