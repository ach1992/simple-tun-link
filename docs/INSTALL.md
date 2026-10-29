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
was the first release with the self-contained `*_local-install.sh` format.**
Use the [latest published Stable](https://github.com/ach1992/simple-tun-link/releases/latest)
for a new installation. As a concrete example, the approved immutable
**v0.1.13** publishes the exact download files below.
When a new release becomes Latest, select that new release's **actual tag**,
matching architecture and source-verified file instead of blindly reusing
v0.1.13.
Open the official release on an Internet-connected device and verify its tag,
publisher and exact published asset before privileged use. The matching file
already embeds all required STL core files; no extra STL binary, installer,
manifest or checksum transfer is necessary. Optional Carrier helpers are
*not* included in the core archive. From Stable v0.1.10, WSS is supported
through a separately verified, explicit
`--with-wss` companion selection; Paqet remains unshipped.

| Server CPU | Exactly ONE file to download | Exact official release asset |
| --- | --- | --- |
| `x86_64` | `stl_v0.1.13_linux_amd64_local-install.sh` | [Official v0.1.13 AMD64 file](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.13/stl_v0.1.13_linux_amd64_local-install.sh) |
| `aarch64` | `stl_v0.1.13_linux_arm64_local-install.sh` | [Official v0.1.13 ARM64 file](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.13/stl_v0.1.13_linux_arm64_local-install.sh) |

Transfer the selected single file
**without renaming, extracting or making it executable** into `/root/stl/`.
Create `/root/stl/` using your SFTP client as root if necessary. No additional
manifest, checksum file, compiler or separate shell helper is required on the
*target*. For WSS alone, the separate verified `wstunnel` archive is an
additional optional file. The folder/file must be owned by root, not
group/other writable; typical root-SFTP file modes `0600`/`0644` work,
and the directory must be root-owned `0700`.
**Keep exactly one matching `*_local-install.sh`** in `/root/stl/`: move
older installers to a separate private directory before running the glob.
The pinned WSS companion archive may coexist with that one installer.
With this one matching installer present,
run the exact command as **root**, or use the separately shown genuine `sudo`
variant from a non-root administrator account:

~~~sh
bash -c 'set -euo pipefail; f=(/root/stl/*_local-install.sh); [[ $EUID == 0 && $(stat -c %u:%a /root) == 0:700 && $(stat -c %u:%a /root/stl) == 0:700 && ${#f[@]} == 1 && -f ${f[0]} && ! -L ${f[0]} && $(stat -c %u:%a "${f[0]}") =~ ^0:(600|644)$ ]] || { echo "STL: unsafe folder/file; require root-owned /root/stl (0700) and one file (0600/0644)" >&2; exit 1; }; n=$(stat -c %s -- "${f[0]}") || exit 1; [[ $n =~ ^[0-9]+$ && $n -gt 0 && $n -le 134250000 ]] || { echo "STL: installer file size must be 1..134250000 bytes" >&2; exit 1; }; d=$(mktemp -d /root/.stl-preflight.XXXXXXXX); trap '\''rm -rf -- "$d"'\'' EXIT; head -c "$n" -- "${f[0]}" > "$d/${f[0]##*/}"; [[ $(stat -c %s -- "$d/${f[0]##*/}") == "$n" ]]; cmp -s -- "${f[0]}" "$d/${f[0]##*/}"; for x in "$@"; do if [[ $x == --with-wss ]]; then case $(uname -m) in x86_64) a=amd64;; aarch64) a=arm64;; *) echo "STL: unsupported WSS CPU" >&2; exit 1;; esac; w="/root/stl/wstunnel_11.0.0_linux_${a}.tar.gz"; [[ -f $w && ! -L $w && $(stat -c %u:%a "$w") =~ ^0:(600|644)$ && $(stat -c %h "$w") == 1 ]] || { echo "STL: missing or unsafe optional WSS archive" >&2; exit 1; }; z=$(stat -c %s "$w"); [[ $z =~ ^[0-9]+$ && $z -gt 1024 && $z -lt 100000000 ]] || { echo "STL: optional WSS archive size is unsafe" >&2; exit 1; }; head -c "$z" -- "$w" > "$d/${w##*/}"; [[ $(stat -c %s -- "$d/${w##*/}") == "$z" ]] && cmp -s -- "$w" "$d/${w##*/}" || { echo "STL: WSS archive changed during protected copy" >&2; exit 1; }; break; fi; done; bash "$d/${f[0]##*/}" "$@"' stl
~~~

For a sudo-capable **non-root** administrator, use this command instead
(the user must already have genuine `sudo` access):

~~~sh
sudo bash -c 'set -euo pipefail; f=(/root/stl/*_local-install.sh); [[ $EUID == 0 && $(stat -c %u:%a /root) == 0:700 && $(stat -c %u:%a /root/stl) == 0:700 && ${#f[@]} == 1 && -f ${f[0]} && ! -L ${f[0]} && $(stat -c %u:%a "${f[0]}") =~ ^0:(600|644)$ ]] || { echo "STL: unsafe folder/file; require root-owned /root/stl (0700) and one file (0600/0644)" >&2; exit 1; }; n=$(stat -c %s -- "${f[0]}") || exit 1; [[ $n =~ ^[0-9]+$ && $n -gt 0 && $n -le 134250000 ]] || { echo "STL: installer file size must be 1..134250000 bytes" >&2; exit 1; }; d=$(mktemp -d /root/.stl-preflight.XXXXXXXX); trap '\''rm -rf -- "$d"'\'' EXIT; head -c "$n" -- "${f[0]}" > "$d/${f[0]##*/}"; [[ $(stat -c %s -- "$d/${f[0]##*/}") == "$n" ]]; cmp -s -- "${f[0]}" "$d/${f[0]##*/}"; for x in "$@"; do if [[ $x == --with-wss ]]; then case $(uname -m) in x86_64) a=amd64;; aarch64) a=arm64;; *) echo "STL: unsupported WSS CPU" >&2; exit 1;; esac; w="/root/stl/wstunnel_11.0.0_linux_${a}.tar.gz"; [[ -f $w && ! -L $w && $(stat -c %u:%a "$w") =~ ^0:(600|644)$ && $(stat -c %h "$w") == 1 ]] || { echo "STL: missing or unsafe optional WSS archive" >&2; exit 1; }; z=$(stat -c %s "$w"); [[ $z =~ ^[0-9]+$ && $z -gt 1024 && $z -lt 100000000 ]] || { echo "STL: optional WSS archive size is unsafe" >&2; exit 1; }; head -c "$z" -- "$w" > "$d/${w##*/}"; [[ $(stat -c %s -- "$d/${w##*/}") == "$z" ]] && cmp -s -- "$w" "$d/${w##*/}" || { echo "STL: WSS archive changed during protected copy" >&2; exit 1; }; break; fi; done; bash "$d/${f[0]##*/}" "$@"' stl
~~~

These commands verify ownership, source type, modes, installer count and the
1..134250000-byte file-size bound **before** private bounded copying or
execution of transferred shell bytes.
An unsafe folder/file, symlink or extra matching installer is refused, not
run. The trailing `stl` is the fixed `bash -c` argument label; for an
**explicit WSS companion selection only**, append ` --with-wss` after
that final `stl`. Only with that flag, the trusted command also checks the matching
optional archive's root ownership, mode, single hardlink, filename/CPU,
size and exact copied bytes **before executing the private snapshot**.
It places the selected helper beside the private STL launcher (not
just beside the original downloaded STL file); the official launcher
then checks pinned archive and extracted executable SHA-256. Without
the flag, the optional archive is neither copied nor installed. The command is necessarily longer than directly
invoking an unauthenticated transferred script; it is still one copyable
invocation and requires no checksum variable, unpack, chmod or second installer.
It is not an independent publisher signature: verify the official file before transfer.

A non-interactive success prints `[OK]` and `stl version --json`, followed by
`sudo stl menu` guidance. On an interactive terminal, the normal menu opens.
A new host installs; an existing verified same-version installation is a no-op;
a newer Stable replaces an older installer-owned Stable through the canonical
atomic update. Downgrades and channel changes fail closed and require explicit
reviewed manual canonical action. The launcher **does not modify Links,
credentials, State, unrelated services or networking**, and it does not stage
IPsec or Paqet; a WSS helper is staged only if explicitly selected with
`--with-wss` and independently verified. Only genuinely missing selected
native and WireGuard distro packages may trigger the host's configured signed
APT path; fully installed
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
latest published Stable single-file format above for new installations,
after verifying the exact asset and its official provenance.

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
| WireGuard over WSS (optional since **v0.1.10**) | No WSS binary is included in the STL core file; obtain the exact official `wstunnel v11.0.0` architecture archive separately with the pinned SHA-256 specified below | Pass explicit `--with-wss` to the canonical one-file installer; kernel WireGuard, mTLS identity, scoped nft ingress guard and host ownership preflight are required |
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

Read the [canonical installer source](../scripts/install.sh) and the
official release contract before running any privileged installer.
**Do not use a raw, caller-selected historical tag as root shell source**:
HTTPS and `bash -n` alone cannot authenticate a published immutable release.
Use the permanent, current-immutable Stable bootstrap below, optionally
passing a verified exact historical Stable tag as **data**. To audit the
installer manually, obtain the current immutable Stable's canonical source
and cross-check its publisher/tag identity before any root execution.

### Permanent short one-line installer (Latest Stable or an exact Stable tag)

The version-free `releases/latest/download/stl-bootstrap.sh` URL selects
the newest published **Stable**, excluding RC and draft releases. GitHub
serves a tag-bound immutable bootstrap asset generated from the reviewed
quick installer source. That bootstrap pins its own exact release tag
before downloading the canonical installer; it does not execute a mutable
`main` script as root. Inspect source, SHA256SUMS and official release
identity before installing. The public command stays unchanged:

~~~sh
bash -c 'set -e; d=$(mktemp -d); cleanup(){ rm -rf -- "$d"; }; trap cleanup EXIT; curl -fsSLo "$d/stl.sh" --proto "=https" --proto-redir "=https" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl.sh"; bash -n "$d/stl.sh"; bash "$d/stl.sh" "$@"' stl
~~~

To install a specific published Stable, append its tag to that same
command (for example the final suffix stl v0.1.9 instead of stl). The one-line
entry point stays unchanged across releases. With no suffix, the immutable
Latest Stable asset supplies its exact pinned default version.

~~~sh
bash -c 'set -e; d=$(mktemp -d); cleanup(){ rm -rf -- "$d"; }; trap cleanup EXIT; curl -fsSLo "$d/stl.sh" --proto "=https" --proto-redir "=https" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl.sh"; bash -n "$d/stl.sh"; bash "$d/stl.sh" "$@"' stl v0.1.9
~~~

The **first hop is downloaded to a private temporary directory**. Only
after curl completes successfully and the file is nonempty and passes Bash
syntax validation can it execute. Failed or partial transfers never execute
the downloaded script; the temporary directory is removed on exit. An
optional historical Stable suffix is checked against the official exact-tag
GitHub release API before privilege elevation; it requires Python 3 and a
published, complete, `immutable:true` non-prerelease release. Missing,
mismatched, truncated, redirected, unavailable or mutable metadata fails
closed. **The executable canonical installer is always downloaded from the
bootstrap's own immutable Latest Stable tag**, never from the separately
selected older tag. That older version remains data (`--version`) for the
canonical installer, which independently validates release SHA256SUMS, binary
metadata and installed ownership/rollback rules. The bootstrap reattaches a
real /dev/tty to open the menu after installation. Without a TTY, use
`sudo stl menu`. This source change reaches users only after a new release
publishes its corresponding permanent bootstrap asset.
Default prerequisites are native and WireGuard. To update an existing
installer-owned STL, **do not run install again**: use this equally fixed
update command:

~~~sh
bash -c 'set -e; d=$(mktemp -d); cleanup(){ rm -rf -- "$d"; }; trap cleanup EXIT; curl -fsSLo "$d/stl.sh" --proto "=https" --proto-redir "=https" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl.sh"; bash -n "$d/stl.sh"; bash "$d/stl.sh" "$@"' stl update
~~~

This selects the unchanged canonical installer update transaction,
including identity-verified existing ownership and rollback journals.
The three published examples (latest install, exact Stable, latest update) use the default native,wireguard prerequisites.
An advanced operator who separately obtains and verifies the immutable
bootstrap asset may invoke it as `bash ./stl-bootstrap.sh native update`
for a narrower backend selection. **Append only a validated exact Stable tag where documented**; use STL Update
for installed-version switching and do not append unrecognized arguments. The installer refuses foreign or
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

The canonical installer selects native GRE/IPIP prerequisites by default. `--backends all` requests every dependency
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

The permanent one-command wrapper completes and syntax-checks the
**current immutable bootstrap's pinned canonical installer** in a private
temporary file **before invoking sudo**; a partial/failed download is never
streamed into a privileged shell. An optional older exact-version suffix
first passes official immutable-release metadata verification and is used
only as an installer argument. The canonical installer then fetches
`SHA256SUMS`, `BUILD-MANIFEST.txt`, `LICENSE`, and the one
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

All menu-driven updates and compatible requested downgrades require
positively verified `immutable:true` official releases, installed-root/TTY
checks, exact selected release identity and fresh action-specific consent
(`UPDATE` or `DOWNGRADE`). Forward same-line RC transitions remain supported.
A same-line Stable **downgrade** is only eligible when the installed Engine
itself implements the current guarded compatibility command and confirms
zero saved Links, no pending journals/receipts, no owned restore unit and an
explicitly known historical State reader. The only supported downlevel
conversion is a strictly empty v4-to-v3 snapshot; never strip a live Link or
unknown State fields. The original JSON must have exactly one `schema_version`
and one genuinely empty `links` array; duplicate keys (including JSON-escaped
duplicates), case aliases, null arrays, unknown fields and any retained
journal/receipt are rejected without replacing the State. Major/minor jumps,
RC-to-Stable, mutable or unverified
releases and unsafe downlevel State remain blocked, not silently installed.

**Bridge from an already-installed v0.1.12 (and older Stable):** the published
v0.1.12 binary lacks the new `maintenance stage-downgrade` command. It
cannot perform a direct v0.1.12-to-v0.1.9 downgrade, even when the newer
installer source is separately downloaded. Official **v0.1.13** contains the
reviewed guarded release-selection workflow: first invoke the unchanged
permanent Latest Stable **update** command above to upgrade the installed
Engine. Then open `sudo stl menu`, select the exact older immutable Stable
and confirm `DOWNGRADE` only after STL validates zero Links, State schema,
pending journal, restore-unit and resource compatibility. This is an explicit
two-step managed transition, not a claim that v0.1.12 already provides the
action. Never skip State/Link checks or replace a binary manually to simulate
this migration.
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

### Existing managed WSS Dial helper after updating to v0.1.12

The v0.1.12 WSS Dial reconnect wakeup is attached to **newly created**
verified STL-owned transient helper units, not to the installed STL binary
itself. A successful v0.1.11 → v0.1.12 core update **does not refresh
already loaded** WSS units; even a plain `systemctl restart` of an old
loaded unit keeps its old properties. The WSS Listen role does not need a
wakeup, and an existing working Link does not need to be recreated or
re-paired. Do not stop a service merely to make its version match.

For an **explicitly authorized maintenance window** on a Dial host, record
the exact Link ID, confirm `stl version --json` and its installer record,
then inspect `stl link status LINK_ID --json` and verify that the actual
helper unit is the expected STL-owned WSS Dial unit, with no foreign systemd
lifecycle hooks. Preserve consistent private State/credential backups and
original SSH/default routes. Only after the exact managed unit is verified:
stop **that unit alone**, confirm systemd has completely collected it
(`LoadState=not-found`), and use the canonical
`sudo stl link restore --all` to reconcile persisted Links. **Restore --all
is mutating and applies to every persisted Link**: first verify all saved
Links are in scope and maintenance is approved; never use it to blindly
refresh one Link on a multi-Link host. When no safe maintenance window or
full-restore scope exists, leave the old helper running and defer activation.

After an authorized refresh, recheck the original Link ID and verified
WireGuard interface/guard, the Dial unit's `ExecStartPost` and
`ExecStartPostEx` readback, real two-way private traffic, SSH and routes.
The systemd extended property must describe only the reviewed bounded
`ignore-failure` ICMP wakeup. If stop/restore/update fails or any original
resource identity is uncertain, preserve credentials and State; use the
[identity-checked rollback guidance](OPERATOR-RECOVERY.md#managed-wss-dialer-restart-reliability-stable-v0112)
instead of deleting the Link/unit or rerunning arbitrary host commands.

The actual IRPT-101 ↔ DE-Hamed-Test field trials of the **reviewed source**
measured 15.5s consecutive loss on the old v0.1.11 loaded Dial unit versus
0.5s in each of two v0.1.12-source candidate trials. Exact public v0.1.12
asset installation and physical version-specific reboot are **separate**
checks; see [Issue #93](https://github.com/ach1992/simple-tun-link/issues/93).

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

**State v4 is a separate, non-downgrade-safe boundary.** The
Stable v0.1.10+ WSS-capable runtime writes schema v4 even on hosts
with only Native Links once State is updated. A pre-v4 STL binary must not parse, restore or mutate
that snapshot; failure to read State does **not** prove no Links are configured.
Safe rollback requires an independently verified, unchanged, consistent and
credential-matched pre-v4 backup, and proof that no later operation committed
a newer recovery/ownership identity. Otherwise use a v4-capable forward fix.
Restoring only an old binary while retaining schema v4 is NOT a valid rollback.
Never manually rewrite schema_version or strip pre-effect journals, original
WSS fingerprints, receipts or resource claims.

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

The interactive `sudo stl menu` Uninstall task now performs the canonical
verified binary removal after a fresh `UNINSTALL` confirmation on the installed
root terminal. The embedded installer holds the exclusive maintenance lock,
checks Link/State/restore ownership, and never silently removes active Links,
private credentials or foreign host resources. A genuinely STL-generated
lock-only footprint with no committed State is retired by STL itself.
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
ambiguous state or unverified restore-unit identity requires
safe Link/Engine reconciliation **before** uninstall. If the only obstacle
is a positively verified STL-owned restore unit with zero saved Links and
no pending operations, the new menu presents an **explicit
`UNINSTALL` confirmation** and passes that consent to the canonical
installer. Under its exclusive maintenance lock, the installed Engine
rechecks State and guarded systemd ownership, disables/retires only the
identified orphan unit, rechecks absence and then permits core binary
uninstall. A public STL marker alone is never ownership evidence: the exact
canonical restore-unit template (all directives and the installed executable
`/usr/local/bin/stl`), trusted file/parent path, pinned inode and systemd
enablement must match. In addition, a bounded read-only inspection of the
**manager-loaded effective unit** must confirm the exact canonical
`FragmentPath`, an empty `DropInPaths`, `NeedDaemonReload=no`,
`LoadState=loaded`, and the canonical effective `ExecStart` before any
owned disable or removal. The installed Engine rechecks this evidence after
external systemctl inspections and before deleting the main unit; a missing
unit must independently show an absent effective identity without leftover
drop-ins. Unknown, altered, stale, or foreign effective configurations must
not be adopted, disabled or deleted by STL. Foreign drop-ins are never purged
by STL. These checks also cover **failed-operation compensation**: after
partial enable/disable, the manager-loaded unit is re-attested before any
compensating systemctl operation; after guarded source-inode restoration, a
read-only manager check must precede daemon-reload and a fresh full canonical
check must precede any re-enable. If a foreign drop-in appears during
recovery, STL refuses to enable/disable that effective service, preserves
foreign configuration, and reports explicitly incomplete recovery. A proven
STL-owned source file may still be restored without granting authority to
re-enable the service. These checks are deliberately fail-closed; preserve
any uncertain host resources and reconcile them explicitly.
Interrupted/uncertain systemctl or foreign units remain blocked.
Do **not** delete interfaces, route/firewall rules, or the restore unit
manually as a shortcut.

After Link State is proven empty, open `sudo stl menu`, choose
**Uninstall**, and type **UNINSTALL** after the verified preview.
An owned orphan restore unit can be retired through this same confirmed
workflow in the successor release; no separate installer download or manual
lock-directory cleanup is needed. Advanced offline/legacy fallback:

~~~sh
sudo bash ./install.sh uninstall
~~~

Uninstall calls `stl maintenance pre-uninstall --json` under the exclusive
maintenance lock. That Go command distinguishes a never-used host from a
missing state snapshot in an existing root and uses the canonical systemd
installed/enabled checks. The original private `state.json` bytes are
also inspected before *any* Uninstall or owned-orphan retirement decision.
Unknown, duplicate, JSON-escaped duplicate, or case-aliased State fields that
could conceal saved Links, pending operations or receipts are rejected even
when the ordinary State loader would decode zero Links. The inspector checks
the same file's identity and bytes again after the Engine preflight.
Missing, malformed, symlinked or otherwise ambiguous State fails closed;
the installed binary/record and committed State remain untouched.
Uninstall removes only the hash-verified installer-owned canonical executable,
its exact `stlink -> stl` symlink, and the installer ownership record. It keeps
the installer lock and does **not** delete committed `/var/lib/simple-tun-link`
State, retained protected credentials, optional companion binaries, other
systemd units, network resources, arbitrary `stl` files, or host packages.
Only exactly verified uncommitted lock-only State residue may be retired
and only an explicitly confirmed, separately verified orphan restore unit
may be disabled and deleted. Uninstall is **not** a universal data purge.
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

## Optional pinned WSS companion (available in Stable v0.1.10+)

Core STL remains the official single-file local installer. WSS is **optional**.
For official Stable v0.1.10 or later, obtain the
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

**Run the verified trusted preflight one-liner shown in the local-install
section**, but **append `--with-wss` after its final `stl` argument**.
After copying the verified `wstunnel` archive beside the selected STL
file, take **the complete original preflight command above** (root or
`sudo`) and append exactly ` --with-wss` after the last `stl`.
Its closing fragment will therefore read
`bash "$d/${f[0]##*/}" "$@"' stl --with-wss`.
That fragment is an illustration of the end of the command, **not** a
standalone command or a replacement for the complete trusted preflight.
The wrapper snapshots the optional archive into **the same private
directory** as the STL installer, because the official one-file installer
resolves that companion relative to the executable file it was given.
The canonical installer re-verifies its pinned hash before admitting it.
Do **not** bypass the root-owned preflight for either file merely to
shorten the command.
Use the real file for the host's CPU and a published Stable version with WSS
support (v0.1.10 or newer). Missing or mismatched selected archives are rejected
before the core installer is started. An existing verified WSS installation
does not need a new sidecar merely to upgrade its core STL executable.

For an **already installer-owned** STL installation, the equivalent standalone
administrator recovery action is available (not the normal first-use path):
~~~sh
sudo bash scripts/install.sh companion-wss --archive /absolute/path/wstunnel_11.0.0_linux_amd64.tar.gz --prefix /usr/local
~~~
Run that action only using the verified canonical installer from the exact
release being operated or a separately authorized test candidate. Never
copy binaries into `/usr/local/libexec/stl` or forge the installer record manually; the read-only Engine admission checks the
whole trusted executable path, digest and ownership before each activation.

WSS uses real kernel WireGuard plus TLS/mTLS. The selected TCP endpoint must
be reachable across the two servers; kernel WireGuard UDP must **not** be
exposed publicly and is restricted by STL's scoped nftables guard. Conflicts
with other host firewalls/interfaces/services cause refusal, not takeover.
A completed local installation does NOT prove WSS connectivity, mTLS peer
acceptance or a WireGuard handshake. See the exact pairing examples in
[CLI.md](CLI.md), evidence gates in Issue #142 and the scope in
[SECURITY.md](SECURITY.md). Do not treat a development-only source build
or a locally selected helper as a published Stable artifact; verify the installed exact release and
authenticated private connectivity before production use.
