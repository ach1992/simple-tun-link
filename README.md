# Simple Tun Link (STL)

**Create and manage point-to-point IP tunnels between Linux servers.**
STL gives each endpoint a private **Link Address** that applications can
use without needing to understand the underlying tunnel technology.

Use STL directly through a guided terminal menu, or integrate it into
other software through versioned CLI/JSON commands. One host can manage
multiple independent Links, including different supported transports
to the same peer. Native Linux backends carry packets without a Go
userspace forwarding loop.

**First connection:** Prefer the same supported Stable release on both hosts,
run `sudo stl menu`, create a tunnel on the first server, privately share its
Setup Link, import it on the second, then choose **Test connectivity** on both.
STL does not claim that a Link works merely because it was saved.
Version equality is recommended but **not intrinsically required for GRE**: the
v0.1.9 and v0.1.13 GRE Setup Link codec is compatible. Host routing,
firewall ownership and kernel capabilities must still pass on both endpoints.

## Tunnel options

| Backend | Transport | Encrypted? | Typical choice |
| --- | --- | --- | --- |
| **GRE** | Native, FOU/UDP, GUE/UDP | No | Simplest default; fast plaintext L3 connectivity |
| **IPIP** | Native, FOU/UDP, GUE/UDP | No | Alternative plaintext L3 encapsulation |
| **WireGuard** | UDP | Yes | Encrypted point-to-point connection |
| **WireGuard over WSS/TLS** | WSS over TCP + private kernel WG | Yes (mTLS and WireGuard) | Optional managed Carrier when the peer can reach a selected TLS TCP port |
| **IPsec** | IKEv2/XFRM, ESP or NAT-T | Yes | Advanced encrypted transport; requires a verified STL-owned strongSwan runtime |

GRE keys and UDP encapsulation do **not** encrypt or authenticate traffic.
A supported backend also requires compatible kernel capabilities and
actual network reachability on both servers. STL does not change a
cloud-provider firewall, configure NAT forwarding, or guarantee passage
through every network.

## Requirements

Two Linux servers you administer, with reachable underlay IP addresses
and root/sudo access. The supported installer baseline is **Ubuntu 22.04+
or Debian 11+**, **amd64/arm64**, kernel **5.4+** and iproute2 **5.1+**;
systemd is used for automatic reboot restoration. Debian 11 requires
working maintained/signed repositories after the end of standard LTS.
Backend support is checked on each host rather than assumed from the OS
name alone. See [supported environments](docs/SUPPORTED-ENVIRONMENTS.md).

Allow the selected underlay transport in the relevant host/provider rules:
GRE Native uses **IP protocol 47** (not TCP port 47); WireGuard uses
the selected UDP port; IPsec typically needs UDP **500/4500** and/or ESP.
For **WSS**, open the chosen TLS **TCP** port on the listening host and
install the explicitly selected, verified `wstunnel v11.0.0` companion on
both endpoints. STL protects the **kernel WireGuard UDP port** with a
Link-scoped ingress guard; do **not** publish that port to the Internet.
Use non-overlapping private Link Address subnets.

## Install on both servers

Use the current [official Stable release](https://github.com/ach1992/simple-tun-link/releases/latest).
The permanent Stable installer URL remains the same across releases:

~~~bash
bash -c 'set -e; d=$(mktemp -d); cleanup(){ rm -rf -- "$d"; }; trap cleanup EXIT; curl -fsSLo "$d/stl.sh" --proto "=https" --proto-redir "=https" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl.sh"; bash -n "$d/stl.sh"; bash "$d/stl.sh" "$@"' stl
~~~

The wrapper downloads the release's tag-pinned bootstrap into a private
temporary directory and checks download completion and shell syntax
before running it. For a requested older exact Stable suffix, the **new
bootstrap** verifies the official complete immutable release via the GitHub
API (Python 3 required) *before* root execution. It executes only the
bootstrap's currently pinned canonical installer; the selected older tag
is an artifact/version argument, never executable older shell source.
The canonical installer verifies checksums, build identity and installed-file
ownership. A checksum supplied by the
same publisher is **not** an independent publisher signature: review
the official release, source and installer before privileged execution.

By default, the installer selects GRE/IPIP and WireGuard prerequisites.
It opens the guided menu on an interactive terminal; otherwise run:

~~~sh
sudo stl menu
~~~

Verify the installed version with `stl version --json`. When updating an
existing managed WSS Dial Link from an older Stable, replacing the STL binary
alone does **not** recreate its running systemd helper or activate the
new dialer reconnect wakeup. See the separately approved
[managed WSS upgrade procedure](docs/INSTALL.md#existing-managed-wss-dial-helper-after-updating-to-v0112).
For IPsec, preparation may require separately approved signed packages
and an exclusively attested private service. STL must not silently
take over another VPN installation.

### Install an exact older published Stable

Use the **same one-line installer** above and append only the desired Stable
version at the end. For example, select the official **v0.1.9**:

~~~bash
bash -c 'set -e; d=$(mktemp -d); cleanup(){ rm -rf -- "$d"; }; trap cleanup EXIT; curl -fsSLo "$d/stl.sh" --proto "=https" --proto-redir "=https" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl.sh"; bash -n "$d/stl.sh"; bash "$d/stl.sh" "$@"' stl v0.1.9
~~~

Use no suffix for Latest Stable. The same trusted bootstrap fetches and
verifies the selected official release; no local file preparation is needed.
For an already installed host, use **Update** in the STL menu to upgrade or
request a downgrade after its State and Link checks. A binary change must never
silently erase Links or protected State. See [Issue #176](https://github.com/ach1992/simple-tun-link/issues/176).

### Local installation without GitHub access on the server

Official Stable releases from **v0.1.9 onward** support one self-contained
core installer. The current example, **v0.1.13**, uses the files below.
For later releases, always select the corresponding tag and architecture from
[official Latest Stable](https://github.com/ach1992/simple-tun-link/releases/latest).
WSS is optional and needs **one separate verified companion archive**.
Download only **one** official architecture-specific release asset on another
device. It already contains the matching STL binary, the canonical installer
and all STL-owned core metadata; no second STL file is needed on the server:

| Destination CPU (`uname -m`) | Download from the exact official release |
| --- | --- |
| `x86_64` | [`stl_v0.1.13_linux_amd64_local-install.sh`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.13/stl_v0.1.13_linux_amd64_local-install.sh) |
| `aarch64` | [`stl_v0.1.13_linux_arm64_local-install.sh`](https://github.com/ach1992/simple-tun-link/releases/download/v0.1.13/stl_v0.1.13_linux_arm64_local-install.sh) |

Upload the single file **as-is** into `/root/stl/` on the server (e.g. through
SFTP); the folder must be root-owned mode `0700` and the file root-owned
mode `0600` or `0644`. Keep **exactly one** matching
`*_local-install.sh` in that folder (move any older installer elsewhere; the
optional WSS companion may coexist). Run **as root**
(the command itself is a trusted pre-execution check, before any transferred
shell instruction):

~~~sh
bash -c 'set -euo pipefail; f=(/root/stl/*_local-install.sh); [[ $EUID == 0 && $(stat -c %u:%a /root) == 0:700 && $(stat -c %u:%a /root/stl) == 0:700 && ${#f[@]} == 1 && -f ${f[0]} && ! -L ${f[0]} && $(stat -c %u:%a "${f[0]}") =~ ^0:(600|644)$ ]] || { echo "STL: unsafe folder/file; require root-owned /root/stl (0700) and one file (0600/0644)" >&2; exit 1; }; n=$(stat -c %s -- "${f[0]}") || exit 1; [[ $n =~ ^[0-9]+$ && $n -gt 0 && $n -le 134250000 ]] || { echo "STL: installer file size must be 1..134250000 bytes" >&2; exit 1; }; d=$(mktemp -d /root/.stl-preflight.XXXXXXXX); trap '\''rm -rf -- "$d"'\'' EXIT; head -c "$n" -- "${f[0]}" > "$d/${f[0]##*/}"; [[ $(stat -c %s -- "$d/${f[0]##*/}") == "$n" ]]; cmp -s -- "${f[0]}" "$d/${f[0]##*/}"; for x in "$@"; do if [[ $x == --with-wss ]]; then case $(uname -m) in x86_64) a=amd64;; aarch64) a=arm64;; *) echo "STL: unsupported WSS CPU" >&2; exit 1;; esac; w="/root/stl/wstunnel_11.0.0_linux_${a}.tar.gz"; [[ -f $w && ! -L $w && $(stat -c %u:%a "$w") =~ ^0:(600|644)$ && $(stat -c %h "$w") == 1 ]] || { echo "STL: missing or unsafe optional WSS archive" >&2; exit 1; }; z=$(stat -c %s "$w"); [[ $z =~ ^[0-9]+$ && $z -gt 1024 && $z -lt 100000000 ]] || { echo "STL: optional WSS archive size is unsafe" >&2; exit 1; }; head -c "$z" -- "$w" > "$d/${w##*/}"; [[ $(stat -c %s -- "$d/${w##*/}") == "$z" ]] && cmp -s -- "$w" "$d/${w##*/}" || { echo "STL: WSS archive changed during protected copy" >&2; exit 1; }; break; fi; done; bash "$d/${f[0]##*/}" "$@"' stl
~~~

The final `stl` labels the `bash -c` invocation; to explicitly install
the separately verified optional WSS helper, append ` --with-wss` after
that final `stl`. Do not append it for a normal core-only install.
The archive must already be beside the installer. When WSS is
explicitly selected, the trusted preflight makes a bounded root-private
snapshot of **both** files together; the canonical launcher then checks
the pinned archive and executable SHA-256. It rejects absent, unsafe or
changed archives instead of silently installing core without WSS.
The [full root/sudo procedure](docs/INSTALL.md#one-transferred-file-and-one-trusted-command-new-release-format)
explains the same verified preflight.

If using a non-root sudo-capable administrator, run the same command with
`sudo` placed before `bash -c` (see the [installation guide](docs/INSTALL.md#local-installation-choose-a-published-asset)).
The preflight rejects unsafe modes/symlinks and snapshots the transferred
file (at most 134250000 bytes) into a root-private directory **before**
executing it. It does not prove
publisher authenticity by itself: verify the official source and release on
the Internet-connected downloading device. The launcher then recognizes the
CPU, privately verifies/extracts its embedded
release archive, and invokes the canonical installer. It handles a new install,
a no-op for the same verified artifact, or a newer **Stable-to-Stable** update;
it then opens the menu on a terminal (otherwise use `sudo stl menu`). It never
fetches STL from GitHub on the destination. Already-installed prerequisites
are reused; only missing native/WireGuard distro packages may use the configured
**signed APT repositories**. IPsec preparation is separate. Since
**Stable v0.1.10**, managed WireGuard over WSS is an **optional**, explicitly
selected Carrier requiring the separately pinned `wstunnel v11.0.0` archive
and `--with-wss`; it is not bundled with core STL. Paqet is not shipped.

**Availability:** [v0.1.9](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.9)
is the first Stable release with the self-contained `.sh` installers.
The older [v0.1.8](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.8)
contains only `.tar.gz` local archives and requires a different manual
procedure; never invoke this command on an archive. See [historical and current installation procedures](docs/INSTALL.md#local-installation-choose-a-published-asset)
for recovery, exact file selection and older-version instructions.
Verify publisher/tag provenance on the downloading device before root execution;
embedded or same-account checksums prove integrity, not independent publisher
authenticity. The v0.1.9 core installer did not support optional WSS;
from v0.1.10, the version-pinned WSS companion can be transferred beside the
core installer and activated **only** with explicit `--with-wss`.

## Connect Server A and Server B

1. On **Server A**, run `sudo stl menu` and select **Create tunnel →
   GRE / Native** (the default). Enter Server B's reachable underlay IPv4.
2. Accept the suggested private Link Address pair or enter your own
   non-overlapping addresses. Review the displayed local/peer
   endpoints and type **YES** to create A's Link.
3. Copy A's **Setup Link**. On **Server B**, open **Import setup link →
   GRE/IPIP**, paste it, review the reversed local/peer settings and
   type **YES**.
4. After both ends are configured, select **Test connectivity** on
   each server. An installed interface or saved Link alone does not
   prove that peer packets are reaching the other server.

You can retrieve a saved plaintext GRE/IPIP Setup Link again from
**My tunnels → Share Setup Link** without recreating the Link.
For advanced native setup without exchanging a Setup Link, see
[manual GRE/IPIP pairing](docs/CLI.md#manual-greipip-native-pairing-no-setup-link).
An existing committed Link is restored after reboot through STL's
owned systemd restore service; an interrupted uncommitted attempt
does not count as a successfully connected Link.

### Want encryption?

Select **WireGuard / UDP** in Create instead. After local creation,
STL displays a **SENSITIVE receiver Setup Link**. Send it to the
intended peer through a trusted private channel, then use
**Import setup link → WireGuard / IPsec** on that server.
The original protected receiver offer can be displayed again
through the explicit **SHOW** action and separately retired with
**DELETE**; ordinary status and JSON never include the secret.
IPsec is also available under Advanced types **only when its
native-exclusive runtime has passed admission**. A failed IPsec
preflight does not disable GRE/IPIP/WireGuard. For IPsec, after the
other server has imported the protected Setup Link, choose **My tunnels
→ Connect IPsec** on either peer and explicitly confirm `CONNECT`
before running Test connectivity. Import alone does not initiate
IKEv2; Test connectivity remains read-only and explains a missing SA.

### WireGuard over WSS/TLS (optional, Stable v0.1.10+)

This uses **real kernel WireGuard** carried through a per-Link WSS/TLS
helper, not an OpenVPN/proxy fallback. WSS requires a separate official
[`wstunnel v11.0.0` archive](https://github.com/erebe/wstunnel/releases/tag/v11.0.0)
matching the host CPU. Copy that unchanged archive beside the STL
single-file local installer on **both servers**, verify its pinned checksum,
and explicitly select `--with-wss` using the
[trusted installation procedure](docs/INSTALL.md#optional-pinned-wss-companion-available-in-stable-v0110).
Merely copying the helper does not install it. Regular online/core STL
installation does **not** fetch or enable this helper.

1. On the first host open **Create tunnel → 6 WireGuard / WSS + TLS**.
   Enter the peer's reachable address, select **Listen WSS** or **Dial WSS**,
   the listener's reachable TLS TCP port (default `443`), distinct local/peer
   protected WG UDP ports, private IPs and TLS server identity. Review the
   planned owned changes and type `YES`.
2. Transfer the resulting **SENSITIVE receiver Setup Link** through an
   authenticated private channel. On the second host use **Import setup
   link → 3 WireGuard / WSS + TLS**, hidden-paste the original offer,
   review the inverted roles/settings and type `YES`.
3. On **both** hosts choose **My tunnels → Check connection**, or
   **Test connectivity → A Check all tunnels**. Verify real private peer
   traffic. `Local status` alone only verifies owned local state; WSS
   carrier **path MTU is not measured** by the five-ping check.

The sender may retrieve its **original** saved offer from **My tunnels →
Share Setup Link → SHOW**. A CLI-created sender must supply its original
private `--output` file; the importing receiver cannot regenerate keys or
the sender's offer. `DELETE` affects only the verified menu-owned offer,
**not** an active Link or an unrelated CLI file. See
[guided/CLI WSS details](docs/CLI.md#managed-wireguard-over-wsstls-stable-v0110)
and [sensitive setup security](docs/SECURITY.md).

## Manage Links

For an on-demand overview of **all** saved tunnels, choose
**4 Test connectivity → A Check all tunnels** in the menu.
The result is a compact table of peer IPs, ICMP replies and observed
status; a missing Ping reply alone does not prove a tunnel is down.
A completed unanswered ping counts as measured packet loss, while a
canceled or failed probe remains unknown rather than invented loss.
Select an individual tunnel for detailed latency, supported MTU data
and counters. **Managed WireGuard/WSS** uses these same Status, five-ping,
Check all and Connection details actions: it verifies the scoped
helper/guard, real kernel WG identity and private peer route before
pinging; WSS carrier **path MTU is not measured** by that check.
`stl link diagnose-wss YOUR_LINK_ID --json` still provides detailed
local WSS helper, guard, WireGuard handshake and traffic counters.

For WSS receiver setup, the original **sender** may Share a protected
offer retained by the menu, or enter the original CLI `--output`
private file after an explicit `SHOW`. The importing receiver
cannot regenerate an old sender-private Setup Link from ordinary
State. Missing and unsafe offers are reported separately; ordinary
Status/Diagnostics never expose secret material.

~~~sh
sudo stl link list --json                    # Saved Link inventory
sudo stl link status YOUR_LINK_ID --json     # Owned local interface
sudo stl link diagnose YOUR_LINK_ID --json   # Peer ICMP; WSS PMTU not measured
sudo stl link diagnose --all --json          # Check all saved Links
sudo stl doctor ipsec --json                 # Read-only IPsec prerequisite check
~~~

The menu also provides Share, Connection details and an individually
confirmed Remove. In scripts, removal needs the exact ID twice:

~~~sh
sudo stl link remove YOUR_LINK_ID --confirm YOUR_LINK_ID
~~~

Do not blindly retry operations reporting uncertain host effects.
Use [operator recovery](docs/OPERATOR-RECOVERY.md) to inspect exact
ownership first. For machine integration, `stl link ensure --stdin
--json` and other [versioned commands](docs/CLI.md) reuse the same
Link lifecycle as the menu.

## Update or uninstall

For an existing **installer-owned** STL, back up protected State,
credentials and saved receiver handoffs, then run the Stable **update**
command instead of reinstalling:

~~~bash
bash -c 'set -e; d=$(mktemp -d); cleanup(){ rm -rf -- "$d"; }; trap cleanup EXIT; curl -fsSLo "$d/stl.sh" --proto "=https" --proto-redir "=https" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl.sh"; bash -n "$d/stl.sh"; bash "$d/stl.sh" "$@"' stl update
~~~

Installer binary rollback is **not** State rollback. Stable v0.1.10+
uses State **v4** for WSS-capable management; an older pre-v4 binary cannot
be assumed safe even on a host that has only Native Links. In particular,
installed v0.1.12 and earlier binaries do not know the guarded `DOWNGRADE`
operation. First use the permanent Latest Stable `update` command to install
official v0.1.13 (or a newer verified Stable); only then request an older
published immutable Stable through the installed menu, subject to zero-Link
and State/resource ownership gates.
The new Uninstall menu also handles a verified owned orphan restore unit
after `UNINSTALL` consent, retaining committed State, credentials, optional
companions and packages. Preserve a
credential-matched private backup and follow
[safe State/rollback instructions](docs/INSTALL.md#persisted-state-v3-upgrade-and-safe-rollback-boundary).
Never downgrade an active managed WSS Link by replacing only its binary.

Uninstall never removes active Links or erases private credentials
implicitly. Remove each owned Link deliberately before using the
verified installer's uninstall action; follow the
[uninstall procedure](docs/INSTALL.md#uninstall-never-tear-down-live-links-implicitly).

## More information

For users: [CLI and advanced setup](docs/CLI.md),
[installation and recovery](docs/INSTALL.md),
[diagnostics](docs/DIAGNOSTICS.md) and
[security](docs/SECURITY.md).

For contributors and integrators:
[Project Specification](docs/PROJECT-SPEC.md),
[architecture](docs/ARCHITECTURE.md),
[pairing format](docs/PAIRING.md),
[development](docs/DEVELOPMENT.md) and
[release verification](docs/RELEASE-ARTIFACTS.md).

**Scope of evidence:** isolated CI, native test guests and published
checksums do not certify every physical two-server WAN/NAT, provider
firewall or host-reboot environment; validate the intended servers
before relying on their connectivity.

[MIT License](LICENSE)
