# Simple Tun Link (STL)

**Create and manage point-to-point IP tunnels between Linux servers.**
STL gives each endpoint a private **Link Address** that applications can
use without needing to understand the underlying tunnel technology.

Use STL directly through a guided terminal menu, or integrate it into
other software through versioned CLI/JSON commands. One host can manage
multiple independent Links, including different supported transports
to the same peer. Native Linux backends carry packets without a Go
userspace forwarding loop.

## Tunnel options

| Backend | Transport | Encrypted? | Typical choice |
| --- | --- | --- | --- |
| **GRE** | Native, FOU/UDP, GUE/UDP | No | Simplest default; fast plaintext L3 connectivity |
| **IPIP** | Native, FOU/UDP, GUE/UDP | No | Alternative plaintext L3 encapsulation |
| **WireGuard** | UDP | Yes | Encrypted point-to-point connection |
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
Use non-overlapping private Link Address subnets.

## Install on both servers

Use the current [official Stable release](https://github.com/ach1992/simple-tun-link/releases/latest).
The permanent Stable installer URL remains the same across releases:

~~~bash
bash -c 'set -e; umask 077; d=$(mktemp -d); trap '"'"'rm -rf -- "$d"'"'"' EXIT; curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 --connect-timeout 10 --max-time 120 -o "$d/stl-bootstrap.sh" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl-bootstrap.sh"; bash -n "$d/stl-bootstrap.sh"; bash "$d/stl-bootstrap.sh"'
~~~

The wrapper downloads the release's tag-pinned bootstrap into a private
temporary directory and checks download completion and shell syntax
before running it. The canonical installer verifies checksums, build
identity and installed-file ownership. A checksum supplied by the
same publisher is **not** an independent publisher signature: review
the official release, source and installer before privileged execution.

By default, the installer selects GRE/IPIP and WireGuard prerequisites.
It opens the guided menu on an interactive terminal; otherwise run:

~~~sh
sudo stl menu
~~~

Verify the installed version with `stl version --json`.
For IPsec, preparation may require separately approved signed packages
and an exclusively attested private service. STL must not silently
take over another VPN installation.

### Local installation without GitHub access on the server

**One file, one folder, one command** on a release that actually publishes the
new `*_local-install.sh` files. On an Internet-connected device, choose **one**
architecture-specific file from that release's official assets:

| Destination CPU (`uname -m`) | Download from the exact official release |
| --- | --- |
| `x86_64` | `stl_<version>_linux_amd64_local-install.sh` |
| `aarch64` | `stl_<version>_linux_arm64_local-install.sh` |

Upload the single file **as-is** into `/root/stl/` on the server (e.g. through
SFTP); the folder must be root-owned mode `0700` and the file root-owned
mode `0600` or `0644`. With just one file in the folder, run **as root**
(the command itself is a trusted pre-execution check, before any transferred
shell instruction):

~~~sh
bash -c 'set -euo pipefail; f=(/root/stl/*_local-install.sh); [[ $EUID == 0 && $(stat -c %u:%a /root) == 0:700 && $(stat -c %u:%a /root/stl) == 0:700 && ${#f[@]} == 1 && -f ${f[0]} && ! -L ${f[0]} && $(stat -c %u:%a "${f[0]}") =~ ^0:(600|644)$ ]] || { echo "STL: unsafe folder/file; require root-owned /root/stl (0700) and one file (0600/0644)" >&2; exit 1; }; n=$(stat -c %s -- "${f[0]}") || exit 1; [[ $n =~ ^[0-9]+$ && $n -gt 0 && $n -le 134250000 ]] || { echo "STL: installer file size must be 1..134250000 bytes" >&2; exit 1; }; d=$(mktemp -d /root/.stl-preflight.XXXXXXXX); trap '\''rm -rf -- "$d"'\'' EXIT; head -c "$n" -- "${f[0]}" > "$d/${f[0]##*/}"; [[ $(stat -c %s -- "$d/${f[0]##*/}") == "$n" ]]; cmp -s -- "${f[0]}" "$d/${f[0]##*/}"; bash "$d/${f[0]##*/}"'
~~~

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
**signed APT repositories**. IPsec preparation is separate. No WSS/Paqet
Carrier is shipped.

**Availability:** the published [v0.1.8 Stable](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.8)
contains the verified `.tar.gz` bundles, **not** this new `.sh` entrypoint.
Do not use this command with that archive or assume a not-yet-published asset
exists. The [installation guide](docs/INSTALL.md#local-installation-choose-a-published-asset)
lists the actual v0.1.8 files, manual fallback, release-link patterns for the
new file and actionable errors. Download only from a verified official release
and independently establish publisher/tag provenance before root execution;
embedded or same-account checksums are integrity checks, not an independent
publisher signature.

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

## Manage Links

For an on-demand overview of **all** saved tunnels, choose
**4 Test connectivity → A Check all tunnels** in the menu.
The result is a compact table of peer IPs, ICMP replies and observed
status; a missing Ping reply alone does not prove a tunnel is down.
A completed unanswered ping counts as measured packet loss, while a
canceled or failed probe remains unknown rather than invented loss.
Select an individual tunnel for detailed latency, MTU and counters.

~~~sh
sudo stl link list --json                    # Saved Link inventory
sudo stl link status YOUR_LINK_ID --json     # Owned local interface
sudo stl link diagnose YOUR_LINK_ID --json   # Peer Link Address probe / MTU
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
bash -c 'set -e; umask 077; d=$(mktemp -d); trap '"'"'rm -rf -- "$d"'"'"' EXIT; curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 --connect-timeout 10 --max-time 120 -o "$d/stl-bootstrap.sh" https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh; test -s "$d/stl-bootstrap.sh"; bash -n "$d/stl-bootstrap.sh"; bash "$d/stl-bootstrap.sh" update'
~~~

Installer binary rollback is **not** State rollback. Once a newer
runtime persists State schema v3, older pre-v3 binaries cannot read it.
See [safe update/rollback instructions](docs/INSTALL.md#persisted-state-v3-upgrade-and-safe-rollback-boundary).

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
