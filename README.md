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

### Local installation without international GitHub access

If a target server cannot reach GitHub, download the files **on another device**
from the same official tag, transfer them to a root-private `/root/stl/`
folder and run the canonical installer locally. No GitHub access, Go or Rust
compiler is required on the destination. For the **currently published
`v0.1.7` Stable** release (not a future unpublished bundle):

| Select/download on the Internet-connected device | Exact official `v0.1.7` source | Required? |
| --- | --- | --- |
| `stl_v0.1.7_linux_amd64` for `uname -m` = `x86_64` **OR** `stl_v0.1.7_linux_arm64` for `aarch64` | [Versioned release assets](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.7) | One architecture only |
| `SHA256SUMS`, `BUILD-MANIFEST.txt`, `LICENSE` | [Versioned release assets](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.7) | All three |
| `scripts/install.sh` from the **same `v0.1.7` source tag** | [Exact-tag canonical installer](https://github.com/ach1992/simple-tun-link/blob/v0.1.7/scripts/install.sh) | Required separately; **not** an asset in that release |
| `stl-bootstrap.sh` | [Versioned release assets](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.7) | Online use only; **not needed** locally |

Verify the release/tag and separately obtained installer source, transfer the
required files as regular files, and on the destination host run:

~~~sh
uname -m                     # choose only the matching architecture above
sudo install -d -m 0700 /root/stl
# Upload the selected files into /root/stl/ via SFTP/SCP before continuing.
sudo -i                      # commands below are from a root shell
cd /root/stl
sha256sum --check --ignore-missing SHA256SUMS
bash -n install.sh
bash ./install.sh install --bundle /root/stl --backends native,wireguard
stl version --json
~~~

The verified local folder must be owned by root, not a symlink, and mode
`0700`; the archive/release's own checksum file alone is **not** an
independent signature. On existing installer-owned installations, use an
explicit `update` for a newer version; a verified exact same-version `install`
is a no-op on releases with the new local-bundle support. The installer reuses
present prerequisites and uses only the server's configured **signed** APT
sources if a selected distro package is missing. If these sources cannot be
reached, the operator can **manually** choose an accessible officially signed
Debian/Ubuntu Iranian or regional mirror; STL never changes APT sources or
weakens package signatures.

Native GRE/IPIP needs **no extra GitHub helper**; WireGuard uses kernel support
and distro `wireguard-tools`; optional IPsec needs selected signed distro
strongSwan packages and separate service/consent checks. WSS and Paqet are
**not shipped Carriers** and require no download. The future per-architecture
`*_local-install.tar.gz` archives are under development and **not present in
v0.1.7**. For a future archive, independently verify its exact release digest
first, then use the **same canonical installer** streamed from that trusted
archive in `unpack` mode; it checks member types, sizes and a fresh private
extraction path before regular `install|update --bundle`. See [exact download, validation, mirror and rollback steps](docs/INSTALL.md)
and [release package inventory](docs/RELEASE-ARTIFACTS.md).


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
