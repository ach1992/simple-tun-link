# Simple Tun Link (STL)

**Create, connect and manage private IP tunnels between Linux servers.**

Simple Tun Link gives two servers private tunnel IP addresses so that
applications can communicate over a chosen network transport. It combines
a guided terminal menu with command-line tools for day-to-day operation:
create a tunnel, connect the other server, check connectivity, restore
saved links, and remove a link when it is no longer needed.

STL can manage **multiple independent tunnels on the same host**. You do
not need to manually assemble each tunnel's interfaces and persistence
configuration. The two servers still need a usable network path for the
transport you select.

## Features and connection methods

- **Guided setup:** create a tunnel on one server, securely transfer its
  Setup Link/Code, and import it on the other server.
- **Several transport options:** choose a native/plaintext tunnel or an
  authenticated, encrypted connection suitable for your network.
- **Manage each tunnel:** inspect saved links, check the peer connection,
  view connection details, share the original setup information, or remove
  just the selected tunnel.
- **Persistence and recovery:** STL manages its own systemd-backed
  restoration and reports failures without silently taking over unrelated
  VPN services or networking.
- **CLI/JSON:** use the same Link-management commands from the terminal
  or scripts without depending on the interactive menu.

| Method | Protection | When to consider it |
| --- | --- | --- |
| **GRE / IPIP** (Native, optional FOU/GUE) | Not encrypted | Simple server-to-server tunnels where the necessary IP protocol/UDP path is reachable |
| **L2TPv3 Direct-IP** | Not encrypted | Direct-IP pseudowire on networks allowing IP protocol 115 |
| **WireGuard** | Encrypted | A straightforward private connection over reachable UDP |
| **WireGuard over WSS** | Encrypted | WireGuard carried over WebSocket/TLS (TCP); requires the supported companion |
| **WireGuard over QUIC** | Encrypted | WireGuard carried over QUIC/TLS (UDP); requires the supported companion |
| **IPsec / IKEv2** | Encrypted | IPsec with separately confirmed host preparation and connection |
| **MASQUE CONNECT-IP** | Encrypted | Private IP over authenticated HTTP/2/TLS |
| **Spoof Direct TUN** | Encrypted | Source/profile-based private IP transport when its actual network path permits it |

The choice depends on kernel features, firewalls, the provider's network
policies, and optional helpers. **A saved or running tunnel is not proof
of two-way traffic.** Spoof has passed isolated multi-host tests and a
bounded real-WAN test with a forged Source in one direction and a real
Source in the return direction, including private ICMP/TCP/UDP. The
strict follow-up excluded both real Sources and tried 23 candidates across
eight profiles in each direction; none of the UK-origin forged candidates
arrived in Iran. See the
[Spoof operator guide](docs/SPOOF-CARRIER.md#verification-boundaries-and-historical-evidence)
for exact evidence and remaining qualification. No single method is
guaranteed to work on every network.

## Requirements

- **Two Linux servers** you control, with a network path usable by the
  selected transport. The other server does not have to be online at
  the moment you create its local configuration.
- **AMD64** (x86_64) or **ARM64** (aarch64), with administrator
  (root/authorized sudo) access for networking changes.
- A supported **Debian/Ubuntu-class environment** with the required
  kernel capabilities and systemd for automatic restoration. STL reuses
  functioning tools and installs selected missing prerequisites from the
  server's existing **signed APT** sources when necessary.

See [supported environments](docs/SUPPORTED-ENVIRONMENTS.md) for the
actual method-specific requirements; package and OS version labels
alone do not establish compatibility.

## Install STL on both servers

With access to the official [Latest Stable release](https://github.com/ach1992/simple-tun-link/releases/latest),
run this **complete-download, checked bootstrap** on each server.
It verifies its downloaded release inputs before installation instead
of executing an unchecked partial download:

~~~bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM-}" ${NO_COLOR+NO_COLOR=1} STL_NO_CLEAR="$([ "${STL_NO_CLEAR:-}" = 1 ] && printf 1)" /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl
~~~

On an interactive terminal, installation normally opens the guided menu.
To reopen STL or check the installed release:

~~~bash
sudo stl menu
stl version
~~~

**No GitHub access from a server?** Download the complete, matching
AMD64/ARM64 release installer through an explicitly trusted
[HTTPS Mirror](docs/MIRROR.md#simple-copy-as-is-mirror-recommended), or
transfer the official file from another machine and follow the
[offline installation steps](docs/INSTALL.md#one-transferred-file-and-one-trusted-command-new-release-format).
You do not need a Go toolchain on the destination server.

## Connect your first two servers

1. **Server A — Create:** Run `sudo stl menu` → **Create tunnel**.
   Pick a method, enter the other server's reachable address, and review
   the proposed local/remote private IPs and changes before confirming.
   GRE Native is the simplest **unencrypted** starting option.
2. **Share the setup:** Use the Setup Link/Code provided after Create,
   or **My tunnels → Share Setup Link** to retrieve the saved original
   where supported. **Keep encrypted-method credentials private.**
3. **Server B — Import:** Run `sudo stl menu` →
   **Import setup link**, select the corresponding connection method,
   provide the complete Setup Link or protected setup file, review the
   endpoints and confirm. **Spoof uses a confidential Setup Code file,
   not a normal pasted `stl://` line.**
4. **Connect if necessary:** For **IPsec**, after setup on both hosts,
   choose **My tunnels → Connect IPsec** on either peer. Import alone
   does not initiate that connection.
5. **Verify both sides:** Choose **Test connectivity** on both servers,
   and then test the actual application traffic using the peer's private
   IP address. Connection status alone cannot prove delivered packets.

You can also configure **native GRE/IPIP manually on both hosts**,
without exchanging a Setup Link; the local and peer private addresses
must be reversed on Server B. See
[manual pairing instructions](docs/CLI.md#manual-greipip-native-pairing-no-setup-link).

Once the tunnel works, use its **private IP addresses** for your
application's connection. For example, if Server B has the tunnel IP
`10.235.1.2`, Server A can check that address and use an application
such as SSH *if the corresponding service and firewall allow it*:

~~~bash
ping -c 3 10.235.1.2
ssh username@10.235.1.2
~~~

The address above is **only an example**; use the actual peer address
shown by STL.

## Everyday commands

The interactive menu covers **Create**, **Import**, **My tunnels**,
**Test connectivity**, **Settings**, **Update** and **Uninstall**.
For quick observation from the terminal, use:

~~~bash
stl help
stl version
sudo stl link list
sudo stl link status YOUR_LINK_ID
sudo stl link diagnose YOUR_LINK_ID
sudo stl link diagnose --all
~~~

Replace `YOUR_LINK_ID` with the ID shown by `sudo stl link list`.
Add `--json` to the supported commands if you need machine-readable
output. `status` checks local ownership/state; `diagnose`
also probes peer reachability, so neither should be mistaken for
a complete application test.

For an **optional throughput test**, first run an `iperf3` listener
on the peer's actual private address; then use the confirmed
`stl link throughput` operation described in
[connectivity diagnostics](docs/CLI.md#diagnostics-and-explicit-traffic).
This generates test traffic and is not required for normal use.

To remove **one** saved tunnel, choose
**My tunnels → Remove this tunnel** and confirm. The equivalent
explicit CLI operation is:

~~~bash
sudo stl link remove YOUR_LINK_ID --confirm YOUR_LINK_ID
~~~

Removing a tunnel may disconnect applications using it. STL checks
ownership of local resources and does not silently remove other links.
If removal or another operation reports partial/unknown effects, use
[recovery guidance](docs/OPERATOR-RECOVERY.md) before trying again.

## Update or uninstall

Use `sudo stl menu` → **Update** to choose an available
official GitHub release, an operator-trusted complete HTTPS release
file, or another verified local/Mirror method. The supported choices
depend on the version currently installed.

For installed versions supporting HTTPS release-file updates:

~~~bash
sudo stl update --url https://YOUR_TRUSTED_MIRROR/releases/vX.Y.Z/stl_vX.Y.Z_linux_ARCH_local-install.sh
~~~

Replace the URL, tag and architecture with a **real matching release
file** from a server you trust. This method trusts the chosen HTTPS
source; it is not independent publisher verification. Read
[installation and update options](docs/INSTALL.md#update), including
[the first MIT → AGPL upgrade](docs/INSTALL.md#first-upgrade-from-mit-releases-to-agpl).

For **Uninstall**, use `sudo stl menu` → **Uninstall**.
The program checks for active/pending tunnels and does **not**
silently erase them. Remove the selected tunnels first, then follow
the guided cleanup.

## Help and documentation

| Task | Guide |
| --- | --- |
| Install, offline transfer, Mirror, Update, uninstall | [Installation and updates](docs/INSTALL.md), [Mirror](docs/MIRROR.md) |
| Interactive menu, advanced CLI and protected handoffs | [CLI and operator workflow](docs/CLI.md), [Pairing](docs/PAIRING.md) |
| Connection fails, uncertain cleanup or restoration | [Diagnostics](docs/DIAGNOSTICS.md), [Operator recovery](docs/OPERATOR-RECOVERY.md) |
| Compatibility, ports and prerequisites | [Supported environments](docs/SUPPORTED-ENVIRONMENTS.md) |
| Configure less common transports | [Spoof](docs/SPOOF-CARRIER.md), [MASQUE](docs/MASQUE-CARRIER.md) |
| Contribute or understand the design | [Project specification](docs/PROJECT-SPEC.md), [Development](docs/DEVELOPMENT.md) |

Published builds and changes: [GitHub Releases](https://github.com/ach1992/simple-tun-link/releases).
Outstanding work and field qualification:
[GitHub Issues](https://github.com/ach1992/simple-tun-link/issues).

## License

Copyright © 2026 ach1992. New source distributions use
**GNU Affero General Public License v3.0 only**
([AGPL-3.0-only](LICENSE)); see the [legal notices](THIRD-PARTY-NOTICES.txt).
Previously published `v0.1.34` and earlier releases retain their
original MIT terms.
