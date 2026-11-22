# Simple Tun Link (STL)

**Create and manage private IP links between Linux servers.** Install STL on
both endpoints, create a Link on one host, transfer its Setup Link securely,
then verify real two-way traffic. A saved Link or running interface does
**not** prove peer connectivity.

STL provides a guided terminal menu and versioned CLI/JSON. Each Link has
independent State, owned resources, diagnostics, Restore and Remove.

## Choose a transport

| Transport | Underlay | Encrypted? |
| --- | --- | --- |
| GRE / IPIP | Native IP 47 / 4; optional FOU/GUE over UDP | No |
| L2TPv3 Direct-IP | Native IP 115 | No |
| WireGuard | Kernel WireGuard over UDP | Yes |
| WireGuard over WSS | WebSocket/TLS/TCP with kernel WireGuard | Yes |
| WireGuard over QUIC | QUIC/TLS with kernel WireGuard and optional helper | Yes |
| IPsec | IKEv2/XFRM; native ESP or NAT-T | Yes |
| [MASQUE CONNECT-IP](docs/MASQUE-CARRIER.md) | IPv4 TUN over authenticated HTTP/2/TLS | Yes |
| [Spoof Direct TUN](docs/SPOOF-CARRIER.md) | Noise-authenticated private IPv4 over selected raw outer formats | Yes |

**GRE/Native is the simplest plaintext default.** No method works through
every ISP, kernel or firewall. STL tests actual host capabilities, reuses
working prerequisites and installs genuinely missing selected tools through
the existing **signed APT** repository. It does not automatically rewrite
APT sources or interfere with foreign VPN services.

**Spoof (Stable v0.1.34+):** Each endpoint selects from its own
operator-supplied Source IPv4 list and can reconnect using authenticated
previously working routes without a second setup. Isolated tests established
private ICMP/TCP/UDP delivery, but **public ISP/WAN reachability and provider
anti-spoof/NAT traversal remain unverified**. TCP/GRE/L2TPv3-shaped packet
wrappers are not the respective native protocols. See its
[operator guide](docs/SPOOF-CARRIER.md) and
[field acceptance](https://github.com/ach1992/simple-tun-link/issues/262).

## Requirements

- Two Linux servers under your administration, with a usable underlay
  for the selected transport and root/authorized `sudo` for host changes.
- Release binaries for AMD64 (`x86_64`) or ARM64 (`aarch64`); systemd for
  automatic Restore after a host reboot.
- Actual kernel and tool capabilities matter more than distro version.
  Maintained qualification starts with kernel 5.4+ and iproute2 5.1+.

See [supported environments](docs/SUPPORTED-ENVIRONMENTS.md) for
method-specific requirements and qualification limits.

## Install on both servers

Choose **one trusted source**. Never execute a partially downloaded
privileged script.

| Network access | Install path |
| --- | --- |
| Official GitHub reachable | Guarded **Latest Stable** command below |
| GitHub blocked; trusted HTTPS Mirror reachable | Download the complete, architecture-matched original `*_local-install.sh`; see [Mirror guide](docs/MIRROR.md#simple-copy-as-is-mirror-recommended) |
| No GitHub/Mirror on the server | Transfer the verified release file from another machine; see [offline install](docs/INSTALL.md#one-transferred-file-and-one-trusted-command-new-release-format) |

The following command downloads the complete official
[Latest Stable](https://github.com/ach1992/simple-tun-link/releases/latest),
validates its bounded shell bootstrap and uses the canonical
release-verified Installer:

~~~bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM-}" ${NO_COLOR+NO_COLOR=1} STL_NO_CLEAR="$([ "${STL_NO_CLEAR:-}" = 1 ] && printf 1)" /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl
~~~

The guarded first hop starts in a clean environment and verifies the
release-bound canonical Installer before privilege elevation. Follow
[installation instructions](docs/INSTALL.md) for proxy or private-CA
setups; avoid `sudo -E`. Trusting a third-party Mirror over HTTPS is
not independent proof of publisher identity. Optional independently
pinned verification is documented for those who need it.

~~~bash
sudo stl menu
stl version --json
~~~

## Create and verify a Link

1. On **Server A**, select **Create tunnel**, a transport and private Link
   Addresses. Review all proposed host changes before confirmation.
2. Transfer its **Setup Link or confidential Setup Code** to Server B
   through a trusted channel. For encrypted transports this handoff may
   contain credentials; never paste it into public logs or Issues.
3. On **Server B**, select **Import setup link** (or the carrier-specific
   Import), check both endpoints and confirm. IPsec has a separate
   consent-based PREPARE/Connect step.
4. Use **Test connectivity** on both hosts and check real application
   TCP/UDP traffic; local readiness and delivered traffic are different.

Advanced workflows: [CLI/Menu](docs/CLI.md) and [Pairing](docs/PAIRING.md).

## Observe, recover and remove

~~~bash
sudo stl menu
sudo stl link list --json
sudo stl link status YOUR_LINK_ID --json
sudo stl link diagnose YOUR_LINK_ID --json
sudo stl link diagnose --all --json
sudo stl link remove YOUR_LINK_ID --confirm YOUR_LINK_ID
~~~

For partial/unknown outcomes, inspect first:
[Diagnostics](docs/DIAGNOSTICS.md) and
[Operator recovery](docs/OPERATOR-RECOVERY.md).
Uninstall has its own ownership checks and never implicitly removes a
live Link.

**Update:** Use `sudo stl menu` → **Update**, or a separately trusted
complete Release/Mirror file with
`sudo stl update --url HTTPS_RELEASE_FILE_URL`.
For GitHub Update, use the independently tested official command:

~~~bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM-}" ${NO_COLOR+NO_COLOR=1} STL_NO_CLEAR="$([ "${STL_NO_CLEAR:-}" = 1 ] && printf 1)" /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl update
~~~

**First MIT → AGPL upgrade:** older releases (including `v0.1.34`)
embed an MIT-only artifact validator. Their own `stl update --url` may
reject the new AGPL manifest; use the **new** architecture-matched
one-file Installer with explicit `--update` (or the new official Stable
bootstrap), not a manually edited manifest. Preserve protected State and
original confidential setup material before changing versions; see
[Update, rollback and Uninstall](docs/INSTALL.md#update). A newer State
may not be readable by an older binary.

## Documentation by task

| What I need | Reference |
| --- | --- |
| Install, Update, Uninstall, diagnose installer errors | [Install](docs/INSTALL.md) |
| Menu steps, CLI commands and JSON contracts | [CLI reference](docs/CLI.md) |
| Diagnose, Restore, environment compatibility | [Diagnostics](docs/DIAGNOSTICS.md), [Recovery](docs/OPERATOR-RECOVERY.md), [Supported environments](docs/SUPPORTED-ENVIRONMENTS.md) |
| Configure advanced carriers or Mirror | [Spoof](docs/SPOOF-CARRIER.md), [MASQUE](docs/MASQUE-CARRIER.md), [Mirror](docs/MIRROR.md) |
| Design, security and contributor guidance | [Specification](docs/PROJECT-SPEC.md), [Architecture](docs/ARCHITECTURE.md), [Security](docs/SECURITY.md), [Development](docs/DEVELOPMENT.md) |
| Build and verify published packages | [Release artifacts](docs/RELEASE-ARTIFACTS.md) |

[GitHub Releases](https://github.com/ach1992/simple-tun-link/releases)
define published versions; [GitHub Issues](https://github.com/ach1992/simple-tun-link/issues)
track distinct outstanding work. Field evidence applies only to the
specified version/hosts, not every network.

## License

Current source distributions use the **GNU Affero General Public License
v3.0 only** (`AGPL-3.0-only`). Copyright © 2026 ach1992.
See the complete [LICENSE](LICENSE) or run `stl license` for the
read-only license/source summary. There is **no warranty**; the
corresponding source is available in this repository. Previously
published `v0.1.34` and earlier releases retain their **MIT** grants;
the change is not retroactive. Third-party dependencies keep their own
licenses and required notices.
