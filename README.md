# Simple Tun Link (STL)

**Create and manage private IP links between Linux servers.** STL gives each
endpoint a private Link Address and handles Create, Import, Status, Diagnose,
Restore and Remove. Use its guided terminal menu or versioned CLI/JSON. A
saved Link is **not** proof that packets reach its peer.

## What STL supports

| Option | Connection | Encryption |
| --- | --- | --- |
| GRE / IPIP | Native IP, optionally FOU/GUE over UDP | No |
| L2TPv3 Direct-IP | Native IP protocol 115 | No |
| WireGuard | Native UDP | Yes |
| WireGuard over WSS/TLS | TCP/TLS plus kernel WireGuard; optional `wstunnel` | Yes |
| WireGuard over QUIC | QUIC/TLS plus kernel WireGuard; optional Hysteria (Plain or Salamander) | Yes |
| IPsec | Native IKEv2/XFRM, ESP or NAT-T; gated host preparation | Yes |

Different transports have different kernel, firewall, network and optional
helper requirements. STL does not automatically configure provider firewalls,
NAT or foreign VPNs, and no transport works through every network.

## Requirements

- Two supported Linux servers you administer; use a matching architecture
  (`x86_64` = AMD64, `aarch64` = ARM64). See
  [supported systems](docs/SUPPORTED-ENVIRONMENTS.md).
- Root privileges (or authorized `sudo`) for local network changes.
- An actually reachable public/underlay path for the selected transport.
- An accessible **signed** Debian/Ubuntu APT repository only when selected OS
  prerequisites are missing. STL does not overwrite APT sources.

## Install on both servers

Use the [latest official Stable release](https://github.com/ach1992/simple-tun-link/releases/latest).
Run this complete-download, syntax-checked installer on each server:

~~~bash
bash -c 'LC_ALL=C; s=$(set -o pipefail; curl -fsSL --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | head -c 131073 | tr "\000" "\001" && printf x) && (( ${#s} > 1 && ${#s} <= 131073 )) && [[ $s != *$(printf "\001")* ]] && s=${s%x} && bash -n <<<"$s" && bash -c "$s" stl "$@"' stl
~~~

It fetches a bounded, complete HTTPS bootstrap before execution. The verified
bootstrap and canonical installer then check the released artifact's checksums
and version/source identity. A publisher's own checksum is not an independent
signature; verify that you trust the official publisher before privileged use.
**Do not replace this command with an unchecked `curl | bash` pipeline.**

After installation, open the menu or verify the installed version:

~~~bash
sudo stl menu
stl version --json
~~~

Already installed? Use **Update**, not a new Install; see below. For a
specific older release, use the
[version-pinned procedure](docs/INSTALL.md#verified-stable-bootstrap-commands-latest-or-exact-stable-tag).

### Install when the server cannot reach GitHub

Download on another trusted device, verify the publisher and release, then
upload only the files you need to a root-owned, private `/root/stl/` folder:

| Function | AMD64 (`x86_64`) | ARM64 (`aarch64`) |
| --- | --- | --- |
| Core (required) | `stl_vX.Y.Z_linux_amd64_local-install.sh` | `stl_vX.Y.Z_linux_arm64_local-install.sh` |
| WSS (optional, wstunnel v11.0.0) | [`wstunnel_11.0.0_linux_amd64.tar.gz`](https://github.com/erebe/wstunnel/releases/download/v11.0.0/wstunnel_11.0.0_linux_amd64.tar.gz) | [`wstunnel_11.0.0_linux_arm64.tar.gz`](https://github.com/erebe/wstunnel/releases/download/v11.0.0/wstunnel_11.0.0_linux_arm64.tar.gz) |
| QUIC (optional, Hysteria app/v2.13.0) | [`hysteria-linux-amd64`](https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64) | [`hysteria-linux-arm64`](https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-arm64) |

Replace `vX.Y.Z` with the exact
[official Stable release tag](https://github.com/ach1992/simple-tun-link/releases/latest);
choose **only one** Core architecture. Use SFTP/SCP to transfer files
unchanged. Do not rename, extract, execute or `chmod +x` the downloaded
`.sh` file directly. For root-owned installation:

~~~bash
sudo install -d -o root -g root -m 0700 /root/stl
~~~

Then follow the [verified local one-command procedure](docs/INSTALL.md#one-transferred-file-and-one-trusted-command-new-release-format),
including `--with-wss` / `--with-quic` **only** for helpers you explicitly
downloaded. That procedure checks the file/directory trust boundary and
copies transferred bytes privately **before** executing any of them. The
Core package needs no GitHub, Go compiler or container on the destination.
If selected OS packages are missing, normal signed APT may still be needed.

To self-host an official, pinned version without GitHub on the destination,
see [HTTPS Mirror setup](docs/MIRROR.md). Generating mirror files does not
deploy a public mirror; do not assume a particular mirror already exists.

## Connect your first two servers

1. On **Server A**, run `sudo stl menu` → **Create tunnel**. Choose a
   transport (GRE/Native is the simplest plaintext default). Supply the
   reachable underlay peer address and review the proposed, non-overlapping
   private Link Addresses and local resource changes before typing `YES`.
2. **Share the Setup Link privately.** For WireGuard, WSS, QUIC and IPsec
   the handoff contains sensitive receiver credentials; never post it in
   logs, Issues, screenshots or public chat.
3. On **Server B**, choose **Import setup link**, paste the original offer
   and verify the reversed local/peer endpoints and exact receiver role.
   Confirm the import explicitly. WSS/QUIC can require manual selection of
   `Listen` or `Dial`: the suggested direction is **not** reachability proof.
4. Use **Test connectivity** on both hosts and test your application's
   private TCP/UDP traffic. Local interface health and peer-received packets
   are different observations.

For encrypted transport details, setup-link handling and advanced modes see
[CLI and operator workflows](docs/CLI.md) and [Pairing](docs/PAIRING.md).

## Manage and troubleshoot

~~~bash
sudo stl menu                              # Guided tasks
sudo stl link list --json                  # Saved links
sudo stl link status YOUR_LINK_ID --json   # Local ownership / state
sudo stl link diagnose YOUR_LINK_ID --json # Bounded peer reachability
sudo stl link diagnose --all --json        # Check all saved links
sudo stl doctor ipsec --json               # Read-only IPsec readiness
~~~

If an operation reports unknown/partial effects, do not blindly retry.
Follow [Diagnostics](docs/DIAGNOSTICS.md) and
[Operator Recovery](docs/OPERATOR-RECOVERY.md). To remove an owned Link, use
the guided confirmation in **My tunnels** or:

~~~bash
sudo stl link remove YOUR_LINK_ID --confirm YOUR_LINK_ID
~~~

Removing one Link must not tear down unrelated Links, services or host
resources. Uninstall has its own explicit safety gates and never implicitly
removes a live Link.

## Update and uninstall

Back up protected State/credentials and any original sensitive receiver
handoffs before upgrading. For an existing installer-owned STL, use:

~~~bash
bash -c 'LC_ALL=C; s=$(set -o pipefail; curl -fsSL --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | head -c 131073 | tr "\000" "\001" && printf x) && (( ${#s} > 1 && ${#s} <= 131073 )) && [[ $s != *$(printf "\001")* ]] && s=${s%x} && bash -n <<<"$s" && bash -c "$s" stl "$@"' stl update
~~~

State and executable rollback are **not** the same: newer managed features
use State v6, so an older binary might not understand the retained State.
Read [Update, recovery, rollback and uninstall](docs/INSTALL.md#update)
before downgrading or removing the installation. A GitHub-restricted host
uses the explicit [Mirror Update](docs/MIRROR.md#3-clean-install-and-explicit-update)
or [local installer](docs/INSTALL.md#one-transferred-file-and-one-trusted-command-new-release-format)
path instead of the built-in GitHub release picker.

## Documentation

- **Users:** [Install and Update](docs/INSTALL.md),
  [CLI/Menu](docs/CLI.md), [Diagnostics](docs/DIAGNOSTICS.md),
  [Operator Recovery](docs/OPERATOR-RECOVERY.md) and
  [Supported environments](docs/SUPPORTED-ENVIRONMENTS.md).
- **Developers and integrators:** [Project Specification](docs/PROJECT-SPEC.md),
  [Architecture](docs/ARCHITECTURE.md), [Pairing](docs/PAIRING.md),
  [Security](docs/SECURITY.md), [Development](docs/DEVELOPMENT.md)
  and [Release verification](docs/RELEASE-ARTIFACTS.md).
- **Latest release and changes:** [GitHub Releases](https://github.com/ach1992/simple-tun-link/releases).
  Outstanding accepted work is managed in
  [GitHub Issues](https://github.com/ach1992/simple-tun-link/issues),
  not in this user guide.

[MIT License](LICENSE)
