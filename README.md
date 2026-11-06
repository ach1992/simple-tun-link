# Simple Tun Link (STL)

**Create and manage private IP links between Linux servers.** STL gives each
endpoint a private Link Address and handles Create, Import, Status, Diagnose,
Restore and Remove. Use its guided terminal menu or versioned CLI/JSON. A
saved Link is **not** proof that packets reach its peer.

## What STL supports

| Option | Connection | Encryption |
| --- | --- | --- |
| GRE / IPIP | Native IP protocols 47 / 4, optionally FOU/GUE over UDP | No |
| L2TPv3 Direct-IP | Native IP protocol 115 | No |
| WireGuard | Native UDP | Yes |
| WireGuard over WSS/TLS | TCP/TLS plus kernel WireGuard; optional `wstunnel` | Yes |
| WireGuard over QUIC | QUIC/TLS plus kernel WireGuard; optional Hysteria (Plain or Salamander) | Yes |
| IPsec | Native IKEv2/XFRM, ESP or NAT-T; gated host preparation | Yes |

Different transports have different kernel, firewall, network and optional
helper requirements. STL does not automatically configure provider firewalls,
NAT or foreign VPNs, and no transport works through every network.

## Requirements

- Two Linux servers you administer. The installer supports Ubuntu 22.04+ or
  Debian 11+, Linux kernel 5.4+, iproute2 5.1+ and AMD64 (`x86_64`) or ARM64
  (`aarch64`); systemd provides reboot restoration. Check each backend's
  additional capabilities in [supported systems](docs/SUPPORTED-ENVIRONMENTS.md).
- Root privileges (or authorized `sudo`) for local network changes.
- An actually reachable public/underlay path for the selected transport.
- An accessible **signed** Debian/Ubuntu APT repository only when selected OS
  prerequisites are missing. STL does not overwrite APT sources.

## Install on both servers

Choose **one** source for the initial install:

| Target connectivity | Installation path |
| --- | --- |
| GitHub reachable | Use the complete-download **official Latest Stable** command below |
| GitHub blocked; trusted file transfer available | Transfer one architecture-matched, independently SHA256-verified release file and use the [guarded local command](docs/INSTALL.md#one-transferred-file-and-one-trusted-command-new-release-format) |
| GitHub blocked; approved HTTPS mirror reachable | Use the independently pinned [Mirror install command](docs/MIRROR.md#3-clean-install-and-explicit-update) generated on the trusted preparation device |

Never run the transferred shell file directly or use an unchecked `curl | bash` command. The local/Mirror first hop must authenticate a complete private copy **before** shell execution. These options use one canonical installer; a Mirror must be prepared and approved independently, not presumed available.

Use the [latest official Stable release](https://github.com/ach1992/simple-tun-link/releases/latest).
Run this complete-download, syntax-checked installer on each server:

~~~bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl
~~~

It fetches a bounded, complete HTTPS bootstrap into an owned temporary file before execution. The verified
bootstrap and canonical installer then check the released artifact's checksums
and version/source identity. Since Stable `v0.1.23`, the official bootstrap
also pins the canonical installer's exact SHA256 **before privilege
elevation**. The older published `v0.1.22` predates that hardening.
A publisher's own checksum is not an independent
signature; verify that you trust the official publisher before privileged use.
**Do not replace this command with an unchecked `curl | bash` pipeline.**
The initial `/usr/bin/env -i` excludes inherited `BASH_ENV`, exported
functions and untrusted `PATH` before starting Bash. Since `v0.1.23`,
privileged Bash executes only an independently digest-matched root-private
snapshot, never the user-owned downloaded pathname. If HTTPS requires a
proxy or private CA, add only explicit, reviewed `HTTPS_PROXY=...`, `NO_PROXY=...` and/or
`CURL_CA_BUNDLE=/trusted/ca.pem` assignments **between `PATH=...` and
`/bin/bash`** in the first command. Those three values alone are forwarded
to the privileged installer; do not use `sudo -E` or include proxy passwords
in commands or shell history. Missing distro packages still use the
host's separately configured signed APT repository/proxy.

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

An operator-managed HTTPS Mirror is available at
`https://stl.gitscripts.ir/install.sh` for the verified, exact `v0.1.23`
release. Its trusted first-hop SHA256 and precise validation are recorded in
[HTTPS Mirror setup](docs/MIRROR.md). Mirror selection is **explicit and
version-pinned**, not an automatic fallback or substitute for trusting the
publisher. Generating future Mirror files alone does not deploy them.

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
   For IPsec, complete separately confirmed preparation and select
   **My tunnels → Connect IPsec** on either peer after Import; Import alone
   does not initiate IKEv2.
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

For builds including the new Update source selector, `sudo stl menu`
→ **Update** → **Verified local file** or **Trusted HTTPS mirror**
provides the same SHA256-pinned CLI path with an explicit `UPDATE`
confirmation and no GitHub API dependency. This menu was first published
in `v0.1.23`; older installed `v0.1.22` binaries must use their documented
verified Update commands to upgrade before selecting the new menu.

Back up protected State/credentials and any original sensitive receiver
handoffs before upgrading. An installed STL release that supports the
`stl update` command can update **without GitHub/API access** using an
independently verified local file or a pinned HTTPS mirror:

~~~bash
sudo stl update --local /root/stl/stl_vX.Y.Z_linux_ARCH_local-install.sh --sha256 TRUSTED_FILE_SHA256
sudo stl update --mirror https://YOUR_TRUSTED_MIRROR/install.sh --sha256 TRUSTED_BOOTSTRAP_SHA256
~~~

Choose **one** method, replace the examples with the actual exact-version
asset and SHA256 obtained independently from the trusted downloading/mirror
preparation device. Never take the trust digest from the same untrusted mirror.
The second command requires a previously prepared, independently pinned HTTPS
mirror. These commands are available starting with installed `v0.1.23`;
older installed Stable versions (including `v0.1.22`) must use their
already supported verified manual procedures.

For an existing installer-owned STL that reaches official GitHub, use:

~~~bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl update
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
