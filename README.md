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
| WireGuard over WSS/TLS | Genuine TLS/TCP + WebSocket plus kernel WireGuard; optional private mTLS or public TLS handshake (authorized Upgrade still requires Link bearer) | Yes |
| WireGuard over QUIC | QUIC/TLS plus kernel WireGuard; pinned Hysteria (Plain/mTLS, Plain/public HTTP/3, Salamander) | Yes |
| IPsec | Native IKEv2/XFRM, ESP or NAT-T; gated host preparation | Yes |
| MASQUE CONNECT-IP (v0.1.28+) | Native IPv4 TUN over HTTP/2 TLS/TCP; private mTLS default and optional request-bearer Public TLS where available in the installed build | Yes |

**In development, NOT in the published Stable release:** the
[Spoof Direct TUN Carrier](docs/SPOOF-CARRIER.md) (Issue #262) encrypts
private IPv4 ICMP/TCP/UDP within one authenticated managed Link.
Its `Auto` policy searches local operator-supplied Source IPv4 addresses
and STL-owned raw outer packet formats: UDP, unsolicited ICMP Echo Reply,
TCP-looking RST packets, GRE-shaped, nested IPIP, bare/echo-shaped protocol
58 and an L2TPv3-style protocol-115 data header. Both endpoints can choose
different outbound Source/profile combinations, save authenticated working
pairs across restarts, and retry previously working pairs before exhaustive
rediscovery. Operators can instead pin a local outgoing profile.
**All eight outer packet profiles have carried bilateral authenticated private
ICMP in two isolated Linux containers.** This is not proof of public WAN
reachability, stealth or full native GRE/IPIP/L2TP interoperability. In
particular, TCP-looking packets are **not** a real established TCP connection
and the protocol-115 option is **not** STL's existing native L2TPv3 Backend.
No Spoof code has been merged into Stable or deployed to real production
servers. See the [operator guide](docs/SPOOF-CARRIER.md) for actual support,
source-list capacity, exact testing and remaining gates.

Different transports have different kernel, firewall, network and optional
helper requirements. STL does not automatically configure provider firewalls,
NAT or foreign VPNs, and no transport works through every network.

**Release and mode compatibility:** MASQUE private mTLS first shipped in
Stable `v0.1.28`. Opt-in QUIC Plain HTTP/3, WSS Public TLS and MASQUE
Public TLS (bearer-authorized CONNECT-IP and same-listener HTTP/2 GET/HEAD)
arrived in `v0.1.29`. Subsequent releases improved MTU admission,
guided MASQUE MTU selection, resource-collision checks and recovery.
Check the **installed version** and [official Release notes](https://github.com/ach1992/simple-tun-link/releases)
before choosing a mode; private mTLS remains the default where applicable.

Physical two-server traffic and same-Link automatic recovery after a full OS
reboot have release- and host-specific [acceptance evidence](https://github.com/ach1992/simple-tun-link/issues/142).
Distinct ISP/NAT and native physical ARM64 coverage remains tracked in
[field acceptance](https://github.com/ach1992/simple-tun-link/issues/93).
Neither local readiness nor a successful field path guarantees all provider
networks or browser-identical TLS fingerprints. See
[supported environments](docs/SUPPORTED-ENVIRONMENTS.md) for QUIC MTU bounds
and the [MASQUE guide](docs/MASQUE-CARRIER.md) for transport details.

## Requirements

- Two Linux servers you administer. The installer supports Debian/Ubuntu
  signed APT environments without an arbitrary numeric OS-version floor.
  Maintained release testing starts with kernel 5.4+ and iproute2 5.1+;
  actual backend/kernel capabilities, rather than version strings alone,
  determine availability. Published binaries target AMD64 (`x86_64`) and
  ARM64 (`aarch64`); systemd provides reboot restoration. See
  [supported environments](docs/SUPPORTED-ENVIRONMENTS.md) for conditional
  requirements, compatibility scope, and older-release caveats.
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
| GitHub blocked; operator-trusted HTTPS mirror reachable | Copy the official Release assets unchanged; download the architecture-matched `*_local-install.sh` and install it using the [simple Mirror instructions](docs/MIRROR.md#simple-copy-as-is-mirror-recommended) |

Do not pipe an unfinished download into a privileged shell. With the simple Mirror path, the operator explicitly trusts the chosen HTTPS server, downloads the **complete original Release file** to protected storage and runs the same build-bound canonical installer. No per-install SHA256 entry or separate signing system is required. Independent publisher verification is not implied by trusting a Mirror; the optional pinned and signed paths remain available.

Use the [latest official Stable release](https://github.com/ach1992/simple-tun-link/releases/latest); check its published tag and release assets before installing.
Run this complete-download, syntax-checked installer on each server:

~~~bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM-}" ${NO_COLOR+NO_COLOR=1} STL_NO_CLEAR="$([ "${STL_NO_CLEAR:-}" = 1 ] && printf 1)" /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl
~~~

The explicit `TERM="${TERM-}"` preserves the actual terminal type, including
unset/empty values, without guessing `xterm`. A real TTY with missing `TERM`
can still redraw its screen **without colored styling**. `${NO_COLOR+NO_COLOR=1}`
passes the color opt-out only when present (including an empty value).
`STL_NO_CLEAR=1` is normalized and preserved as an explicit append-only menu
preference; other values do not enable it. The non-root `sudo` menu handoff
restores only these menu settings after installation; the canonical privileged
installer retains its separate clean environment. Explicit `TERM=dumb`,
`STL_NO_CLEAR=1` or redirected output disables ANSI screen controls; otherwise
the menu replaces the visible installer output while preserving scrollback.

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

Since Stable `v0.1.24`, successful interactive Install and Update automatically
launch the menu using the canonical absolute executable path, even when the
hardened bootstrap `PATH` excludes `/usr/local/bin`. If using `v0.1.23`, the
installer may have succeeded even if its last automatic menu launch failed;
run `/usr/local/bin/stl menu` as root or `/usr/bin/sudo /usr/local/bin/stl menu`
from an authorized non-root account.

Stable `v0.1.25` adds complete local canonical installer/APT diagnostic streaming,
accurate failure stages and exit codes, and preserved `NO_COLOR` in clean
bootstrap and non-root menu handoffs. It does not change persisted Link State,
network configuration or the independently verified Mirror trust procedure.

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

You can use **any HTTPS Mirror that copies official GitHub Release assets
byte-for-byte**. Choose the matching `*_local-install.sh` URL and follow the
[simple Mirror installation](docs/MIRROR.md#simple-copy-as-is-mirror-recommended).
No additional signer, special bootstrap or per-install SHA256 is required.
To update an already installed compatible STL, use `sudo stl update --url
https://YOUR_MIRROR/PATH/stl_vX.Y.Z_linux_ARCH_local-install.sh`. The operator
chooses and trusts the URL; Mirror TLS does not independently authenticate
the GitHub publisher. Advanced pinned/signed options remain available.
STL does not prescribe a default Mirror or fallback source.

## Connect your first two servers

1. On **Server A**, run `sudo stl menu` → **Create tunnel**. Choose a
   transport (GRE/Native is the simplest plaintext default). Supply the
   reachable underlay peer address and review the proposed, non-overlapping
   private Link Addresses and local resource changes before typing `YES`.
2. **Share the Setup Link privately.** For WireGuard, WSS, QUIC, IPsec and MASQUE
   the handoff contains sensitive receiver credentials; never post it in
   logs, Issues, screenshots or public chat.
3. On **Server B**, choose **Import setup link**, paste the original offer
   and verify the reversed local/peer endpoints and exact receiver role.
   Confirm the import explicitly. WSS/QUIC/MASQUE support the
   `Listen` or `Dial` endpoint roles: the suggested direction is **not**
   reachability proof.
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
→ **Update** → **HTTPS release file** accepts the URL of an original
GitHub Release `*_local-install.sh` hosted on any explicitly trusted HTTPS
Mirror, without a typed SHA256 or separate signer. The menu requires fresh
`UPDATE` confirmation. The previously published `v0.1.23` menu did **not**
have this direct-asset option: use the downloaded newer one-file installer
with explicit `--update` to upgrade an older installation.

Back up protected State/credentials and any original sensitive receiver
handoffs before upgrading. A new STL that supports direct HTTPS release-file
Update can use a **literal copied official file** with no GitHub API:

~~~bash
sudo stl update --url https://YOUR_MIRROR/releases/vX.Y.Z/stl_vX.Y.Z_linux_ARCH_local-install.sh
~~~

The operator explicitly trusts that HTTPS host. Advanced SHA256-pinned local
and bootstrap alternatives (both available from `v0.1.23`) remain supported:

~~~bash
sudo stl update --local /root/stl/stl_vX.Y.Z_linux_ARCH_local-install.sh --sha256 TRUSTED_FILE_SHA256
sudo stl update --mirror https://YOUR_MIRROR/install.sh --sha256 TRUSTED_BOOTSTRAP_SHA256
~~~

Choose one method and use a real published tag/architecture. Only the pinned
modes require a separately obtained hash. To upgrade an older installed STL
lacking `--url`, download the original newer one-file asset, then run it
with `--update` as in [MIRROR.md](docs/MIRROR.md#simple-copy-as-is-mirror-recommended).

For an existing installer-owned STL that reaches official GitHub, use:

~~~bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM-}" ${NO_COLOR+NO_COLOR=1} STL_NO_CLEAR="$([ "${STL_NO_CLEAR:-}" = 1 ] && printf 1)" /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl update
~~~

State and executable rollback are **not** the same: the current runtime
writes State v7 (MASQUE-aware); an older binary might not understand the
retained State. Historical v6-to-v5 empty-State downgrade documentation
does **not** authorize directly downleveling v7 or stripping receipts.
Read [Update, recovery, rollback and uninstall](docs/INSTALL.md#update)
before downgrading or removing the installation. A GitHub-restricted host
uses the explicit [Mirror Update](docs/MIRROR.md#simple-copy-as-is-mirror-recommended)
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
