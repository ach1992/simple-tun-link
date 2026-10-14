# simple-tun-link (STL)

**Create and manage point-to-point IP tunnels between Linux servers.** STL provides a stable private IPv4 **Link Address** on each server, while the underlying tunnel can use GRE, IPIP, WireGuard, or conditionally available IPsec. You can create multiple independent Links, including different tunnels between the same pair of servers.

**Latest:** [v0.1.0-rc.2](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.0-rc.2) (**pre-release, not Stable**). This release includes automatic restoration of committed Links after reboot, endpoint-local managed MTU, and the IPsec/diagnostic fixes introduced after rc.1. Isolated native Linux and guest-reboot tests passed; **physical Internet/WAN/NAT-router deployments have not yet been independently validated**. Test on noncritical systems first.

The installed command is `stl`; `stlink` is an alias for the same program.

**Version note:** The simplified Create/Manage interface below is currently
in development under [Issue #91](https://github.com/ach1992/simple-tun-link/issues/91)
and **not yet included in the published rc.2 executable**. Use the rc.2
commands below until a separately reviewed new version is published.

## What you can create

| Tunnel backend | Carrier | Encrypted/authenticated? | Notes |
| --- | --- | --- | --- |
| GRE | Native, FOU/UDP, GUE/UDP | No | **Default**; easiest way to start |
| IPIP | Native, FOU/UDP, GUE/UDP | No | Advanced plaintext alternative |
| WireGuard | UDP | Yes | Guided encrypted Quick Link |
| IPsec/XFRM | IKEv2 ESP / NAT-T | Yes | Advanced; only if STL-exclusive strongSwan runtime passes admission |

GRE keys distinguish tunnels but **do not encrypt traffic**. FOU/GUE are UDP encapsulations, not encryption. Use WireGuard or properly configured IPsec when confidentiality is required.

## 1. Requirements

- Two or more **Linux** servers you administer, with mutually reachable public/private **underlay IP addresses**. You must know the peer server's reachable IP.
- **Ubuntu 22.04+ or Debian 11+**, on **amd64 or arm64**; kernel **5.4+**, iproute2 **5.1+**, systemd for reboot persistence. Actual backend/kernel support is checked per host. Prefer maintained distributions such as Ubuntu 24.04 LTS or Debian 13; Debian 11 requires working, signed, maintained package repositories.
- `sudo`/root access on **both** hosts and `curl` for the download command. The installer uses the host's existing APT repositories to install missing dependencies; it does not rewrite repository settings.
- Permit the chosen protocol between the **underlay** addresses in upstream firewalls/security groups. Native GRE uses IP protocol **47** (not TCP/UDP port 47); WireGuard uses the chosen UDP port; IPsec can require UDP **500/4500** and ESP depending on mode. STL does **not** configure cloud-provider firewalls or NAT/port forwarding for you.
- Check that the proposed private **/31 auto pair** (or manual **/30 pair**) does not overlap networks/routes on either server. The Link Address is for applications **inside** the tunnel; the underlay address is what peers use to reach each other.

## 2. Install on both servers

### Published rc.2 (available now, older menu)

This existing one-liner installs the **published** pre-release, not the
new Issue #91 menu. Review the [installer source](scripts/install.sh)
before giving it root access. It verifies release manifests and binary checksums.

~~~bash
bash -c 'set -euo pipefail; umask 077; t=$(mktemp); trap '\''rm -f -- "$t"'\'' EXIT; curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 -o "$t" https://raw.githubusercontent.com/ach1992/simple-tun-link/v0.1.0-rc.2/scripts/install.sh; bash -n "$t"; sudo bash "$t" install --version v0.1.0-rc.2'
~~~

This installs native GRE/IPIP prerequisites. To include WireGuard, append
--backends native,wireguard to the installer invocation.

### Simpler one-line install (next published release only)

Once Issue #91 has passed review and a *new real tag* is published, replace
both occurrences of vX.Y.Z with that same actual released tag:

~~~bash
curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 https://raw.githubusercontent.com/ach1992/simple-tun-link/vX.Y.Z/scripts/quick-install.sh | bash -s -- vX.Y.Z
~~~

The quick bootstrap runs without initial root privileges; it downloads and
syntax-checks the same pinned official installer into a private temporary
file, runs its verified install with sudo, and **opens the interactive menu
automatically** on a real terminal, even when the quick script came from
stdin. In noninteractive environments, use sudo stl menu afterward.
Its default dependencies support native GRE/IPIP and WireGuard. IPsec
dependencies require separate explicit operator admission; third-party
strongSwan services are never silently adopted or stopped. Do not try this
new command against rc.2 (the quick-install file is not in that old tag).
Pinned HTTPS/asset checksums do not replace trust in the release publisher.

Verify when done:

~~~bash
stl version --json
stlink version --json
sudo stl menu
~~~

## 3. Connect Server A and Server B (new menu)

The simplest default, GRE Native, is **not encrypted**. You need the
OTHER server's reachable connection IPv4. STL automatically chooses
THIS server's underlay/source IP from the Linux kernel route to that peer.

1. On **Server A**, choose **1 Create tunnel -> 1 GRE / Native** (or press
   Enter on the tunnel type). Enter Server B's reachable connection IPv4.
2. STL shows THIS server's automatically selected connection IP and
   suggests two unused private tunnel IPs. **Press Enter to accept both
   suggested tunnel IPs automatically.** Or type the two IPs directly,
   for example Server A = 10.235.1.1 and Server B = 10.235.1.2 (/30).
3. Keep advanced settings at their defaults. Review both public/connection
   IPs and tunnel IPs, then type **YES** after the fresh preview to create
   the local tunnel. Local success is not proof of remote connectivity.
4. Copy the displayed plaintext stl:// Setup Link. On **Server B** choose
   **2 Import setup link -> 1 GRE/IPIP**, paste the full line (visible
   while typing), review the reciprocal settings and type **YES**.
5. After both ends are configured, use **4 Test connectivity**, select
   the tunnel by number and run the peer checks. Before both ends exist,
   automatic MTU is only a conservative local estimate, not an end-to-end
   PMTU measurement.

**Forgot to copy the link?** You do not need to recreate the tunnel:
on Server A, use **3 My tunnels -> number -> 3 Share**. It returns the
same Setup Link for a saved GRE/IPIP tunnel. On the currently installed
rc.2 release, where the menu is older, use the CLI instead:

~~~bash
sudo stl link list
sudo stl link export YOUR_LINK_ID
~~~

Successful committed Links are restored across reboot by the STL-owned
systemd service. An attempt aborted before a Link is committed can be
restarted independently.

### Connect both servers without a Setup Link

Choose **1 Create tunnel -> 4 Manual connection** and select either
GRE Native (1) or IPIP Native (2). Provide the OTHER server's reachable
IPv4, then enter the same two private tunnel IPs but **reverse the local
and peer IP assignments** on the other server.

For GRE Native, pressing Enter at the receive-key prompt creates unkeyed
GRE on that server. To match an already keyed GRE Native peer, type the
**identical GRE receive key** from its saved Connection details; it is
a numeric receive identity, **not encryption or authentication**.
Open IP protocol **47** (GRE) or **4** (IPIP) through applicable firewalls
and provider security groups; these are not TCP/UDP ports.

A copyable two-server reference remains available at any later time:
**3 My tunnels -> number -> 4 Connection details**. It displays the
configured connection/underlay IPs, both tunnel IPs and prefixes, backend,
nonsecret GRE key, any known UDP port, and exactly which settings are reversed
on the second host. Saved values are **not a live observation of the remote
host**. FOU/GUE should use Share Setup Link to preserve the paired UDP
settings. WireGuard/IPsec require their protected private receiver handoff;
public details alone cannot recreate an unknown receiver key/PSK.

## 4. Create an encrypted WireGuard tunnel

Install WireGuard prerequisites on both hosts. In the new menu select
**1 Create tunnel -> 2 WireGuard**. Enter the OTHER host's reachable IPv4;
press Enter for the suggested private tunnel IP pair and the default UDP
51820 ports, or choose different ports. Optional keepalive and local MTU
are under advanced settings.

The creator writes the sensitive receiver Setup Link into an owner-private
file. Transfer that file securely to the OTHER server, choose **2 Import
setup link -> 2 Protected link**, paste while terminal echo is suppressed,
review the effective settings and confirm. Test real traffic and the
WireGuard handshake once both ends are configured.

**Keep the private handoff file if you may need to reuse it.** The first
server saves public peer parameters, not the receiver's private credential.
A lost WireGuard/IPsec receiver secret cannot be reconstructed from saved
public Link state. Never place that handoff in shell history or public logs.
On the published rc.2 binary, WireGuard creation still has its old
**separate menu option 9** and older explicit confirmation prompts; use
the full [CLI/pairing guide](docs/CLI.md) for advanced usage.

## 5. View, share, test, and remove saved tunnels

In the next menu, **3 My tunnels** lists Link numbers instead of forcing
users to type long IDs. A selected Link offers Status, Test connection,
Share (recover nonsecret GRE/IPIP Setup Link), Connection details and
Remove. Removal still needs a fresh interactive confirmation and refuses
changed/unowned resources.

The stable CLI commands work in rc.2 as well as future releases:

~~~bash
sudo stl link list --json                  # Saved Links
sudo stl link export YOUR_LINK_ID         # Re-copy GRE/IPIP setup URL
sudo stl link status YOUR_LINK_ID --json   # Owned local interface/status
sudo stl link diagnose YOUR_LINK_ID       # Real peer/MTU checks
sudo stl link diagnose --all --json        # Check every saved Link
sudo stl doctor ipsec                      # Read-only IPsec prerequisites
~~~

For deliberate scripted removal of one Link, specify the exact ID twice:

~~~bash
sudo stl link remove YOUR_LINK_ID --confirm YOUR_LINK_ID
~~~

For an already committed Link that needs a permitted restore, first
inspect state and status, then use sudo stl link restore --all.
A blocked/uncertain operation must be investigated; the interface does
not automatically retry possible partial network mutations.

## 6. Update safely

To update an existing rc.1 installation to rc.2, fetch and review the installer **from rc.2**, then use the same secure one-command wrapper above with its last invocation changed from `install --version v0.1.0-rc.2` to **`update --version v0.1.0-rc.2`**. The terminal menu's Update task only shows instructions; it does not silently install anything.

**Important State v3 compatibility warning:** after an rc.2 executable successfully writes **State schema v3** (used for managed local MTU), an older pre-v3 executable **cannot read that State**. **Binary-only rollback is not State rollback.** Before updating hosts with existing Links, quiesce STL mutations and keep a **consistent protected backup** of State **and separate credentials** with a tested recovery path. Do **not** manually edit `schema_version`, drop MTU fields, or delete interfaces/systemd files to force a downgrade. Prefer a compatible roll-forward if recovery is needed; follow the [full update/recovery runbook](docs/INSTALL.md#persisted-state-v3-upgrade-and-safe-rollback-boundary).

## 7. Uninstall

Remove Links deliberately, one at a time; **uninstall does not tear down active tunnels**:

```bash
sudo stl link list --json
sudo stl link remove YOUR_LINK_ID --confirm YOUR_LINK_ID  # Repeat for each saved Link
```

Then use the **same trusted, inspected installer script** downloaded from the published tag:

```bash
sudo bash ./install.sh uninstall
```

The last command assumes you explicitly saved the official installer locally as `./install.sh`; the installation one-liner normally deletes its temporary copy. The uninstaller checks that no Links or Engine-owned restore unit remain and removes only its verified binary, `stlink` alias and ownership record. It **does not delete credentials/State, uninstall distro packages, or remove unrelated network resources**. See [safe uninstall steps](docs/INSTALL.md#uninstall-never-tear-down-live-links-implicitly).

## Troubleshooting and safety

- **No traffic:** verify each side's underlay route/firewall/security group, correct reciprocal Link Addresses, peer import, and `sudo stl link diagnose YOUR_LINK_ID`. A configured interface is not an end-to-end success signal.
- **Backend unavailable:** inspect capability/prerequisite errors; `sudo stl doctor ipsec` is read-only. One unavailable optional backend must not disable unrelated backends.
- **MTU problems:** use Link diagnostics and, when needed, the **endpoint-local** managed `auto` or `manual` MTU policy. Auto is a conservative local bound, **not** a measured end-to-end PMTU guarantee. Do not copy A's local MTU setting to B blindly.
- **Partial failure:** check `list`, `status`, and the reported `reason_code`/`next_step`. Never blindly retry or delete unverified/foreign kernel resources after an uncertain committed operation; consult [operator recovery](docs/OPERATOR-RECOVERY.md).
- **Secrets and encryption:** GRE/IPIP are plaintext. Handle WireGuard/IPsec setup offers and keys privately. STL does not guarantee NAT traversal, traffic camouflage, or unrestricted network accessibility.

## More information

The **README is the quick-start and everyday user guide**. Detailed reference and maintainer material stays separate:

- [Full command / JSON / pairing reference](docs/CLI.md)
- [Installer, updates, State v3 rollback, and safe uninstall](docs/INSTALL.md)
- [Supported operating systems and capabilities](docs/SUPPORTED-ENVIRONMENTS.md)
- [Security boundaries](docs/SECURITY.md)
- [Diagnosing Links](docs/DIAGNOSTICS.md)
- [Project specification / architecture](docs/PROJECT-SPEC.md) / [architecture](docs/ARCHITECTURE.md)
- [Release files and validation](docs/RELEASE-ARTIFACTS.md)

Source: [GitHub](https://github.com/ach1992/simple-tun-link) | License: [MIT](LICENSE).
