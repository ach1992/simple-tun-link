# simple-tun-link (STL)

**Create and manage point-to-point IP tunnels between Linux servers.** STL provides a stable private IPv4 **Link Address** on each server, while the underlying tunnel can use GRE, IPIP, WireGuard, or conditionally available IPsec. You can create multiple independent Links, including different tunnels between the same pair of servers.

**Current release candidate:** [v0.1.0-rc.3](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.0-rc.3) (**Pre-release, not Stable**). The new operator-first menu, one-line installer and repeatable protected Setup Link sharing build on rc.2's committed-Link reboot restoration, managed MTU and backend fixes. Isolated native Linux validation does **not** prove physical Internet/WAN/NAT-router behavior; test on noncritical servers first.

The installed command is `stl`; `stlink` is an alias for the same program.

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

**One-line installer for v0.1.0-rc.3** (run on each server):

~~~bash
curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 https://raw.githubusercontent.com/ach1992/simple-tun-link/v0.1.0-rc.3/scripts/quick-install.sh | bash -s -- v0.1.0-rc.3
~~~

This is an explicitly tag-pinned HTTPS bootstrap; review its
[small bootstrap source](scripts/quick-install.sh) and
[canonical installer](scripts/install.sh) before running privileged
operations. The bootstrap checks the downloaded canonical installer
before elevating permissions; the canonical installer verifies the
release manifest and artifact SHA256 checksums. It installs native
GRE/IPIP and WireGuard prerequisites by default and **opens STL's
menu automatically** in a real terminal, even when the bootstrap
script was piped to Bash. It does not install/adopt IPsec services,
silently edit provider firewall/NAT settings or rewrite host routes.
Without a terminal, run sudo stl menu after installation.

To install only GRE/IPIP prerequisites, append native after the
version argument. **An existing STL installation must use the
explicit update action**, not install. The canonical installer will
refuse to overwrite an existing or foreign executable, rather than
silently adopt it. Read the [State/rollback precautions](docs/INSTALL.md)
before updating a server with configured Links.
The command uses curl; if its download fails, nothing should be
installed. Do not paste untrusted scripts or replace the version
with a mutable branch name. A HTTPS tag and checksum are not proof
of publisher trust.

**Older v0.1.0-rc.2** used a longer installer and has the old menu.
The new instructions and protected receiver-handoff retention
require that the installed executable actually reports rc.3.
Existing private rc.2 handoffs stay in their original chosen paths.

Verify when done:

~~~bash
stl version --json
stlink version --json
sudo stl menu
~~~

## 3. Connect Server A and Server B

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
same Setup Link for a saved GRE/IPIP tunnel. On the older
rc.2 release, where the menu is different, use the CLI instead:

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
settings. WireGuard/IPsec require their protected receiver handoff,
accessible later through SHOW-gated Share. Public details alone cannot
recreate an unknown receiver private key/PSK.

## 4. Create an encrypted WireGuard tunnel

Install WireGuard prerequisites on both hosts. In the menu select
**1 Create tunnel -> 2 WireGuard**. Enter the OTHER host's reachable IPv4;
press Enter for the suggested private tunnel IP pair and the default UDP
51820 ports, or choose different ports. Optional keepalive and local MTU
are under advanced settings.

After confirmation the initiator automatically saves the original
**SENSITIVE** receiver Setup Link in an STL-owned private directory
(0700 parent, 0600 per-Link file). No filename needs to be remembered.
Choose **3 My tunnels -> number -> 3 Share Setup Link**, and enter
**SHOW** on a private interactive terminal. The exact original
receiver link is displayed; no new WireGuard key or IPsec PSK is
generated by viewing it. Copy it to Server B, choose Import ->
Protected link, paste with hidden input, review and confirm.

Use **My tunnels -> number -> 6 Delete saved receiver Setup Link**,
and type **DELETE**, only when you will not need it again.
Deleting the handoff does NOT remove the tunnel or its local key,
and the receiver secret cannot then be recreated from ordinary
saved Link State. The shown link is sensitive to shoulder-surfing,
terminal recording and scrollback; never paste into public logs,
chats, tickets or shell history.

On **already published rc.2**, the older creator used a manually
chosen private output filename, not this automatic retention.
Keep and use that original protected file: it cannot be magically
recovered from State by the rc.3 menu. The protected Share/Delete
actions are not available in rc.2. WireGuard creation in
rc.2 is still the old separate menu option 9; consult the
[CLI/pairing guide](docs/CLI.md).

## 5. View, share, test, and remove saved tunnels

In the menu, **3 My tunnels** lists Link numbers instead of forcing
users to type long IDs. A selected Link offers Status, Test connection,
Share (repeatable plaintext GRE/IPIP regeneration or fresh SHOW-gated
protected WireGuard/IPsec retrieval), Connection details, Remove and
an independent **Delete saved receiver Setup Link** action.
Viewing/deleting a receiver handoff does not regenerate keys or modify
a running tunnel. Removing a Link does not automatically delete its
retained private handoff; cleanup after Link removal needs a
deliberate owner-private file action. Remove still requires a fresh
confirmation and rejects changed/unowned resources.

These stable CLI commands work in rc.2 and rc.3:

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

**To update an already installer-owned STL to v0.1.0-rc.3**, first
quiesce STL mutations and protect a consistent backup of State and
receiver/sender credential files. Then run the explicit, pinned
**one-line update** on that server:

~~~bash
curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 https://raw.githubusercontent.com/ach1992/simple-tun-link/v0.1.0-rc.3/scripts/quick-install.sh | bash -s -- v0.1.0-rc.3 update
~~~

This uses the canonical installer **update** transaction, checks
existing binary/record ownership before replacement, verifies
downloaded artifact identity and checksums, and returns to the menu
after success. It never silently modifies existing tunnel interfaces.
A fresh installation uses the **install** one-liner in section 2,
not update. The menu's Update task only provides guidance; it
does not perform hidden upgrades.

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
