# simple-tun-link (STL)

**Create and manage point-to-point IP tunnels between Linux servers.** STL provides a stable private IPv4 **Link Address** on each server, while the underlying tunnel can use GRE, IPIP, WireGuard, or conditionally available IPsec. You can create multiple independent Links, including different tunnels between the same pair of servers.

**Latest:** [v0.1.0-rc.2](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.0-rc.2) (**pre-release, not Stable**). This release includes automatic restoration of committed Links after reboot, endpoint-local managed MTU, and the IPsec/diagnostic fixes introduced after rc.1. Isolated native Linux and guest-reboot tests passed; **physical Internet/WAN/NAT-router deployments have not yet been independently validated**. Test on noncritical systems first.

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
- Check that the proposed private **/31 Link Address pair** does not overlap networks/routes on either server. The Link Address is for applications **inside** the tunnel; the underlay address is what peers use to reach each other.

## 2. Install on both servers

The command below downloads the installer from the **pinned release tag**, saves and syntax-checks it in a private temporary file, and only then runs it with `sudo`. Review [the installer source](scripts/install.sh) before trusting root execution.

```bash
bash -c 'set -euo pipefail; umask 077; t=$(mktemp); trap '\''rm -f -- "$t"'\'' EXIT; curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 -o "$t" https://raw.githubusercontent.com/ach1992/simple-tun-link/v0.1.0-rc.2/scripts/install.sh; bash -n "$t"; sudo bash "$t" install --version v0.1.0-rc.2'
```

This defaults to **native GRE/IPIP** prerequisites. To include WireGuard from the start, add `--backends native,wireguard` to the final `install` command inside the wrapper. For optional IPsec dependencies, select `--backends all` **only after reviewing existing strongSwan services**: package installation can start a system service; STL refuses unsafe service ownership. The installer does not activate an IPsec tunnel by itself.

Verify on each server:

```bash
stl version --json
stlink version --json
sudo stl menu
```

The command `sudo stl` also opens the interactive menu in a terminal. `stl help` displays all available CLI commands.

## 3. Connect Server A and Server B (GRE Native)

This is the simplest first Link; it **does not encrypt** traffic.

1. **On Server A:** run `sudo stl menu` and choose **Create Tunnel**. Keep **GRE Native** selected, enter Server B's **underlay IPv4**, review the detected local underlay address and proposed unused private **/31** pair, then confirm the displayed Link ID by typing it exactly.
2. STL creates Server A's local Link and displays a receiver-oriented **`stl://` Setup Link**. Copy that Link to Server B using a trusted channel. Successful creation on A does **not** yet mean B is connected.
3. **On Server B:** run `sudo stl menu`, choose **Import Setup Link**, paste the one-line `stl://` offer when prompted, inspect the redacted configuration preview, and enter the exact Link ID to confirm. Review local/peer addresses carefully before applying.
4. **On both servers:** inspect the resulting Link using its ID and test communication between the two **Link Addresses**:

```bash
sudo stl link list --json
sudo stl link status YOUR_LINK_ID --json
sudo stl link diagnose YOUR_LINK_ID
sudo stl link diagnose --all
```

For example, if the proposed Link Addresses are `10.80.20.0/31` (A) and `10.80.20.1/31` (B), applications on A should address B as `10.80.20.1`. These are **illustrative** addresses, not a fixed subnet STL always creates. Diagnostics attempt bounded real reachability checks; `status` alone verifies the local interface, **not peer connectivity**.

Once successfully committed, the Link is saved and the STL-owned `simple-tun-link-restore.service` restores it after reboot when the underlay and peer are available. A setup interrupted **before successful creation** can simply be restarted as a new attempt.

## 4. Create an encrypted WireGuard Link

Install both hosts with **WireGuard dependencies** (`--backends native,wireguard`). Then:

1. On A: `sudo stl menu` -> **Create WireGuard Tunnel**. Enter B's underlay IPv4, choose valid **UDP ports** and the private Link Address pair, and select an **absolute output file** inside a root-owned/private (`0700`) directory for the receiver's one-time Quick Link.
2. Confirm the Link ID. STL writes the **SENSITIVE** receiver handoff to a private (`0600`) file; it does **not** print that secret to normal status/JSON output.
3. Transfer that file securely to B and use **Import Setup Link** from B's menu (or the protected stdin preview/import commands documented below). Verify the expected peer and confirm the Link ID.
4. Run `sudo stl link diagnose YOUR_LINK_ID` on both hosts, and ensure the expected UDP path is open.

**Protect the handoff like a credential**: it can contain a receiver private key. Never post it in tickets/chats/logs, pass it as a command-line argument, or place it in a public directory. Peer setup and local interface status are not proof of an encrypted working connection until traffic has been tested. Advanced CLI: [pairing and recovery](docs/CLI.md#wireguard-sender-creation-recovery-and-credential-retirement).

## 5. Manage, test, and remove Links

All commands below act on the **local** server. `list`, `status`, `diagnose`, and `doctor` are observational; `ensure`, `remove`, and `restore` can **modify host network state**.

```bash
sudo stl link list --json                  # All saved Links
sudo stl link status YOUR_LINK_ID --json   # Owned local interface/status
sudo stl link diagnose YOUR_LINK_ID       # Bounded connectivity / MTU / quality checks
sudo stl link diagnose --all --json        # Check all saved Links independently
sudo stl doctor ipsec                      # Read-only IPsec prerequisite/ownership check
```

For a confirmed removal (use the exact stable ID twice):

```bash
sudo stl link remove YOUR_LINK_ID --confirm YOUR_LINK_ID
```

For recovery of **already saved** Links after an operational problem, inspect their status first; `sudo stl link restore --all` explicitly reapplies owned saved Links. Diagnostics never repair automatically. For automation, use versioned JSON and idempotent `stl link ensure --stdin --json < desired-link.json`, following the [exact request schema](docs/CLI.md#explicit-link-lifecycle-commands--issue-10). Never parse menu text as an API.

**IPsec:** start with `sudo stl doctor ipsec`. IPsec is available only when an STL-owned, native-exclusive strongSwan setup passes checks; an existing foreign/ambiguous strongSwan deployment is **not adopted or stopped**. Installing IPsec dependencies alone does not meet that condition. Consult [IPsec operations](docs/operations/IPSEC-REAL-E2E.md) before attempting this advanced backend.

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
