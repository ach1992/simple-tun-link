# Supported Environments

This document owns the v0.1 platform baseline. Runtime preflight remains authoritative for backend capability on a specific host.

## Initial platform policy

- Linux only.
- Installer distro floor: Ubuntu 22.04+ and Debian 11+ (Debian/Ubuntu ID
  values, not guesses from ID_LIKE). Unknown derivatives fail explicitly;
  repositories are never rewritten automatically. The requested Debian 11
  compatibility floor remains despite its security LTS expiry (2026-08-31).
  Security-maintained production hosts should use Debian 12+ or suitable
  extended security support.
- Automatic prerequisite provisioning: native GRE/IPIP installs/verifies
  iproute2 and iptables. Optional WireGuard selects wireguard-tools; optional
  IPsec selects charon-systemd and strongswan-swanctl explicitly to avoid
  surprising an existing strongSwan daemon. The installer only requests
  missing packages from the distro's own configured APT sources.
- Baseline kernel: **5.4 or newer**.
- Baseline iproute2: **5.1 or newer**.
- Initial release architectures: **linux/amd64** and **linux/arm64**.
- systemd is the initial persistence/service target, but STL must not require or replace systemd-networkd, NetworkManager, Netplan, or another primary host network manager.
- On systemd hosts, persistence file operations require a protected root-owned unit-directory chain and Linux filesystem support for atomic no-replace creation and renameat2 guarded exchange/retirement; unsupported filesystem primitives fail explicitly rather than using an unsafe overwrite fallback.

The kernel floor is intentionally newer than the first XFRM-interface kernel. strongSwan documents XFRM interfaces from Linux 4.19/iproute2 5.1 and an inbound-policy limitation before Linux 5.1; the 5.4 floor gives v0.1 a simpler supported baseline while remaining broadly available.

## Capability-based backends

A supported host may still lack one optional backend. Preflight must detect the actual capability and report that backend as unavailable without making unrelated backends unusable.

### GRE / IPIP

Require the selected kernel/iproute2 support for the requested mode. Native, FOU, and GUE support are detected independently. Missing FOU/GUE support does not disable Native GRE/IPIP.

### WireGuard

Requires the WireGuard kernel/module capability and the userspace `wg` tooling used by the implementation. Absence disables only the WireGuard backend.

### IPsec/XFRM

Requires Linux XFRM-interface support, iproute2 XFRM support, and a compatible strongSwan/IKEv2 installation. strongSwan supports XFRM interfaces since 5.8.0; the exact v0.1 tested strongSwan versions are validated by Issue #7 rather than guessed in advance.

## Release validation

Before v0.1 is tagged:

- validate on at least one currently maintained Ubuntu LTS and one current Debian stable release;
- exercise amd64 and arm64 release artifacts where test capacity permits;
- record the exact tested distro/kernel/iproute2/backend versions with release evidence;
- treat other Linux distributions as best-effort until explicitly added to the tested matrix.

Unsupported or missing capability must be reported explicitly. Tests must not silently convert an unsupported backend into a pass.
