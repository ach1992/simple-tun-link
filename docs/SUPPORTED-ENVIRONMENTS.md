# Supported Environments

This document owns STL's **supported platform and capability contract**.
It is not a list of historical release-candidate test milestones.
Runtime preflight is authoritative for actual backend capability on a host.

## Initial platform policy

- Linux only.
- Installer distro floor: Ubuntu 22.04+ and Debian 11+ (Debian/Ubuntu ID
  values, not guesses from ID_LIKE). Unknown derivatives fail explicitly;
  repositories are never rewritten automatically. The requested Debian 11
  compatibility floor remains despite its security LTS expiry (2026-08-31).
  **Working maintained/signed APT repositories are a precondition** on
  Debian 11: default Bullseye security package indexes can return HTTP 404
  after LTS expiry. STL refuses blind repository rewrites or disabling APT
  signature/expiry protection. Prefer Debian 12+ or suitable ELTS support.
- Selected prerequisite planning: native GRE/IPIP installs/verifies
  iproute2, iptables and kmod (module introspection and explicit on-demand
  module loading). Optional WireGuard selects wireguard-tools; optional
  IPsec selects charon-systemd, strongswan-swanctl and
  libstrongswan-standard-plugins (OpenSSL/GCM) explicitly to avoid
  surprising an existing strongSwan daemon. Only missing packages are requested from the distro's configured,
  signed APT sources. IPsec package/service preparation is separately
  gated by observed host ownership and explicit operator approval;
  direct installer invocations must not bypass that gate.
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

The native-exclusive IPsec backend is **conditionally registered**
only when current STL-origin protected configuration and service-unit files
and inode receipts, the already loaded exact systemd unit and effective
settings, exclusive strongSwan process/netns/cgroup/executable/configuration
and logging, protected VICI peer credentials, UDP 500/4500 and collision-free
XFRM identity are all independently attested. A foreign/unverifiable
same-namespace service, process, port or XFRM/VICI owner disables **only
IPsec**, never GRE/IPIP/WireGuard. No package installation or service start
occurs in ordinary runtime assembly. A SENSITIVE IPsec Quick Link may be staged/activated only under
its separately verified prerequisite and runtime admission contracts.

## Validation and deployment boundaries

Supported OS/kernel/architecture **baselines are not a blanket promise**
that every optional tunnel backend works on every host. Verify the
actual kernel features, service manager, module availability, package
state, port/interface ownership and endpoint network conditions at
deployment time.

Runtime and released-artifact acceptance must distinguish:

- Source and unit tests from **actual native kernel traffic**.
- Container tests (which use their runner's host kernel) from
  independently booted distro guests and host reboot tests.
- Whole-guest committed-Link reboot/reapply evidence from **physical
  two-server WAN, NAT, provider-firewall and systemd 249** acceptance.
- A valid source/build/checksum from a downloaded published release
  installed and exercised on the target platform.

Reproducible tests, their explicit environments and their limitations
belong to [Cross-backend E2E](operations/CROSS-BACKEND-REAL-E2E.md),
[IPsec real E2E](operations/IPSEC-REAL-E2E.md),
[RELEASE-ARTIFACTS.md](RELEASE-ARTIFACTS.md) and their exact GitHub
CI/release records. The separate Owner field gate is tracked by
[Issue #93](https://github.com/ach1992/simple-tun-link/issues/93);
absence of field evidence must not be advertised as verified WAN
compatibility.

For a release, test at least one maintained Ubuntu LTS and current
Debian stable where practicable, execute native amd64/arm64
artifacts with appropriate available facilities, and record exact
distro/kernel/iproute2/backend and installed-build identity **with
that release's verification evidence**, not in this durable baseline.
Other Linux distributions/derivatives remain best-effort until a
specific supported capability policy and acceptance are added.
Unsupported capability is a visible unsupported/unknown result, never
a silent passed test or a reason to disable an unrelated backend.
