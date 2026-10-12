# Supported Environments

This document owns the v0.1 platform baseline. Runtime preflight remains authoritative for backend capability on a specific host.

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
- Automatic prerequisite provisioning: native GRE/IPIP installs/verifies
  iproute2 and iptables. Optional WireGuard selects wireguard-tools; optional
  IPsec selects charon-systemd, strongswan-swanctl and
  libstrongswan-standard-plugins (OpenSSL/GCM) explicitly to avoid
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

The accepted native-exclusive IPsec backend is **conditionally registered**
only when current STL-origin protected configuration and service-unit files
and inode receipts, the already loaded exact systemd unit and effective
settings, exclusive strongSwan process/netns/cgroup/executable/configuration
and logging, protected VICI peer credentials, UDP 500/4500 and collision-free
XFRM identity are all independently attested. A foreign/unverifiable
same-namespace service, process, port or XFRM/VICI owner disables **only
IPsec**, never GRE/IPIP/WireGuard. No package installation or service start
occurs in ordinary runtime assembly. The user may stage a SENSITIVE IPsec
Quick Link only after runtime admission.

**Observed disposable kernel/daemon acceptance (2026-10-12)**:
- **Debian 13 (trixie) amd64**: strongSwan `6.0.1-6+deb13u7`,
  iproute2 `6.15.0-1`, Linux kernel `6.8.0-31-generic` (shared
  test host's kernel, not a Debian kernel claim).
- **Ubuntu 24.04 LTS amd64**: strongSwan
  `5.9.13-2ubuntu4.24.04.5`, iproute2 `6.1.0-1ubuntu6.4`,
  systemd `255.4-1ubuntu8.17` for native PID1-service acceptance;
  Linux kernel `6.8.0-31-generic` (same isolated host kernel).

On both distributions actual IKEv2/ESP/NAT-T, kernel `espinudp`,
bidirectional Link Address traffic, two same-underlay Links, safe sibling
removal, mismatch/foreign-owner rejection, canonical CLI state/diagnostics
and protected key retirement were exercised in fresh network-disconnected
disposable containers. A real **Ubuntu native STL systemd unit** and CLI
also passed both ESP and NAT-T with restart of the owned service, state
restore, bidirectional traffic, exact SA/XFRM cleanup and receipt-bound PSK
retirement. See [IPsec real E2E](operations/IPSEC-REAL-E2E.md).

The installer floor **Ubuntu 22.04+/Debian 11+** and kernel/iproute2 floors
listed above are **not** operational IPsec certification for those older
versions. Named-protocol legacy `iproute2` text parsing remains guarded
by canonical NSS file/`getent` agreement. On the tested strongSwan 5.9/6.x
the VICI socket can be group-mode `0770`; acceptance requires its
root-owned **0700 immediate ancestor**, root socket owner and matching
`SO_PEERCRED`, rejecting other/world access.

**Deployment boundary:** distro strongSwan maintainer scripts may
automatically enable/start vendor `strongswan.service`; the disposable
systemd test image disables *its own* vendor service during image build.
Never infer that a package install/upgrade on a real host is harmless or
disable/adopt a third-party service. This PR is not a production installer,
release, real NAT-router test, arm64 validation, physical reboot or
power-failure recovery certification. Broader matrix remains Issue #12.

## Release validation

Before v0.1 is tagged:

- validate on at least one currently maintained Ubuntu LTS and one current Debian stable release;
- exercise amd64 and arm64 release artifacts where test capacity permits;
- record the exact tested distro/kernel/iproute2/backend versions with release evidence;
- treat other Linux distributions as best-effort until explicitly added to the tested matrix.

Unsupported or missing capability must be reported explicitly. Tests must not silently convert an unsupported backend into a pass.

## Non-release XFRM inspector verification (2026-10-10)

One isolated read-only-inspector probe used Debian 13 (trixie) amd64
**host kernel 6.12.41+deb13-amd64** with an ephemeral Debian 12
(bookworm) container containing **iproute2 6.1.0** and Go 1.27.1.
The container used `--network none` and isolated NET_ADMIN; disposable
XFRM interface name/if_id and policy collision cases passed and were
removed within that container. On this iproute2 version, `ip -json xfrm
policy/state` emits legacy text for nonempty tables and empty stdout
for an empty table on successful exit. These are **not** two supported
installations or any strongSwan/IKEv2 compatibility acceptance: the test
image has no strongSwan; no encrypted traffic was negotiated. Required
Ubuntu/Debian, strongSwan version, architecture, systemd and release E2E
evidence remains outstanding under Issues #7 and #12.
