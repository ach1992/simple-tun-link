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

Requires Linux XFRM-interface support, iproute2 XFRM support, and a compatible strongSwan/IKEv2 installation. strongSwan supports XFRM interfaces since 5.8.0; the exact v0.1 tested strongSwan versions are validated by Issue #7 rather than guessed in advance.
The accepted operational target is **native-exclusive**: one STL-owned
strongSwan runtime per host, with standard UDP 500/4500. A foreign or
unprovably owned strongSwan service/process, conflicting ports, untrusted
configuration or ambiguous XFRM owner state makes only IPsec unavailable;
no automatic foreign-service shutdown or adoption. Probe outcomes reflect
actual capabilities and distinguish unknown from absent. The source-only
IPsec backend is **not yet registered**, regardless of read-only
prerequisite results. Installing strongSwan packages can auto-start
distro services: eligible-host lifecycle and package-script effects
require disposable testing before operational activation. Multiple full
IPsec implementations per distribution and mandatory netns are not
planned for v0.1; package and service adapters may differ by capability.
On glibc Debian/Ubuntu hosts where iproute2 emits legacy named XFRM
selector protocols, read-only vacancy checks additionally need
`/usr/bin/getent` to verify the host's actual NSS primary-name mapping
against `/etc/protocols`. Missing/mismatched NSS mapping is an explicit
fail-closed IPsec preflight incompatibility, not an empty resource table.

The read-only native-exclusive diagnostic now includes UDP 500/4500
observations from bounded `/proc/net/udp` and `/proc/net/udp6` for the
calling network namespace. Linux procfs layout is parsed strictly; a
missing IPv6 table, inaccessible procfs or incomplete snapshot yields
`ike_udp_inventory_unverified`, **not** a positive vacancy. This does not
change the supported kernel/distro matrix, count as a qualified port-ownership
test or enable IPsec. The fixed proposed strongSwan configuration is a
non-operational `charon-systemd` template; validated distro/systemd
adapters, service ownership and effective logging verification still require
real disposable-environment acceptance.
The additive `native_config` read-only check requires root-private
canonical storage and exact reviewed source bytes. It can report unknown
when invoked without access to that protected path. Successful source
file attestation is not installed-package compatibility, durable
STL-created inode proof, active logging attestation or service eligibility.
The optional source-only native publication primitive needs a trusted,
owner-private local filesystem supporting Linux
`renameat2(RENAME_NOREPLACE)`, `user.*` inode xattrs and file/directory
`fsync`; unsupported features fail closed. In unprivileged private-directory
unit tests these primitives successfully stage and verify a no-clobber,
receipt-bound fixed config, including failure/replacement scenarios. This
is **not** a root-host provisioning, distro package, systemd startup,
post-reboot or IKEv2/ESP/NAT-T compatibility test. The separate additive
`native_config_origin` read-only diagnostic reports a receipt-bound snapshot
or a stable missing/conflict/unverified reason, and always leaves
`activation_allowed:false`.
The additional source-only `charon-systemd` systemd-unit profile assumes
`/usr/sbin/charon-systemd` and `Type=notify` on a qualified Debian/Ubuntu
package. Its read-only `native_service_unit` doctor check inspects only the
protected canonical unit file and never claims active/effective unit ownership.
The companion source-only **unit publication** primitive has no
production call site and has only been exercised under private unprivileged
fixtures. Like the separate native config publisher it requires
renameat2(RENAME_NOREPLACE), inode user.* xattrs and successful file and
directory fsync. Unlike the config it stages a private 0600 unit in the
root-owned /etc/systemd/system directory and records its origin under
/var/lib/simple-tun-link/ipsec. Any preexisting unit is a conflict, even
when byte-identical. The unit-stage file and its parent directory
must both fsync successfully **before** a pre-receipt interruption can
be described as leaving a durably discoverable fixed-name stage.
Subsequently, the receipt file/state directory and final unit directory
must be synced at their respective publication boundaries. A failed
fsync leaves persistence unknown and fails closed; interrupted or
observably retained stages require manual reconciliation. These fixtures
do not simulate a real power failure or certify all filesystem semantics. The additional read-only native_service_unit_origin
observation does not establish an effective systemd unit, package
compatibility, service ownership or operational acceptance.
The profile has not been installed or exercised via systemd, and package
installation may trigger distro service-start hooks; this requires separately
authorized disposable-environment verification before admission. Exact
Ubuntu/Debian packaging, service aliases, unit overrides and process/runtime
settings remain unproven for operational use.
The documented Ubuntu/Debian daemonless/container smoke therefore must
not be promoted to an operational or persistence acceptance result.


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
