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
disable/adopt a third-party service. The earlier systemd fixture alone was
not ARM64 runtime validation. The separate native multi-architecture matrix
below now provides that proof, but these early fixtures **alone** do not
certify a production installer/release artifact, physical NAT-router
traversal, full OS reboot, independently booted distro kernels or
power-failure recovery. Later separate guest-only evidence is distinguished
below; none is a published tagged release or physical WAN deployment.

## Native release-level runtime matrix (Issue #12, 2026-10-12)

The [official privileged six-Link E2E run](https://github.com/ach1992/simple-tun-link/actions/runs/38280434443)
completed **SUCCESS** at Git commit
`a6aa71316c3b27cf5c49b7f752c41962677e871c`.
Each GitHub-hosted disposable VM has a **real independently running Linux
kernel** and a natively built Go test binary (not cross-compiled or emulated):

| Runner architecture | Verified kernel | Native Go architecture | Container userspaces |
| --- | --- | --- | --- |
| x86_64 | `6.8.0-1064-azure` | `amd64` | Ubuntu 24.04.5 LTS and Debian 13 |
| aarch64 | `6.17.0-1022-azure` | `arm64` | Ubuntu 24.04.5 LTS and Debian 13 |

All **four** architecture/userspace combinations passed real bidirectional
traffic for simultaneous GRE Native/FOU/GUE, authenticated WireGuard,
separately keyed IKEv2/XFRM ESP and NAT-T, scoped recovery and removal,
and sequential IPIP Native/FOU/GUE coexistence. Both real native kernels
exercised protected credential/ownership handling, resource collisions
and foreign-resource rejection. Each userspace completed
`GRE_E2E_CLEANUP_EXIT=0`; both jobs completed
`CROSS_BACKEND_DISPOSABLE_CLEANUP_EXIT=0`.

This is accepted **native linux/amd64 and linux/arm64 runtime**
evidence for the network-namespace release-level matrix. Ubuntu/Debian
containers **share their respective runner's kernel**: **this particular
runner workflow** did not boot independent distro kernels or exercise
whole-guest reboot, external NAT-router traversal or power-loss recovery.
Runtime proof is distinct from installing final downloadable release
artifacts, which Issue #11 owns.

## Supplementary source-bound native-guest acceptance (2026-10-13)

The [Issue #11 release-lifecycle record](https://github.com/ach1992/simple-tun-link/issues/11#issuecomment-6133926392)
proves actual root `/usr/local` installer **snapshot** upgrade and safe uninstall
on two **independently booted, disposable KVM Linux kernels** built from
clean `main@aab0cac0cd8991d792e75b421c4acfacd42258e7`:

| Guest | Actual independent guest kernel | iproute2 | Result |
| --- | --- | --- | --- |
| Debian 13 (amd64) | `6.12.111+deb13-cloud-amd64` | `6.15.0` | **PASS** |
| Ubuntu 24.04 LTS (amd64) | `6.8.0-142-generic` | `6.1.0` | **PASS** |

Each system installed a previous source-bound `stl` snapshot, provisioned
all explicitly selected GRE/WireGuard/IPsec distro packages through signed
APT, atomically updated to the current snapshot, rejected a tampered
artifact without changing the executable, and successfully completed
idempotent update and uninstall while preserving unrelated files/packages.
A separate Debian 13 guest proved active bidirectional GRE traffic prevents
uninstall without stopping the Link or overwriting the executable; after
explicit scoped Link/restore-unit removal, uninstall succeeds
([Issue #11](https://github.com/ach1992/simple-tun-link/issues/11#issuecomment-6133986111)).

The [Issue #12 crash/recovery record](https://github.com/ach1992/simple-tun-link/issues/12#issuecomment-6134259976)
additionally proves that real **GRE Native and WireGuard** Links and protected
receiver credentials survive a deliberately abrupt QEMU process kill and
booting the **same persisted VM disk**; automatic systemd restoration,
bilateral authenticated traffic, idempotent reapply and scoped cleanup
were observed. Earlier separate full-guest clean reboot acceptance also
passed for GRE and WireGuard.

The subsequent, **unreleased PR #81 source candidate** independently passed
true Debian 13 AMD64 KVM full-kernel reboot for native-exclusive IPsec ESP
and NAT-T, including automatic STL Link restoration, reestablished IKE/CHILD
SAs, and verified two-way encrypted traffic in an isolated Ubuntu PID1
systemd guest with ext4-persisted owner receipts. ESP additionally passed
an abruptly SIGKILL-terminated QEMU guest and automatic same-disk crash
recovery. These results do **not** prove NAT-T abrupt-crash recovery,
physical WAN/NAT-router traversal, or an installed published prerelease
binary. Native ARM64 six-Link traffic remains covered by official E2E;
**installed ARM64 release artifact** acceptance also remains outstanding.
Issue #12 tracks remaining physical network/crash gates and Issue #11 the
public release/installed-artifact acceptance. The currently published
prerelease predates this candidate and must not claim these fixes.

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
for an empty table on successful exit. **This historical inspector-only
probe**, by itself, was not a supported installation or strongSwan/IKEv2
traffic acceptance: its image contained no strongSwan. The later
native AMD64/ARM64 Ubuntu/Debian operational release matrix is documented
above; **this 2026-10-10 inspector-only probe** did not boot independent
distribution kernels or demonstrate full-guest reboot/recovery. Later
source-bound KVM guest evidence is separately recorded above under Issue #12.
