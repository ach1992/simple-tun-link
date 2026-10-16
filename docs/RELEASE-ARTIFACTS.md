# Release artifacts: build, verification and acceptance

This is a **maintainer procedure**, not a live release log. For ordinary
installation and updates use [INSTALL.md](INSTALL.md). Exact publication
state, tagged SHAs and successful CI/guest results belong to the
GitHub release, associated Issues/PRs and workflow runs.

A successful source test, a build, a published asset and a verified
installed release are **different evidence levels**. The build script
does not create Git tags, publish a release, install a host or authorize
production rollout.

## Reproducible local artifacts

From a clean source checkout with the pinned Go toolchain and
`sha256sum`, choose a **new** output directory:

~~~sh
scripts/build-artifacts.sh --snapshot /path/to/existing-parent/new-bundle
~~~

For a separately authorized exact version tag that **already exists
at current HEAD**:

~~~sh
scripts/build-artifacts.sh --tag vX.Y.Z /path/to/existing-parent/new-bundle
~~~

The tag mode refuses absent/mismatched tags. The script requires a
clean Git tree and a nonexisting destination; intermediate outputs
are staged privately and verified before atomic publication to the
destination. It generates static linux/amd64 and linux/arm64 binaries,
`LICENSE`, `SHA256SUMS` and `BUILD-MANIFEST.txt` with the intended
source, commit, version, build date and supported build platforms.
The binary's reported version/commit must match the manifest.

For a **compatible Linux AMD64** build bundle:

~~~sh
cd /path/to/new-bundle
sha256sum --check SHA256SUMS
version=$(sed -n 's/^version=//p' BUILD-MANIFEST.txt)
test -n "$version"
"./stl_${version}_linux_amd64" version --json
~~~

Cross-compilation does not prove native arm64 execution, kernel
support, systemd behavior or peer traffic.

## Installer and publication boundaries

The canonical [installer](../scripts/install.sh) verifies the chosen
bundle manifest, MIT license, checksums, expected executable
identity/version and installed ownership record before atomic
install/update. Its private recovery journal distinguishes completed
from uncertain operations. It refuses removal when saved Links,
a restore unit, credentials/State uncertainty or a foreign executable
makes cleanup unsafe. The installer is **not** a second Link
lifecycle or a foreign VPN service manager.

The bounded local regression commands are:

~~~sh
bash scripts/test-install-requirements.sh
bash scripts/test-install.sh
bash scripts/test-quick-install.sh
~~~

These use disposable files/prefixes, fake release fixtures and guarded
failure injection; they do not prove published download identity,
actual distro package hooks or kernel traffic.

Publication requires a **separately authorized** action binding an
accepted exact source commit to an immutable version tag and complete
assets (the two binaries, `SHA256SUMS`, `BUILD-MANIFEST.txt`,
`LICENSE` and the applicable fixed-tag bootstrap when supplied).
Verify official GitHub release immutability **at publication**; a tag
name, HTTPS or checksum uploaded by the same account alone is not
an independent cryptographic signature of source provenance.

After publication, independently download **the public assets**,
verify each published checksum and manifest against the exact tag,
install in an authorized isolated environment, and prove
`stl version --json` reports the correct installed artifact.
Exercise a fresh private-prefix install, supported update,
failure rollback/idempotence and safe uninstall. Keep immutable
historic releases unchanged; do not treat a prior RC's acceptance
as evidence for a new tag.

For the terminal menu's automated privileged Update, eligible
official releases must positively report `immutable:true`
and satisfy the separately specified root/TTY/fresh-consent and
version-transition requirements in [INSTALL.md](INSTALL.md).
Unknown/mutable immutability is **manual verification only**;
no alternate privileged mutable-tag updater should be invented.

## Committed-Link and State compatibility acceptance

A release with changed lifecycle/State behavior must independently
demonstrate that valid older saved State remains readable according
to its documented migration rules. Current State schema v3 adds
**endpoint-local managed MTU**. Older valid v1/v2 State loads
without surprise MTU writes; subsequent successful modification may
persist v3. A binary-only rollback to an old v1/v2 reader
**cannot** be assumed safe after v3 was written. Back up
protected State, separately stored keys and receiver handoffs as
described in [INSTALL.md](INSTALL.md) before testing an upgrade.

For an accepted release's representative native guests, prefer the
following evidence when required by its changes:

1. Install and record **exact published binary/manifest identity**
   and the guest distro/kernel/iproute2/backend versions.
2. Commit a Link and observe **real bidirectional inner-IP traffic**,
   actual owned resources and the selected local MTU policy.
3. On an authorized **disposable full guest** with systemd PID 1,
   reboot the guest OS while keeping the **same persisted disk**,
   restore service and original committed Link identity. Do not
   manually run fresh Pairing/Ensure as a substitute for automatic
   restore.
4. On the new boot ID, inspect same-Link traffic, persisted credential
   identity, scoped sibling isolation and eventual safe cleanup.
5. Distinguish container/netns-only traffic, independently booted
   guests, crashed-QEMU recovery and physical two-server WAN/NAT tests;
   none automatically proves the other.

Use the reproducible [cross-backend](operations/CROSS-BACKEND-REAL-E2E.md)
and [IPsec native](operations/IPSEC-REAL-E2E.md) procedures and
record verified outcomes against the **exact** candidate/tag in
GitHub checks/Issues. Tests must not reboot or alter the AI Server
Agent/control host or use an unapproved production/physical peer.
Physical WAN, provider firewall, real-pair and affected-host
acceptance is a distinct Owner test under
[Issue #93](https://github.com/ach1992/simple-tun-link/issues/93);
do not claim it based on disposable validation.
