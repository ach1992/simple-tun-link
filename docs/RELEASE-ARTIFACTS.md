# Release artifact build, verification, and acceptance

**For users:** installation, first tunnel and common management commands
are in the [README](../README.md). This page describes how a maintainer
builds and verifies release artifacts; the build script itself **does not
publish** a tag, release, or deployment.

Issue #11 is historical installer acceptance, and
[Issue #12](https://github.com/ach1992/simple-tun-link/issues/12)
records the source/tag/download and real systemd-guest reboot evidence
for the prior
[v0.1.0-rc.2 pre-release](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.0-rc.2).
[Issue #91](https://github.com/ach1992/simple-tun-link/issues/91)
and [PR #92](https://github.com/ach1992/simple-tun-link/pull/92)
record the published v0.1.0-rc.3 operator interface, explicit one-line
install/update and protected receiver handoff retention. A green PR
check is source-bound evidence only; the public release is qualified
separately by checking its recorded tag commit, exact packaged binaries,
SHA256SUMS and actual installed executable. Historical rc.2 guest
evidence must not be presented as a new rc.3 tagged-guest boot test.

[Issue #93](https://github.com/ach1992/simple-tun-link/issues/93)
and [PR #94](https://github.com/ach1992/simple-tun-link/pull/94)
record the reviewed Ubuntu 22.04/systemd 249 absent-unit fix and
one-screen operator presentation in the **published**
[v0.1.0-rc.4 public pre-release](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.0-rc.4).
Its source/CI, recorded tag commit, five public artifacts, downloaded checksums,
fresh public install, and actual rc.3-to-rc.4 disposable update have
separate accepted evidence in Issue #93. Those isolated checks do **not**
close the Owner's real affected-host systemd, reboot or WAN/NAT acceptance.
The follow-up UI and diagnostic changes were independently approved
and merged in [PR #96](https://github.com/ach1992/simple-tun-link/pull/96)
under closed [Issue #95](https://github.com/ach1992/simple-tun-link/issues/95).
The **v0.1.0-rc.5 public pre-release** packages these changes; its
separate tagged-asset/download/install acceptance is recorded under
[Issue #97](https://github.com/ach1992/simple-tun-link/issues/97).
The rc.4 asset hashes were verified at acceptance; that is not
GitHub-enforced release immutability. Real host reboot/WAN/NAT
acceptance remains independent in Issue #93.

## Local build

From a **clean Git source tree**, with the pinned Go toolchain and GNU
sha256sum:

~~~sh
scripts/build-artifacts.sh --snapshot /path/to/existing-parent/new-bundle
~~~

When release/tagging is separately authorized and the exact tag already
exists at current HEAD:

~~~sh
scripts/build-artifacts.sh --tag vX.Y.Z /path/to/existing-parent/new-bundle
~~~

The tag command **does not create tags or publish anything**. It refuses a
non-existent/non-current/invalid tag. Both modes require a clean checkout and
a new output path; no existing path is overwritten. Intermediate binaries are
built in a private temporary directory and atomically moved into the output
directory after verification. A failed build cleans its temporary output.

The bundle contains static linux/amd64 and linux/arm64 executables, the MIT
LICENSE, a source/commit/version/build-date/platform manifest and SHA256SUMS.
The executable carries the actual Git commit SHA, supplied version string and
Git commit timestamp. Build date derives from Git rather than wall-clock time
for source reproducibility. To verify:

~~~sh
cd /path/to/new-bundle
sha256sum --check SHA256SUMS
./stl_dev-<commit-prefix>_linux_amd64 version --json
~~~

The example executable command requires compatible amd64 Linux.
Cross-compilation is not proof of arm64 execution, kernel backend support, or
network behavior. Issue #12 owns the Ubuntu/Debian, kernel, iproute2,
architecture, systemd and cross-backend runtime evidence.

## Installer acceptance slice

`scripts/install.sh` consumes the existing artifact filenames and manifest
without creating a second package format. It verifies manifest/license/
selected-binary SHA-256, intended version/commit, and the executable's
reported metadata before an owned installation or atomic update. It installs
one executable, exposes `stlink` as a relative symlink, and keeps a private
installer ownership record; a failed update attempts guarded rollback.
Uninstall refuses configured Links, ambiguous reads, foreign/modified
executables and leftover Engine-owned restore units, rather than removing
host resources itself. See [install/update/uninstall runbook](INSTALL.md).

`bash scripts/test-install.sh` runs disposable nonprivileged/offline regression
cases, including injected after-rename update/uninstall failures. No privileged
network operations or real release download happen in these tests.

## Publication versus build acceptance

This **build script** only produces a verified bundle; it never creates
a public tag/release. To publish a candidate such as rc.3, a separately
authorized publisher must bind the tag to the exact accepted source,
attach the two binaries plus `SHA256SUMS`, `LICENSE` and
`BUILD-MANIFEST.txt`, then **download the public files independently**
and verify checksums, installed version/commit and installer behavior.
For a **future release eligible for automatic in-menu root update**,
GitHub `Enable release immutability` is an Owner-approved prerequisite:
enable it before publication, create a draft, attach all expected assets,
publish, and verify the official release API reports `immutable:true`.
An old `immutable:false` release cannot be made eligible retroactively.

**Uninstall** remains a read-only preparatory menu; it cannot silently
remove Links or protected credentials. The **post-rc.5 Update candidate**
([Issue #99](https://github.com/ach1992/simple-tun-link/issues/99))
can delegate to the existing canonical installer after explicit root/TTY/
forward-only/UPDATE gates, **only** for an official GitHub release whose
API reports `immutable:true`. False, missing or malformed immutability
means manual verification guidance, never root execution of a downloaded
mutable-tag script. There is no second updater or rollback engine.
GitHub release immutability must be enabled before publishing **future**
releases; enabling it does not retroactively change public rc.5
(`immutable:false`). This candidate is unreleased, and all normal
independent review, Owner merge, publication and field acceptance gates
remain in effect. The offline regression script cannot replace
the release-specific guest reboot and real kernel traffic evidence in
[Issue #12](https://github.com/ach1992/simple-tun-link/issues/12).
Historically, Issue #11 established rc.1 installation acceptance,
while Issue #12 records the stronger rc.2 release and whole-guest
systemd reboot proof. For rc.3, exact-head disposable Ubuntu AMD64/
ARM64 six-Link traffic is recorded in PR #92's workflow checks;
publication must additionally verify rc.3's tag, binary manifest,
download integrity and installed identity. The physical WAN/NAT
acceptance remains Owner-run after publication and is not certified
by this isolated test lab.

## State v3 and full-guest release acceptance (Issue #12)

Managed MTU is persisted in **State schema v3**; it is distinct from CLI
request schema v2 and existing pairing schemas. Valid old v1/v2 State must
restore without a surprise MTU write, and a subsequent successful mutation
may persist v3. An old pre-v3 executable cannot consume a v3 snapshot: test
upgrade/rollback policy and publish the operator guidance in [INSTALL.md](INSTALL.md)
with the release. A binary-only installer recovery is not a State migration.

Before separately authorized Stable publication, collect exact **candidate
source/tag, build manifest, checksum and installed executable identities** for
supported architectures. In an authorized **disposable full-system guest with
real PID1 systemd and its own kernel**, prove the following on the **same
persisted guest disk**, not by creating a replacement Link after reboot:

1. A canonical successfully committed Link has an immutable recorded Link ID,
   State/credential identity and **actual bidirectional inner Link traffic**;
   managed-MTU policy is applied and observed at the real Linux interface.
2. Record the guest kernel boot ID, verify the STL-owned scheduled restore unit,
   then reboot the **guest OS**, never the AI/test-server host or its control
   plane. Provide the private peer underlay before the normal restore unit runs.
3. On a distinct kernel boot ID, **before manual `ensure`, fresh pairing or
   re-creation**, prove automatic restore of the same Link and observed MTU,
   returned bilateral packets, idempotent subsequent reapply and scoped cleanup.
4. Verify safe v1/v2-to-v3 state compatibility, secret-safe evidence, real
   installed executable/manifest SHA and failure/unsupported-capability cases.

Namespace-only kernel tests, a disposable container's systemd restart,
source-only offline installer, older source's KVM results, and a green CI
summary are **not** substitutes for this current-source whole-guest proof.
Record exact distro/kernel/backend/tool versions, results and honest limits in
[Issue #12](https://github.com/ach1992/simple-tun-link/issues/12). External
physical WAN/NAT validation remains Owner-run **after** publication; do not
claim it occurred or circumvent tool/platform restrictions to attempt it.
