# Release artifact build — Issue #11

This is **build-only preparation**, not a publisher, release, or deployment.
Installation and release-level system verification remain tracked under
Issues #11 and #12.

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

## Remaining Issue #11 and release acceptance

No tag or public GitHub release was created by this implementation. A later
**separately authorized** publication must attach the exact source-tagged
binaries, SHA256SUMS, LICENSE and BUILD-MANIFEST to the matching GitHub
release, establish the tested supported-environment matrix (Issue #12), and
record release notes/evidence. The menu's Update/Uninstall operator integration
(Issue #10) remains pending; the installer is available as an explicit script.
No production installation, deployment or privileged systemd/network E2E has
been performed as part of this slice.
