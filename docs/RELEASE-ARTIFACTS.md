# Release artifact build — Issue #11

This is **build-only preparation**, not an installer, publisher, release or
deployment. STL v0.1 release acceptance and supported-environment tests remain
owned by Issue #11 and Issue #12.

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

The tag command **does not create tags or publish anything**. It refuses
a non-existent/non-current/invalid tag. Both modes require a clean checkout
and a new output path; no existing path is overwritten. Intermediate binaries
are built in a private temporary directory and atomically moved into the
resulting output directory after verification. A failed build cleans its own
temporary output.

The bundle contains static linux/amd64 and linux/arm64 executables, the MIT
LICENSE, a source/commit/version/build-date/platform manifest and SHA256SUMS.
The executable carries the actual Git commit SHA, supplied version string and
Git commit timestamp. The build date derives from Git rather than wall-clock
time to preserve reproducibility of the same source. To verify:

~~~sh
cd /path/to/new-bundle
sha256sum --check SHA256SUMS
./stl_dev-<commit-prefix>_linux_amd64 version --json
~~~

The example executable invocation works only on compatible amd64 Linux;
cross-compilation itself does not prove arm64 runtime, kernel support, or
network data-plane behavior. Before final v0.1, Issue #12 owns the exact
Ubuntu LTS, Debian stable, kernel, iproute2 and architecture runtime evidence.

## Remaining Issue #11 acceptance

This build stage does **not** provide one-command installation, checksum-
verified download/update, atomic replacement of an installed executable,
owned unit installation, stlink alias setup, safe uninstall, backend
dependency installation, or actual GitHub release publication. Those require
separately reviewed installer/update/uninstall implementation and the
applicable owner authorization before any production or public release.
