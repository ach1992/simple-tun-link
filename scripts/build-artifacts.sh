#!/usr/bin/env bash
# Build-only v0.1 release artifacts; does not install, publish or change host networking.
set -euo pipefail
umask 077

usage() {
  printf '%s\n' 'Usage: scripts/build-artifacts.sh --snapshot <new-output-dir>' \
    '       scripts/build-artifacts.sh --tag <existing-head-tag> <new-output-dir>' >&2
  exit 2
}

if [[ $# -eq 2 && $1 == --snapshot ]]; then
  mode=snapshot
  output=$2
elif [[ $# -eq 3 && $1 == --tag ]]; then
  mode=tag
  version=$2
  output=$3
else
  usage
fi

repo_dir="$(git rev-parse --show-toplevel)"
cd "$repo_dir"
[[ -z "$(git status --porcelain)" ]] || {
  echo 'Refusing to package a dirty source tree' >&2
  exit 1
}
commit="$(git rev-parse --verify HEAD)"
short_commit="$(git rev-parse --short=12 HEAD)"
commit_date="$(git show -s --format=%cI HEAD)"
if [[ $mode == snapshot ]]; then
  version="dev-$short_commit"
else
  # A real published version can only come from the exact tagged source.
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || {
    echo 'Release tag must follow a safe semantic version pattern' >&2
    exit 2
  }
  git rev-parse -q --verify "refs/tags/$version^{commit}" >/dev/null || {
    echo 'Release tag does not exist' >&2
    exit 1
  }
  tag_commit="$(git rev-parse "refs/tags/$version^{commit}")"
  [[ $tag_commit == "$commit" ]] || {
    echo 'Release tag does not resolve to checked-out HEAD' >&2
    exit 1
  }
fi

[[ $output != "" && $output != "/" && $output != "." ]] || usage
[[ ! -e "$output" && ! -L "$output" ]] || {
  echo 'Refusing to overwrite an existing output path' >&2
  exit 1
}
parent="$(dirname -- "$output")"
[[ -d "$parent" && ! -L "$parent" ]] || {
  echo 'Output parent must already be an existing, non-symlink directory' >&2
  exit 1
}
output_dir="$(cd "$parent" && pwd -P)/$(basename -- "$output")"
tmp="$(mktemp -d "$parent/.stl-artifacts.XXXXXXXX")"
cleanup() { [[ -d $tmp ]] && rm -rf -- "$tmp"; }
trap cleanup EXIT

if [[ ! -f LICENSE ]] || [[ $(sed -n '1p' LICENSE | sed 's/^[[:space:]]*//') != 'GNU AFFERO GENERAL PUBLIC LICENSE' ]] || ! grep -q 'END OF TERMS AND CONDITIONS' LICENSE; then
  echo 'Source LICENSE is missing or not complete GNU AGPLv3' >&2
  exit 1
fi

[[ -f THIRD-PARTY-NOTICES.txt && ! -L THIRD-PARTY-NOTICES.txt &&
   -s THIRD-PARTY-NOTICES.txt ]] || {
  echo 'Historical and upstream legal notices missing from source' >&2
  exit 1
}
# The pre-relicense MIT grant/copyright notice must survive distribution of
# material originally covered by it, even though new releases are AGPL-only.
grep -Fxq -- '--- Original STL MIT copyright and license notice (pre-AGPL releases) ---' THIRD-PARTY-NOTICES.txt &&
grep -Fxq -- 'Copyright (c) 2026 ach1992' THIRD-PARTY-NOTICES.txt &&
grep -Fxq -- '--- Go standard library/runtime (Go toolchain) ---' THIRD-PARTY-NOTICES.txt || {
  echo 'Required historic STL MIT or Go runtime legal notice is missing' >&2
  exit 1
}

# Go's embedded package-only preparer MUST be byte-identical to the
# canonical release installer, not a second independently updated shell.
cmp -s scripts/install.sh cmd/stl/canonical-installer.sh || {
  echo 'Refusing artifact: embedded canonical package installer is stale' >&2
  exit 1
}
ldflags="-s -w -X github.com/ach1992/simple-tun-link/internal/version.Version=$version -X github.com/ach1992/simple-tun-link/internal/version.Commit=$commit -X github.com/ach1992/simple-tun-link/internal/version.Date=$commit_date"
for arch in amd64 arm64; do
  filename="stl_"$version"_linux_"$arch
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" \
    -o "$tmp/$filename" ./cmd/stl
done

# Keep notices synchronized with what the actual release executables link,
# not with every historical module or test-only package in the Go graph.
# go version -m inspects compiled binary metadata without executing it,
# including the separately compiled ARM64 output on an AMD64 builder.
for arch in amd64 arm64; do
  filename="stl_${version}_linux_${arch}"
  binary_metadata=$(go version -m "$tmp/$filename") || {
    echo "Could not inspect actual compiled dependencies for linux/$arch" >&2
    exit 1
  }
  while IFS= read -r module_version; do
    [[ -n $module_version ]] || continue
    grep -Fxq -- "--- $module_version ---" THIRD-PARTY-NOTICES.txt || {
      echo "Missing legal notice for linked dependency on linux/$arch: $module_version" >&2
      exit 1
    }
  done < <(awk '$1 == "dep" {print $2 " " $3}' <<< "$binary_metadata")
done

cp LICENSE THIRD-PARTY-NOTICES.txt "$tmp/"
# Stable releases ship a self-pinned bootstrap using the permanent
# releases/latest/download/stl-bootstrap.sh URL. Never for snapshots/RCs.
stable_bootstrap=false
if [[ $mode == tag && $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  bash scripts/render-stable-bootstrap.sh "$version" "$tmp/stl-bootstrap.sh"
  stable_bootstrap=true
fi
cat > "$tmp/BUILD-MANIFEST.txt" <<EOF
project=simple-tun-link
executable=stl
license=AGPL-3.0-only
version=$version
commit=$commit
build_date=$commit_date
platforms=linux/amd64 linux/arm64
source=https://github.com/ach1992/simple-tun-link
mode=$mode
EOF
# Ship a separate directly transferable, architecture-specific local package.
# The packaged installer is byte-identical to the canonical embedded version;
# the package contains no dependency binaries, host secrets or foreign helpers.
# Per-package checksums list ONLY files contained in that one archive. The
# release-wide checksums additionally authenticate each complete archive.
for arch in amd64 arm64; do
  filename="stl_${version}_linux_${arch}"
  archive="stl_${version}_linux_${arch}_local-install.tar.gz"
  package_dir="$tmp/.package-$arch"
  mkdir -m 0700 -- "$package_dir"
  cp -- scripts/install.sh "$package_dir/install.sh"
  cp -- "$tmp/$filename" "$tmp/LICENSE" "$tmp/THIRD-PARTY-NOTICES.txt" "$tmp/BUILD-MANIFEST.txt" "$package_dir/"
  cat > "$package_dir/LOCAL-INSTALL.txt" <<EOF_LOCAL
STL verified local archive (version $version, linux/$arch)

For the simplest installation, download the ONE official matching release
file stl_${version}_linux_${arch}_local-install.sh instead of this tar.gz.
Copy the official file unchanged into /root/stl/ (root-owned 0700 directory,
file mode 0600). After choosing and trusting the HTTPS GitHub or Mirror source,
run as an administrator:
    sudo bash /root/stl/stl_${version}_linux_${arch}_local-install.sh
    For an existing version, explicitly append --update.
No external SHA256 needs to be typed for this simple operator-trusted source
path. Optional independently SHA-pinned first-hop scripts are documented in
docs/INSTALL.md if independent source authentication is desired. The file's
build-bound archive digest proves embedded byte consistency, NOT that a
maliciously replaced complete shell launcher came from GitHub.

The .sh file embeds these exact archive bytes and a build-bound digest; it
verifies a private copy, delegates safe unpack to the canonical install.sh,
then installs or safely no-ops; replacing an older installed Stable
requires the explicit --update argument.
It uses no GitHub downloads on the target; only genuinely missing native and
WireGuard packages may use the host's preconfigured signed APT repositories.
IPsec still requires its own separate approved PREPARE/service flow.

If you intentionally use this tar.gz alone, consult the maintainer/operator
manual archive procedure at docs/INSTALL.md of the exact release source.
It remains the canonical format for legacy/archive users, not a shell script.

For the ordinary operator-trusted HTTPS workflow, select a trusted source
and correct official version/architecture. No independent full-file SHA256
or publisher key needs to be supplied. HTTPS and the internal archive digest
do NOT independently prove GitHub publisher identity if a complete launcher
is replaced. Do not trust unknown mirrors or repackaged installers.

OPTIONAL independently SHA256-pinned local workflow: on a trusted device,
verify the official publisher/tag, obtain the full-file .sh SHA256 separately,
and use the pinned transfer command documented in docs/INSTALL.md. Do not
take the trust pin solely from the same untrusted Mirror; a checksum from
the same publisher is an integrity receipt, NOT an independent signature
against a compromised publisher account.
An OPTIONAL approved upstream wstunnel v11.0.0 archive may be placed beside
this single-file installer. Explicit --with-wss on the SAME single-file
installer command selects WSS; merely placing an optional archive has no
effect. The canonical installer verifies the exact architecture-specific file, verifies both archive and extracted executable
SHA-256 and installs it under the canonical installer-owned path.
See docs/INSTALL.md for official filenames, HTTPS source trust, and the
OPTIONAL independently SHA256-pinned workflow.
An OPTIONAL official Hysteria v2.13.0 binary hysteria-linux-$arch may also
be placed beside this file. Explicit --with-quic selects its pinned binary
and the WireGuard/nftables distro prerequisites; it creates no Link or service.
Its SHA-256 is verified before core installation and again from a private
snapshot before no-replace companion publication. Helpers are not bundled.
Other helpers (including Paqet) are NOT included in STL.
EOF_LOCAL
  (
    cd "$package_dir"
    sha256sum -- "$filename" install.sh LICENSE THIRD-PARTY-NOTICES.txt BUILD-MANIFEST.txt LOCAL-INSTALL.txt > SHA256SUMS
    sha256sum --check SHA256SUMS >/dev/null
  )
  # Fixed member list, no absolute paths, no symlinks, canonical ordering,
  # stable timestamps and owner metadata. Never archive the staging dir itself.
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -C "$package_dir" -cf - \
    "$filename" install.sh LICENSE THIRD-PARTY-NOTICES.txt BUILD-MANIFEST.txt LOCAL-INSTALL.txt SHA256SUMS \
    | gzip -n > "$tmp/$archive"
  rm -rf -- "$package_dir"

  # One-file copy-as-is local UX: a small build-bound shell bootstrap followed
  # by the EXACT tested archive bytes. The bootstrap only verifies/stages and
  # dispatches to the canonical installer; do not create another install engine.
  local_entry="stl_${version}_linux_${arch}_local-install.sh"
  archive_digest=$(sha256sum -- "$tmp/$archive" | awk '{print $1}')
  archive_bytes=$(stat -c %s -- "$tmp/$archive")
  sed -e "s|@VERSION@|$version|g" \
      -e "s|@COMMIT@|$commit|g" \
      -e "s|@ARCH@|$arch|g" \
      -e "s|@ARCHIVE@|$archive|g" \
      -e "s|@DIGEST@|$archive_digest|g" \
      -e "s|@BYTES@|$archive_bytes|g" \
      scripts/local-install-entrypoint.sh > "$tmp/$local_entry"
  cat -- "$tmp/$archive" >> "$tmp/$local_entry"
done
(
  cd "$tmp"
  entries=("stl_${version}_linux_amd64" "stl_${version}_linux_arm64" "LICENSE" "THIRD-PARTY-NOTICES.txt" "BUILD-MANIFEST.txt"
    "stl_${version}_linux_amd64_local-install.tar.gz"
    "stl_${version}_linux_arm64_local-install.tar.gz"
    "stl_${version}_linux_amd64_local-install.sh"
    "stl_${version}_linux_arm64_local-install.sh")
  if [[ $stable_bootstrap == true ]]; then
    entries+=("stl-bootstrap.sh")
  fi
  sha256sum -- "${entries[@]}" > SHA256SUMS
  sha256sum --check SHA256SUMS >/dev/null
)

# Final publication is local and atomic at the directory level.
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || {
  echo 'Output path appeared during build; not overwriting' >&2
  exit 1
}
mv -T -n -- "$tmp" "$output_dir"
[[ ! -d "$tmp" && -d "$output_dir" ]] || {
  echo 'Output path raced with another writer; preserving existing path' >&2
  exit 1
}
trap - EXIT
printf 'Artifact bundle: %s\n' "$output_dir"
printf 'Version: %s\nCommit: %s\n' "$version" "$commit"
