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

if [[ ! -f LICENSE ]] || ! grep -q 'MIT License' LICENSE; then
  echo 'Source LICENSE is missing or not MIT' >&2
  exit 1
fi

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

cp LICENSE "$tmp/LICENSE"
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
license=MIT
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
  cp -- "$tmp/$filename" "$tmp/LICENSE" "$tmp/BUILD-MANIFEST.txt" "$package_dir/"
  cat > "$package_dir/LOCAL-INSTALL.txt" <<EOF_LOCAL
STL verified local archive (version $version, linux/$arch)

For the simplest installation, download the ONE official matching release
file stl_${version}_linux_${arch}_local-install.sh instead of this tar.gz.
Transfer the .sh file unchanged into /root/stl/ and, with that ONE file
present, run as an administrator:
    sudo bash -c 'bash /root/stl/*_local-install.sh'

The .sh file embeds these exact archive bytes and a build-bound digest; it
verifies a private copy, delegates safe unpack to the canonical install.sh,
then installs, safely no-ops, or updates newer Stable STL in one invocation.
It uses no GitHub downloads on the target; only genuinely missing native and
WireGuard packages may use the host's preconfigured signed APT repositories.
IPsec still requires its own separate approved PREPARE/service flow.

If you intentionally use this tar.gz alone, consult the maintainer/operator
manual archive procedure at docs/INSTALL.md of the exact release source.
It remains the canonical format for legacy/archive users, not a shell script.

Verify official source/tag and publisher identity on the downloading device
before running any privileged installer. SHA256SUMS from that same publisher,
or the digest embedded in the .sh file, detects corruption but does NOT
provide an independent publisher signature against a compromised account.
Do not use anonymous mirrors or unverifiable repackaged installers.
WSS/Paqet helpers are NOT included or approved for use.
EOF_LOCAL
STL local installation (version $version, linux/$arch)

Download this archive and the separately published release-wide SHA256SUMS
from the immutable, verified matching STL release. Confirm the archive SHA256
against an independently trusted release identity before executing any
script bytes from the archive. A hash in the same compromised download does
not independently authenticate the publisher.

On the target, copy the archive into a root-owned /root/stl-transfer (0700).
The destination /root/stl must NOT exist yet. As root:
    set -euo pipefail
    umask 077
    cd /root/stl-transfer
    archive="stl_${version}_linux_${arch}_local-install.tar.gz"
    trusted_sha256=PASTE_INDEPENDENTLY_VERIFIED_64_HEX_SHA256
    verified_dir=\$(mktemp -d /root/stl-verified.XXXXXXXX)
    [[ -n "\$verified_dir" && "\$verified_dir" == /root/stl-verified.* &&
       -d "\$verified_dir" && ! -L "\$verified_dir" ]] ||
      { printf 'Private verified archive staging failed\n' >&2; exit 1; }
    install -m 0600 -- "\$archive" "\$verified_dir/\$archive"
    cd -- "\$verified_dir"
    printf '%s  %s\n' "\$trusted_sha256" "\$archive" | sha256sum -c -
    tar -xOzf "\$archive" install.sh > ./verified-installer.sh
    chmod 0600 ./verified-installer.sh
    bash -n ./verified-installer.sh
    bash ./verified-installer.sh unpack \
      --archive "\$PWD/\$archive" --destination /root/stl --sha256 "\$trusted_sha256"
    cd /root/stl
    sha256sum --check SHA256SUMS
    bash -n install.sh

The newly copied root-private 0600 archive is the source of both digest
verification and the completely extracted private installer: never execute
from a writable transfer source. Unpack itself makes an operation-local private archive copy,
authenticates and extracts only those protected bytes, and checks exact six
regular members, names, sizes, fresh destination and internal checksums.
It does not install STL or call APT. Never extract unverified tar members
directly as root; use the checked unpack path.

For a NEW host with native GRE/IPIP and WireGuard selected:
    sudo bash ./install.sh install --bundle . --backends native,wireguard
For an already installer-owned host with a newer, verified release:
    sudo bash ./install.sh update --bundle . --backends native,wireguard
Then check: stl version --json

Existing selected packages are reused. Only missing selected distro
prerequisites may use the host's configured, signed APT repositories.
If APT repositories are unreachable, inspect them and manually choose a
suitable official signed regional mirror; STL never rewrites sources.
IPsec package/service preparation needs its separate exact-plan consent.
Do not download/activate optional WSS or Paqet helpers: neither ships yet.
EOF_LOCAL
  (
    cd "$package_dir"
    sha256sum -- "$filename" install.sh LICENSE BUILD-MANIFEST.txt LOCAL-INSTALL.txt > SHA256SUMS
    sha256sum --check SHA256SUMS >/dev/null
  )
  # Fixed member list, no absolute paths, no symlinks, canonical ordering,
  # stable timestamps and owner metadata. Never archive the staging dir itself.
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -C "$package_dir" -cf - \
    "$filename" install.sh LICENSE BUILD-MANIFEST.txt LOCAL-INSTALL.txt SHA256SUMS \
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
  entries=("stl_${version}_linux_amd64" "stl_${version}_linux_arm64" "LICENSE" "BUILD-MANIFEST.txt"
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
