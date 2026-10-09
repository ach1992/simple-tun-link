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

ldflags="-s -w -X github.com/ach1992/simple-tun-link/internal/version.Version=$version -X github.com/ach1992/simple-tun-link/internal/version.Commit=$commit -X github.com/ach1992/simple-tun-link/internal/version.Date=$commit_date"
for arch in amd64 arm64; do
  filename="stl_"$version"_linux_"$arch
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" \
    -o "$tmp/$filename" ./cmd/stl
done

cp LICENSE "$tmp/LICENSE"
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
(
  cd "$tmp"
  sha256sum -- "stl_"$version"_linux_amd64" "stl_"$version"_linux_arm64" \
    "LICENSE" "BUILD-MANIFEST.txt" > SHA256SUMS
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
