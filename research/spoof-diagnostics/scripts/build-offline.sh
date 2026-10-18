#!/usr/bin/env bash
# Research-only binary packaging: builds no STL assets and never publishes releases.
set -euo pipefail
umask 077
usage() { echo 'usage: scripts/build-offline.sh <new-output-directory> <source-sha> <version> [amd64|arm64]' >&2; exit 2; }
[[ $# -ge 3 && $# -le 4 ]] || usage
output=$1
commit=$2
version=$3
arch=${4:-amd64}
[[ $arch == amd64 || $arch == arm64 ]] || usage
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo 'exact 40-digit source SHA required' >&2; exit 2; }
[[ $version =~ ^(dev-[a-z0-9.-]+|spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?)$ ]] || usage
[[ ! -e $output && ! -L $output ]] || { echo 'output must not exist' >&2; exit 1; }
parent=$(dirname -- "$output")
[[ -d $parent && ! -L $parent ]] || { echo 'output parent invalid' >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ -f $here/go.mod && -f $here/cmd/stl-spoofdiag/main.go ]] || exit 1
tmp=$(mktemp -d "$parent/.spoofdiag-bundle.XXXXXXXX")
cleanup() { [[ ! -d $tmp ]] || rm -rf -- "$tmp"; }
trap cleanup EXIT
( cd "$here"; GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$version -X main.commit=$commit" \
    -o "$tmp/stl-spoofdiag" ./cmd/stl-spoofdiag )
chmod 755 "$tmp/stl-spoofdiag"
cp "$here/scripts/install-offline.sh" "$tmp/install-offline.sh"
chmod 755 "$tmp/install-offline.sh"
repo_root=$(cd "$here/../.." && pwd -P)
cp "$repo_root/LICENSE" "$tmp/LICENSE"
cp "$here/README.md" "$tmp/README.md"
# The canonical README links to these local references; bundle the exact
# documentation instead of shipping links that break on an offline host.
mkdir "$tmp/docs"
cp "$here/docs/"*.md "$tmp/docs/"
cp "$here/examples/sources-private.csv" "$tmp/sources-private.csv"
cp "$here/examples/evidence-private.json" "$tmp/evidence-private.json"
cat > "$tmp/BUILD-MANIFEST.txt" <<EOF
project=stl-spoofdiag
version=$version
commit=$commit
platform=linux/$arch
cgo_enabled=0
go_version=$(go version)
source_repo=https://github.com/ach1992/simple-tun-link
mode=standalone-research-snapshot
EOF
( cd "$tmp"; sha256sum -- stl-spoofdiag install-offline.sh README.md LICENSE sources-private.csv evidence-private.json BUILD-MANIFEST.txt docs/*.md > SHA256SUMS; sha256sum --check SHA256SUMS > /dev/null )
# A snapshot builds a staged package only. No tags, release mutations or network.
mv -T -n -- "$tmp" "$output"
trap - EXIT
printf 'Built self-contained offline directory: %s\n' "$output"
