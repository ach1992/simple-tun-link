#!/usr/bin/env bash
# Create an entirely self-contained offline tarball from the Go source.
# Snapshot only. This script does NOT tag or publish any GitHub release.
set -euo pipefail
umask 077
[[ $# -eq 4 ]] || { echo 'usage: scripts/package-offline.sh <new-package-directory> <40-digit-source-sha> <version> <amd64|arm64>' >&2; exit 2; }
out=$1; sha=$2; version=$3; arch=$4
[[ $out != / && $out != . && ! -e $out && ! -L $out ]] || { echo 'fresh output directory required' >&2; exit 1; }
[[ $version =~ ^(dev-[a-z0-9.-]+|spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?)$ ]] || exit 2
[[ $arch == amd64 || $arch == arm64 ]] || exit 2
parent=$(dirname -- "$out")
[[ -d $parent && ! -L $parent ]] || exit 1
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
tmp=$(mktemp -d "$parent/.spoofdiag-package.XXXXXXXX")
cleanup() { [[ ! -d $tmp ]] || rm -rf -- "$tmp"; }
trap cleanup EXIT
bash "$here/scripts/build-offline.sh" "$tmp/stl-spoofdiag" "$sha" "$version" "$arch"
filename="spoofdiag-${version}_linux_${arch}.tar.gz"
# The archive contains one fixed private directory, not files scattered in /root.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
  -C "$tmp" -czf "$tmp/$filename" stl-spoofdiag
(
  cd "$tmp"
  sha256sum -- "$filename" > "${filename}.sha256"
  sha256sum --check "${filename}.sha256" >/dev/null
  # Consume the complete tar listing before checking members: grep -q in
  # a pipe closes early, giving tar SIGPIPE under set -o pipefail.
  tar -tzf "$filename" > "$tmp/archive-members.txt"
  grep -Fxq 'stl-spoofdiag/install-offline.sh' "$tmp/archive-members.txt"
  grep -Fxq 'stl-spoofdiag/stl-spoofdiag' "$tmp/archive-members.txt"
  rm -- "$tmp/archive-members.txt"
)
# Do not duplicate the unpacked staging directory in the output artifact.
rm -rf -- "$tmp/stl-spoofdiag"
mv -T -n -- "$tmp" "$out"
trap - EXIT
echo "Self-contained archive: $out/$filename"
echo "Verify external checksum: cd $out && sha256sum -c ${filename}.sha256"
