#!/usr/bin/env bash
# Build tool-only, exact-source releasable assets for independent review.
# Intentionally NEVER creates tags, Releases or deploys anything.
set -euo pipefail
umask 077

fail() { printf 'SpoofDiag release preparation: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 2 ]] || fail 'usage: prepare-release.sh spoofdiag-vX.Y.Z[-rc.N] /new/output-directory'
version=$1 output=$2
[[ $version =~ ^spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] ||
  fail 'release version must have spoofdiag-v prefix, never STL v*'
[[ $output != / && $output != . && ! -e $output && ! -L $output ]] ||
  fail 'use a fresh output directory; refusing overwrite'
parent=$(dirname -- "$output")
[[ -d $parent && ! -L $parent ]] || fail 'invalid output parent'
tool=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
repo=$(git -C "$tool" rev-parse --show-toplevel)
sha=$(git -C "$repo" rev-parse HEAD)
[[ $sha =~ ^[0-9a-f]{40}$ ]] || fail 'bad HEAD identity'
[[ -z $(git -C "$repo" status --porcelain) ]] ||
  fail 'source tree must be committed and clean before assembly'
branch=$(git -C "$repo" branch --show-current)
# Local worktree may be detached when checking an approved tag:
if [[ $branch != dev-spoof ]]; then
  existing=$(git -C "$repo" rev-parse -q --verify "refs/tags/$version^{}" || true)
  remote_sha=$(git -C "$repo" ls-remote --heads origin dev-spoof | awk '{print $1}')
  [[ $branch == "" && ( $existing == "$sha" || $remote_sha == "$sha" ) ]] ||
    fail 'only dev-spoof, its exact detached remote HEAD, or an exact commit-matched spoofdiag-v* tag may be packaged'
fi
existing=$(git -C "$repo" rev-parse -q --verify "refs/tags/$version^{}" || true)
[[ -z $existing || $existing == "$sha" ]] ||
  fail 'tag already exists but points to a different commit'

stage=$(mktemp -d "$parent/.spoofdiag-release-prep.XXXXXXXX") ||
  fail 'cannot create private preparation directory'
cleanup() { if [[ -d $stage && ! -L $stage ]]; then rm -rf -- "$stage"; fi; }
trap cleanup EXIT
for arch in amd64 arm64; do
  bash "$tool/scripts/package-offline.sh" "$stage/$arch" "$sha" "$version" "$arch" >/dev/null
  archive="${version}_linux_${arch}.tar.gz"
  ( cd "$stage/$arch" && sha256sum -c "${archive}.sha256" >/dev/null ) ||
    fail "archive SHA256 failed for $arch"
  mv -- "$stage/$arch/$archive" "$stage/$archive"
  mv -- "$stage/$arch/${archive}.sha256" "$stage/${archive}.sha256"
  rmdir -- "$stage/$arch"
done
cp -- "$tool/scripts/online-bootstrap.sh" "$stage/online-bootstrap.sh"
chmod 755 "$stage/online-bootstrap.sh"
( cd "$stage"; sha256sum -- "${version}_linux_amd64.tar.gz" "${version}_linux_arm64.tar.gz" online-bootstrap.sh > SHA256SUMS;
  sha256sum -c SHA256SUMS >/dev/null )
cat > "$stage/RELEASE-SOURCE.txt" <<META
product=stl-spoofdiag
release_tag=$version
source_branch=dev-spoof
source_commit=$sha
repository=https://github.com/ach1992/simple-tun-link
artifact_scope=research/spoof-diagnostics-only
distribution_status=CANDIDATE_NOT_PUBLISHED
META
mv -T -n -- "$stage" "$output" || fail 'could not commit isolated output directory'
trap - EXIT
printf 'Prepared ONLY SpoofDiag assets from %s at %s\n' "$version" "$sha"
printf 'Inspect and independently review the exact bytes before creating a public prerelease.\n'
