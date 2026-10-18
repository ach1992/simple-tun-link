#!/usr/bin/env bash
# Offline installation of the standalone Go tool (local-loopback lab only; field disabled).
# Deliberately never calls apt/curl/wget/pip/go and never mutates STL resources.
set -euo pipefail
umask 077

usage() {
  echo 'Usage: bash install-offline.sh --verify | --install [--accept] [--destdir /existing/disposable/root]' >&2
  exit 2
}
mode='' accept=false destdir=/
while (($#)); do
  case "$1" in
    --verify) [[ -z $mode ]] || usage; mode=verify ;;
    --install) [[ -z $mode ]] || usage; mode=install ;;
    --accept) accept=true ;;
    --destdir) shift; (($#)) || usage; destdir=$1 ;;
    *) usage ;;
  esac
  shift
done
[[ $mode == verify || $mode == install ]] || usage
[[ $destdir == /* && $destdir != *'/../'* && $destdir != *'/./'* && $destdir != */.. && $destdir != */. ]] || usage
[[ -d $destdir && ! -L $destdir ]] || { echo 'existing non-symlink destination root required' >&2; exit 1; }
[[ $(cd -P -- "$destdir" && pwd -P) == "$destdir" ]] || { echo 'non-canonical destination root' >&2; exit 1; }

bundle=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
for name in stl-spoofdiag install-offline.sh README.md LICENSE sources-private.csv evidence-private.json BUILD-MANIFEST.txt SHA256SUMS; do
  [[ -f $bundle/$name && ! -L $bundle/$name ]] || { echo "invalid bundle member: $name" >&2; exit 1; }
done
( cd "$bundle"; sha256sum --check --strict SHA256SUMS > /dev/null ) || {
  echo 'bundle checksum verification failed' >&2
  exit 1
}
field() { sed -n "s/^$1=//p" "$bundle/BUILD-MANIFEST.txt"; }
[[ $(field project) == stl-spoofdiag ]] || { echo 'wrong product manifest' >&2; exit 1; }
version=$(field version)
commit=$(field commit)
platform=$(field platform)
[[ $version =~ ^(dev-[a-z0-9.-]+|spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?)$ ]] || { echo 'unsafe version' >&2; exit 1; }
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo 'unsafe commit identity' >&2; exit 1; }
[[ $platform == linux/amd64 || $platform == linux/arm64 ]] || { echo 'unsupported bundle platform' >&2; exit 1; }
case "$(uname -m)" in x86_64) host_arch=amd64 ;; aarch64) host_arch=arm64 ;; *) echo 'unsupported host architecture' >&2; exit 1 ;; esac
[[ $platform == "linux/$host_arch" ]] || { echo 'archive architecture does not match this host' >&2; exit 1; }
"$bundle/stl-spoofdiag" version | grep -F -q "\"version\": \"$version\"" || {
  echo 'bundle binary version mismatch' >&2
  exit 1
}
"$bundle/stl-spoofdiag" version | grep -F -q "\"commit\": \"$commit\"" || {
  echo 'bundle binary commit mismatch' >&2
  exit 1
}
echo "Verified local offline bundle: $version / $commit / $platform"
[[ $mode == install ]] || exit 0

if [[ $accept != true ]]; then
  [[ -t 0 ]] || { echo 'interactive YES or explicit --accept is required' >&2; exit 1; }
  printf 'Install standalone diagnostic only under %s (NO STL changes)? Type YES: ' "$destdir"
  read -r confirmation
  [[ $confirmation == YES ]] || { echo 'operator declined installation' >&2; exit 1; }
fi

prefix=$destdir
[[ $prefix == / ]] || prefix=${prefix%/}
base=$prefix/opt/stl-spoofdiag
versions=$base/releases
launchdir=$prefix/usr/local/bin
launcher=$launchdir/stl-spoofdiag

# Reject symlinked intermediate paths even if the leaf itself looks owned.
# This also applies to preexisting release directories and the launcher parent.
for d in "$prefix/opt" "$base" "$versions" "$prefix/usr" "$prefix/usr/local" "$launchdir"; do
  if [[ -e $d || -L $d ]]; then
    [[ -d $d && ! -L $d ]] || { echo "unsafe intermediate directory: $d" >&2; exit 1; }
  fi
done

# Existing resources must be provably ours; preserve foreign objects.
if [[ -e $base || -L $base ]]; then
  [[ -d $base && ! -L $base && -f $base/.product-id && ! -L $base/.product-id ]] || { echo 'foreign or ambiguous install location' >&2; exit 1; }
  [[ $(cat "$base/.product-id") == stl-spoofdiag ]] || { echo 'foreign installation ownership' >&2; exit 1; }
fi
if [[ -e $launcher || -L $launcher ]]; then
  [[ -L $launcher && $(readlink "$launcher") == "$base/current/stl-spoofdiag" ]] || { echo 'foreign launcher; refusing to overwrite' >&2; exit 1; }
fi
if [[ -e $base/current || -L $base/current ]]; then
  current_target=$(readlink "$base/current" 2>/dev/null || true)
  [[ -L $base/current && $current_target =~ ^releases/(dev-[a-z0-9.-]+|spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?)$ ]] || { echo 'foreign or traversing current version pointer' >&2; exit 1; }
fi
if [[ -e $versions/$version || -L $versions/$version ]]; then
  [[ -d $versions/$version && ! -L $versions/$version && -f $versions/$version/BUILD-MANIFEST.txt && ! -L $versions/$version/BUILD-MANIFEST.txt && -f $versions/$version/stl-spoofdiag && ! -L $versions/$version/stl-spoofdiag && -f $versions/$version/SHA256SUMS && ! -L $versions/$version/SHA256SUMS ]] || { echo 'ambiguous existing version directory' >&2; exit 1; }
  cmp -s "$bundle/BUILD-MANIFEST.txt" "$versions/$version/BUILD-MANIFEST.txt" || { echo 'version identity conflict' >&2; exit 1; }
  cmp -s "$bundle/stl-spoofdiag" "$versions/$version/stl-spoofdiag" || { echo 'version binary conflict' >&2; exit 1; }
else
  mkdir -p "$versions" "$launchdir"
  [[ -f $base/.product-id ]] || printf '%s\n' stl-spoofdiag > "$base/.product-id"
  stage=$(mktemp -d "$versions/.stage.XXXXXXXX")
  cleanup() { [[ ! -d $stage ]] || rm -rf -- "$stage"; }
  trap cleanup EXIT
  install -m 0755 "$bundle/stl-spoofdiag" "$stage/stl-spoofdiag"
  install -m 0644 "$bundle/BUILD-MANIFEST.txt" "$stage/BUILD-MANIFEST.txt"
  install -m 0644 "$bundle/SHA256SUMS" "$stage/SHA256SUMS"
  mv -T -- "$stage" "$versions/$version"
  trap - EXIT
fi
mkdir -p "$base"
target="releases/$version"
next=$base/.current-new-$$
[[ ! -e $next && ! -L $next ]] || { echo 'temporary version pointer busy' >&2; exit 1; }
ln -s "$target" "$next"
mv -Tf -- "$next" "$base/current"
if [[ ! -e $launcher && ! -L $launcher ]]; then
  mkdir -p "$launchdir"
  ln -s "$base/current/stl-spoofdiag" "$launcher"
fi
echo "Installed $version; execute: $launcher version"
