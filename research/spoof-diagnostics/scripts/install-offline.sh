#!/usr/bin/env bash
# Offline installation of the standalone Go tool (local-loopback lab only; field disabled).
# Deliberately never calls apt/curl/wget/pip/go and never mutates STL resources.
set -euo pipefail
umask 077

usage() {
  echo 'Usage: install-offline.sh --verify | --install [--accept] | --rollback --to VERSION [--accept] | --uninstall [--accept] (optional --destdir /existing/root)' >&2
  exit 2
}
mode='' accept=false destdir=/ to_version=''
while (($#)); do
  case "$1" in
    --verify) [[ -z $mode ]] || usage; mode=verify ;;
    --install) [[ -z $mode ]] || usage; mode=install ;;
    --rollback) [[ -z $mode ]] || usage; mode=rollback ;;
    --uninstall) [[ -z $mode ]] || usage; mode=uninstall ;;
    --to) shift; (($#)) || usage; to_version=$1 ;;
    --accept) accept=true ;;
    --destdir) shift; (($#)) || usage; destdir=$1 ;;
    *) usage ;;
  esac
  shift
done
[[ $mode == verify || $mode == install || $mode == rollback || $mode == uninstall ]] || usage
[[ $mode == rollback && -n $to_version || $mode != rollback && -z $to_version ]] || usage
if [[ -n $to_version ]]; then
  [[ $to_version =~ ^(dev-[a-z0-9.-]+|spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?)$ ]] || usage
fi
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
[[ $mode != verify ]] || exit 0

if [[ $accept != true ]]; then
  [[ -t 0 ]] || { echo 'interactive YES or explicit --accept is required' >&2; exit 1; }
  printf 'Approve standalone diagnostic %s under %s (NO STL changes)? Type YES: ' "$mode" "$destdir"
  read -r confirmation
  [[ $confirmation == YES ]] || { echo 'operator declined installation' >&2; exit 1; }
fi

prefix=${destdir%/}
# An empty prefix is correct for filesystem root; avoids //usr/local/bin.
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

# Serialize mutations by destination without a persistent lock file. The lock
# is on the canonical opt directory and is released automatically even if
# the installing shell is killed. Verification-only never acquires this lock.
command -v flock >/dev/null || { echo 'missing standard util-linux flock; refusing unsafe concurrent install' >&2; exit 1; }
if [[ ! -d $prefix/opt ]]; then
  if [[ $mode == install ]]; then
    mkdir -p -- "$prefix/opt"
  elif [[ $mode == uninstall && ! -e $launcher && ! -L $launcher ]]; then
    echo 'Already uninstalled; private state left untouched'
    exit 0
  else
    echo 'not installed; cannot verify tool ownership' >&2
    exit 1
  fi
fi
exec {install_lock}< "$prefix/opt"
if ! flock -n "$install_lock"; then
  echo 'another installer is active under this destination; retry after it completes' >&2
  exit 1
fi

# Existing resources must be provably ours; preserve foreign objects.
if [[ -e $base || -L $base ]]; then
  [[ -d $base && ! -L $base && -f $base/.product-id && ! -L $base/.product-id ]] || { echo 'foreign or ambiguous install location' >&2; exit 1; }
  [[ $(cat "$base/.product-id") == stl-spoofdiag ]] || { echo 'foreign installation ownership' >&2; exit 1; }
fi
# A SIGKILL/power loss may leave a .stage.XXXXXXXX directory. Only after
# acquiring the destination lock and verifying product ownership, recover
# exactly named, owned, regular installer staging members. Unknown material
# is NEVER recursively deleted or silently adopted.
recover_aborted_staging() {
  [[ -d $versions && ! -L $versions ]] || return 0
  local stage member name
  shopt -s nullglob dotglob
  # Preflight ALL stages before removing any, to keep foreign content intact.
  for stage in "$versions"/.stage.*; do
    name=$(basename -- "$stage")
    if [[ ! $name =~ ^\.stage\.[A-Za-z0-9]{8}$ || ! -d $stage || -L $stage ||
          $(stat -c %u -- "$stage") != "$(id -u)" ]]; then
      echo "unsafe or foreign abandoned install stage: $stage" >&2
      return 1
    fi
    for member in "$stage"/*; do
      name=$(basename -- "$member")
      case "$name" in stl-spoofdiag|BUILD-MANIFEST.txt|SHA256SUMS) ;; *)
        echo "foreign install stage member: $member" >&2; return 1 ;;
      esac
      if [[ ! -f $member || -L $member || $(stat -c %u -- "$member") != "$(id -u)" ]]; then
        echo "unsafe install stage member: $member" >&2
        return 1
      fi
    done
  done
  for stage in "$versions"/.stage.*; do
    for member in "$stage"/*; do rm -- "$member"; done
    rmdir -- "$stage"
    echo "Recovered owned incomplete install stage: $stage"
  done
}
recover_aborted_staging || exit 1

legacy_launcher="//opt/stl-spoofdiag/current/stl-spoofdiag"
legacy_owned_link=false
if [[ -e $launcher || -L $launcher ]]; then
  [[ -L $launcher ]] || { echo 'foreign launcher; refusing to overwrite' >&2; exit 1; }
  actual_launcher=$(readlink "$launcher")
  if [[ $actual_launcher != "$base/current/stl-spoofdiag" ]]; then
    # Prior root-only versions installed an otherwise identical //opt link.
    # Accept ONLY that exact historical alias with verified tool ownership.
    [[ $prefix == "" && $actual_launcher == "$legacy_launcher" &&
       -f $base/.product-id && ! -L $base/.product-id &&
       $(cat "$base/.product-id") == stl-spoofdiag ]] || { echo 'foreign launcher; refusing to overwrite' >&2; exit 1; }
    legacy_owned_link=true
  fi
fi
if [[ -e $base/current || -L $base/current ]]; then
  current_target=$(readlink "$base/current" 2>/dev/null || true)
  [[ -L $base/current && $current_target =~ ^releases/(dev-[a-z0-9.-]+|spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?)$ ]] || { echo 'foreign or traversing current version pointer' >&2; exit 1; }
fi

verify_stored_release() {
  local candidate=$1 dir expected actual name
  [[ $candidate =~ ^(dev-[a-z0-9.-]+|spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?)$ ]] ||
    { echo 'invalid stored release identity' >&2; return 1; }
  dir=$versions/$candidate
  [[ -d $dir && ! -L $dir ]] || { echo 'missing or unsafe stored release directory' >&2; return 1; }
  for name in stl-spoofdiag BUILD-MANIFEST.txt SHA256SUMS; do
    [[ -f $dir/$name && ! -L $dir/$name ]] || { echo "unsafe stored release member: $name" >&2; return 1; }
  done
  [[ $(sed -n 's/^project=//p' "$dir/BUILD-MANIFEST.txt") == stl-spoofdiag &&
     $(sed -n 's/^version=//p' "$dir/BUILD-MANIFEST.txt") == "$candidate" ]] ||
    { echo 'stored release manifest disagrees with path' >&2; return 1; }
  expected=$(grep -E '^[0-9a-f]{64}  stl-spoofdiag$' "$dir/SHA256SUMS" || true)
  [[ -n $expected && $(wc -l <<< "$expected") -eq 1 ]] ||
    { echo 'stored executable digest missing' >&2; return 1; }
  actual=$(cd "$dir" && sha256sum -- stl-spoofdiag)
  [[ $expected == "$actual" ]] || { echo 'stored executable digest mismatch' >&2; return 1; }
}

if [[ $mode == rollback ]]; then
  [[ -d $base && -f $base/.product-id ]] || { echo 'not installed' >&2; exit 1; }
  verify_stored_release "$to_version" || exit 1
  # Installed executables and manifests are public; private credentials live
  # elsewhere. Preserve normal nonroot access to a verified local release.
  chmod 0755 "$base" "$versions" "$versions/$to_version"
  next=$base/.current-rollback-$$
  [[ ! -e $next && ! -L $next ]] || { echo 'temporary rollback pointer exists' >&2; exit 1; }
  ln -s "releases/$to_version" "$next"
  mv -Tf -- "$next" "$base/current"
  if [[ ! -e $launcher && ! -L $launcher ]]; then
    mkdir -p "$launchdir"
    ln -s "$base/current/stl-spoofdiag" "$launcher"
  fi
  printf 'Rolled back to verified stored release: %s\n' "$to_version"
  exit 0
fi

if [[ $mode == uninstall ]]; then
  if [[ ! -e $base && ! -L $base && ! -e $launcher && ! -L $launcher ]]; then
    echo 'Already uninstalled; private state left untouched'
    exit 0
  fi
  [[ -d $base && -f $base/.product-id ]] || { echo 'uninstall cannot prove tool ownership' >&2; exit 1; }
  shopt -s nullglob dotglob
  # Prevalidate every object before removal; never recursively remove foreign files.
  for item in "$base"/*; do
    case "$(basename -- "$item")" in .product-id|current|releases) ;; *)
      echo "foreign install member: $item" >&2; exit 1 ;;
    esac
  done
  [[ -d $versions && ! -L $versions ]] || { echo 'missing release directory' >&2; exit 1; }
  for item in "$versions"/*; do
    candidate=$(basename -- "$item")
    verify_stored_release "$candidate" || exit 1
    for member in "$item"/*; do
      case "$(basename -- "$member")" in stl-spoofdiag|BUILD-MANIFEST.txt|SHA256SUMS) ;; *)
        echo "foreign release member: $member" >&2; exit 1 ;;
      esac
    done
  done
  if [[ -L $launcher ]]; then rm -- "$launcher"; fi
  if [[ -L $base/current ]]; then rm -- "$base/current"; fi
  for item in "$versions"/*; do
    for name in stl-spoofdiag BUILD-MANIFEST.txt SHA256SUMS; do rm -- "$item/$name"; done
    rmdir -- "$item"
  done
  rmdir -- "$versions"
  rm -- "$base/.product-id"
  rmdir -- "$base"
  echo 'Removed only tool binaries/links. Private /etc/stl-spoofdiag and /var/lib/stl-spoofdiag were PRESERVED.'
  exit 0
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
# umask 077 must protect staging and signing material, not prevent operators
# from running the installed, nonsecret standalone binary via PATH.
chmod 0755 "$base" "$versions" "$versions/$version"
target="releases/$version"
next=$base/.current-new-$$
[[ ! -e $next && ! -L $next ]] || { echo 'temporary version pointer busy' >&2; exit 1; }
ln -s "$target" "$next"
mv -Tf -- "$next" "$base/current"
if [[ $legacy_owned_link == true ]]; then
  # Canonicalize only the exact formerly owned alias with an atomic switch.
  alias_tmp=$launchdir/.stl-spoofdiag-alias-$$
  [[ ! -e $alias_tmp && ! -L $alias_tmp ]] || { echo 'owned alias migration conflict' >&2; exit 1; }
  ln -s "$base/current/stl-spoofdiag" "$alias_tmp"
  mv -Tf -- "$alias_tmp" "$launcher"
fi
if [[ ! -e $launcher && ! -L $launcher ]]; then
  mkdir -p "$launchdir"
  ln -s "$base/current/stl-spoofdiag" "$launcher"
fi
echo "Installed $version; execute: $launcher version"
