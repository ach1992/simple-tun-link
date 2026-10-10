#!/usr/bin/env bash
# Release installer for simple-tun-link. Does not create/remove Links or systemd units.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

usage() {
  cat >&2 <<'USAGE'
Usage:
  install.sh install --version vX.Y.Z [--prefix /usr/local]
  install.sh update --version vX.Y.Z [--prefix /usr/local]
  install.sh install|update --bundle /path/to/release-bundle [--prefix /usr/local]
  install.sh uninstall [--prefix /usr/local]

The remote source is the official GitHub release, never a caller-supplied URL.
--bundle is for locally built/tested bundles. No host Links are modified.
USAGE
  exit 2
}
fail() { printf 'stl installer: %s\n' "$*" >&2; exit 1; }
[[ $# -ge 1 ]] || usage
action=$1
shift
case "$action" in install|update|uninstall) ;; *) usage ;; esac
prefix=/usr/local
version=
bundle=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) [[ $# -ge 2 && -z $version ]] || usage; version=$2; shift 2 ;;
    --bundle) [[ $# -ge 2 && -z $bundle ]] || usage; bundle=$2; shift 2 ;;
    --prefix) [[ $# -ge 2 ]] || usage; prefix=$2; shift 2 ;;
    *) usage ;;
  esac
done
if [[ $action == uninstall ]]; then
  [[ -z $version && -z $bundle ]] || usage
else
  [[ -n $version && -z $bundle || -z $version && -n $bundle ]] || usage
fi
if [[ -n $version ]]; then
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]] || usage
fi
[[ $prefix == /* && $prefix != / && -d $prefix && ! -L $prefix ]] || fail 'prefix must be an existing absolute non-symlink directory'
[[ "$(realpath -e -- "$prefix")" == "$prefix" ]] || fail 'prefix must be canonical (no symlinks or dot segments)'
# Nondefault prefixes are isolated/offline test or custom local installations.
[[ $prefix == /usr/local || -n $bundle || $action == uninstall ]] || fail 'a nondefault prefix requires an offline --bundle'
[[ $prefix != /usr/local || $EUID -eq 0 ]] || fail 'installation to /usr/local requires root'
bin_dir="$prefix/bin"
record_dir="$prefix/lib/simple-tun-link"
target="$bin_dir/stl"
alias="$bin_dir/stlink"
record="$record_dir/install-record"
lock="$record_dir/.maintenance.lock"
[[ -d $bin_dir && ! -L $bin_dir && -d $prefix/lib && ! -L $prefix/lib ]] || fail 'prefix must already contain safe bin and lib directories'

# Default system-wide install must not traverse a writable or unowned directory.
if [[ $prefix == /usr/local ]]; then
  for path in / /usr /usr/local "$bin_dir" "$prefix/lib"; do
    [[ ! -L $path && -d $path && $(stat -c %u -- "$path") == 0 ]] || fail "untrusted installation directory: $path"
    perms=$(stat -c %a -- "$path")
    [[ $perms =~ ^[0-7]{3,4}$ ]] && (( (8#$perms & 8#022) == 0 )) || fail "installation directory is writable by non-root: $path"
  done
fi

if [[ $action != install ]]; then
  [[ -d $record_dir && ! -L $record_dir ]] || fail 'no STL installer-owned installation found'
fi
if [[ ! -e $record_dir ]]; then
  mkdir -m 0700 -- "$record_dir" || fail 'cannot create installer-owned metadata directory'
fi
[[ -d $record_dir && ! -L $record_dir ]] || fail 'untrusted installer metadata directory'
if [[ $prefix == /usr/local ]]; then
  [[ $(stat -c %u -- "$record_dir") == 0 ]] || fail 'installer metadata must be root-owned'
  perms=$(stat -c %a -- "$record_dir")
  [[ $perms =~ ^[0-7]{3,4}$ ]] && (( (8#$perms & 8#077) == 0 )) || fail 'installer metadata directory must be private'
fi
[[ ! -L $lock && ( ! -e $lock || -f $lock ) ]] || fail 'unsafe installer lock identity'
exec 9>>"$lock"
flock -x -w 30 9 || fail 'another STL installer is running'
is_regular() { [[ -f $1 && ! -L $1 ]]; }
hash_file() { sha256sum -- "$1" | awk '{print $1}'; }
sync_paths() { sync -f -- "$@"; }
failpoint() {
  if [[ $prefix != /usr/local && ${STL_INSTALL_TEST_FAIL_AT:-} == "$1" ]]; then
    fail "injected $1 durability/transaction failure (isolated test only)"
  fi
}
# Preserve uncertain transactions and never replay them blindly. A prior
# durable COMMITTED journal may be retired only after verifying the recorded
# current installation identity under the exclusive maintenance gate.
shopt -s nullglob
recovery_dirs=("$bin_dir"/.stl-install.*)
shopt -u nullglob
for recovery in "${recovery_dirs[@]}"; do
  [[ -d $recovery && ! -L $recovery ]] || fail 'unsafe retained recovery identity'
  marker="$recovery/COMMITTED"
  is_regular "$marker" || fail 'unreconciled STL installer recovery directory exists; inspect it before retrying'
  saved_action=$(sed -n 's/^operation=//p' "$marker")
  saved_hash=$(sed -n 's/^sha256=//p' "$marker")
  [[ $saved_hash =~ ^[0-9a-f]{64}$ ]] || fail 'invalid committed recovery marker'
  grep -qx 'status=committed' "$marker" || fail 'invalid committed recovery status'
  case "$saved_action" in
    install|update)
      is_regular "$record" && is_regular "$target" &&
        [[ -L $alias && $(readlink -- "$alias") == stl ]] &&
        [[ $(hash_file "$target") == "$saved_hash" ]] &&
        grep -qx "sha256=$saved_hash" "$record" || fail 'committed installation differs; preserve recovery evidence'
      ;;
    uninstall)
      [[ ! -e $record && ! -L $record && ! -e $target && ! -L $target && ! -e $alias && ! -L $alias ]] || fail 'committed uninstall differs; preserve recovery evidence'
      ;;
    *) fail 'unknown committed recovery operation' ;;
  esac
  rm -rf -- "$recovery" || fail 'cannot retire verified committed recovery'
  sync_paths "$bin_dir" || fail 'cannot durably retire verified committed recovery'
done
read_record() {
  is_regular "$record" || fail 'STL ownership record is missing or not regular'
  grep -qx 'format=1' "$record" && grep -qx 'project=simple-tun-link' "$record" || fail 'invalid ownership record'
  prior_version=$(sed -n 's/^version=//p' "$record")
  prior_hash=$(sed -n 's/^sha256=//p' "$record")
  [[ $prior_hash =~ ^[0-9a-f]{64}$ && $prior_version =~ ^(v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?|dev-[0-9a-f]{12})$ ]] || fail 'invalid ownership record fields'
  is_regular "$target" || fail 'installed stl is missing or unsafe'
  [[ $(hash_file "$target") == "$prior_hash" ]] || fail 'installed stl differs from recorded owned binary; refusing overwrite'
  [[ -L $alias && $(readlink -- "$alias") == stl ]] || fail 'stlink alias missing or differs from installer-owned symlink'
  prior_record_hash=$(hash_file "$record")
}

if [[ $action == install ]]; then
  [[ ! -e $record && ! -L $record && ! -e $target && ! -L $target && ! -e $alias && ! -L $alias ]] || fail 'an installed or foreign STL identity already exists; refusing takeover'
else
  read_record
fi

# A release operation is not a Link lifecycle. Prevent uninstall unless STL's
# canonical read contract proves zero Links and the Engine-owned unit is absent.
if [[ $action == uninstall ]]; then
  # Installer holds exclusive maintenance flock. The canonical Go preflight
  # is the single authority on durable state and systemd enablement.
  checked=$("$target" maintenance pre-uninstall --json) || fail 'canonical uninstall preflight failed; no files removed'
  [[ $checked == '{"schema_version":1,"ready":true}' ]] || fail 'canonical uninstall preflight did not prove safety'

fi

stage=
record_tmp=
new_hash=
new_record_hash=
keep_recovery=0

# All failure compensation is identity-guarded. Keep previous recovery copies
# in stage (do not mv away the only copy) until the repaired canonical state
# and every applicable parent directory are durably synchronized.
finish() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ -n $stage && -d $stage ]]; then
    if (( rc == 0 )); then
      if [[ -f $stage/COMMITTED ]]; then
        # A deliberately retained, fsynced commit marker is reconciled and
        # retired by the next installer invocation, after verifying identity.
        :
      else
        rm -rf -- "$stage" || rc=1
        sync_paths "$bin_dir" || rc=1
      fi
    elif [[ -f $stage/COMMITTED ]]; then
      keep_recovery=1
    else
      if [[ $action == uninstall ]]; then
        if [[ ! -f $target || -L $target || $(hash_file "$target") != "$prior_hash" ]]; then
          if [[ ! -e $target && ! -L $target && -f $stage/previous-stl ]] &&
             [[ $(hash_file "$stage/previous-stl") == "$prior_hash" ]]; then
            cp -p -- "$stage/previous-stl" "$stage/recover-stl" &&
              sync_paths "$stage/recover-stl" "$stage" &&
              mv -T -- "$stage/recover-stl" "$target" || keep_recovery=1
          else
            keep_recovery=1
          fi
        fi
        if [[ ! -f $record || -L $record || $(hash_file "$record") != "$prior_record_hash" ]]; then
          if [[ ! -e $record && ! -L $record && -f $stage/previous-record ]] &&
             [[ $(hash_file "$stage/previous-record") == "$prior_record_hash" ]]; then
            cp -p -- "$stage/previous-record" "$record_dir/.stl-restore-record.$$" &&
              sync_paths "$record_dir/.stl-restore-record.$$" &&
              mv -T -- "$record_dir/.stl-restore-record.$$" "$record" || keep_recovery=1
          else
            keep_recovery=1
          fi
        fi
        if [[ ! -L $alias || $(readlink -- "$alias") != stl ]]; then
          if [[ ! -e $alias && ! -L $alias ]]; then
            ln -s stl "$alias" || keep_recovery=1
          else
            keep_recovery=1
          fi
        fi
      else
        if [[ -n $new_hash && -f $target && ! -L $target && $(hash_file "$target") == "$new_hash" ]]; then
          if [[ $action == update ]]; then
            if [[ $new_hash != "$prior_hash" ]]; then
              if [[ -f $stage/previous-stl && $(hash_file "$stage/previous-stl") == "$prior_hash" ]]; then
                cp -p -- "$stage/previous-stl" "$stage/recover-stl" &&
                  sync_paths "$stage/recover-stl" "$stage" &&
                  mv -T -- "$stage/recover-stl" "$target" || keep_recovery=1
              else
                keep_recovery=1
              fi
            fi
          else
            rm -- "$target" || keep_recovery=1
          fi
        elif [[ $action == install && ( -e $target || -L $target ) ]]; then
          keep_recovery=1
        elif [[ $action == update ]] &&
             [[ ! -f $target || -L $target || $(hash_file "$target") != "$prior_hash" ]]; then
          keep_recovery=1
        fi
        if [[ $action == install && -L $alias && $(readlink -- "$alias") == stl ]]; then
          rm -- "$alias" || keep_recovery=1
        elif [[ $action == install && ( -e $alias || -L $alias ) ]]; then
          keep_recovery=1
        fi
        if [[ -n $new_record_hash && -f $record && ! -L $record && $(hash_file "$record") == "$new_record_hash" ]]; then
          if [[ $action == update ]]; then
            if [[ -f $stage/previous-record && $(hash_file "$stage/previous-record") == "$prior_record_hash" ]]; then
              cp -p -- "$stage/previous-record" "$record_dir/.stl-restore-record.$$" &&
                sync_paths "$record_dir/.stl-restore-record.$$" &&
                mv -T -- "$record_dir/.stl-restore-record.$$" "$record" || keep_recovery=1
            else
              keep_recovery=1
            fi
          else
            rm -- "$record" || keep_recovery=1
          fi
        elif [[ $action == install && ( -e $record || -L $record ) ]]; then
          keep_recovery=1
        elif [[ $action == update ]] &&
             [[ ! -f $record || -L $record || $(hash_file "$record") != "$prior_record_hash" ]]; then
          keep_recovery=1
        fi
      fi
      # A successful apparent compensation is not a proven rollback until
      # all restored files, aliases and directory entries have been fsynced.
      if (( !keep_recovery )); then
        [[ ! -e $target || ( -f $target && ! -L $target ) ]] || keep_recovery=1
        if [[ -f $target ]]; then sync_paths "$target" || keep_recovery=1; fi
        if [[ -f $record ]]; then sync_paths "$record" || keep_recovery=1; fi
        sync_paths "$bin_dir" "$record_dir" "$stage" || keep_recovery=1
        if [[ $prefix != /usr/local && ${STL_INSTALL_TEST_FAIL_AT:-} == compensation-sync ]]; then
          keep_recovery=1
        fi
      fi
      if (( !keep_recovery )); then
        rm -rf -- "$stage" || keep_recovery=1
        sync_paths "$bin_dir" || keep_recovery=1
      fi
    fi
    if (( keep_recovery )); then
      printf 'stl installer: partial failure; inspect retained recovery directory: %s\n' "$stage" >&2
    fi
  fi
  if [[ -n $record_tmp ]]; then
    rm -f -- "$record_tmp" "$record_tmp.recover"
  fi
  exit "$rc"
}

# All source and record materials must be synced before the first canonical
# namespace mutation. COMMITTED is written only after both identities are
# verified and all canonical publication/directory syncs succeeded.
commit_marker() {
  local committed_hash=$1
  printf 'status=committed\noperation=%s\nsha256=%s\n' "$action" "$committed_hash" > "$stage/COMMITTED"
  chmod 0600 "$stage/COMMITTED"
  sync_paths "$stage/COMMITTED" "$stage" "$bin_dir" "$record_dir" || fail 'cannot durably publish committed transaction marker'
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage=$(mktemp -d "$bin_dir/.stl-install.XXXXXXXX")

if [[ $action == uninstall ]]; then
  cp -p -- "$target" "$stage/previous-stl"
  cp -p -- "$record" "$stage/previous-record"
  [[ $(hash_file "$target") == "$prior_hash" && $(hash_file "$record") == "$prior_record_hash" ]] || fail 'installed identity changed before uninstall'
  sync_paths "$stage/previous-stl" "$stage/previous-record" "$stage" "$bin_dir" || fail 'cannot durably preserve uninstall rollback source'
  failpoint prepublish-sync
  rm -- "$alias"
  sync_paths "$bin_dir" || fail 'cannot durably retire alias'
  mv -T -- "$target" "$stage/removed-stl"
  sync_paths "$bin_dir" "$stage" || fail 'cannot durably retire canonical executable'
  rm -- "$record"
  if [[ $prefix != /usr/local && ${STL_INSTALL_TEST_FAIL_AFTER_UNINSTALL_REMOVE:-} == 1 ]]; then
    fail 'injected uninstall failure (isolated test only)'
  fi
  sync_paths "$record_dir" || fail 'cannot durably retire ownership record'
  failpoint record-sync
  [[ ! -e $target && ! -L $target && ! -e $alias && ! -L $alias && ! -e $record && ! -L $record ]] || fail 'uninstall identities not fully retired'
  commit_marker "$prior_hash"
  printf 'Uninstalled installer-owned stl/stlink only; Link state was left untouched.\n'

fi

arch=$(uname -m)
case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) fail "unsupported architecture: $arch" ;; esac
if [[ -n $bundle ]]; then
  [[ -d $bundle && ! -L $bundle ]] || fail 'bundle must be a directory, not a symlink'
  bundle=$(realpath -e -- "$bundle")
  is_regular "$bundle/BUILD-MANIFEST.txt" || fail 'bundle manifest missing or unsafe'
  version=$(sed -n 's/^version=//p' "$bundle/BUILD-MANIFEST.txt")
  [[ $version =~ ^(v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?|dev-[0-9a-f]{12})$ ]] || fail 'invalid bundle version'
fi
asset="stl_${version}_linux_${arch}"
for file in SHA256SUMS BUILD-MANIFEST.txt LICENSE "$asset"; do
  if [[ -n $bundle ]]; then
    is_regular "$bundle/$file" || fail "bundle file missing or unsafe: $file"
    cp -- "$bundle/$file" "$stage/$file" || fail "cannot read bundle file: $file"
  else
    url="https://github.com/ach1992/simple-tun-link/releases/download/${version}/${file}"
    curl -fLSs --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 2 -o "$stage/$file" "$url" || fail "cannot download release file: $file"
  fi
done
for file in BUILD-MANIFEST.txt LICENSE "$asset"; do
  expected=$(awk -v name="$file" '$2 == name {print $1}' "$stage/SHA256SUMS")
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || fail "missing/duplicate or malformed SHA256 entry for $file"
  [[ $(hash_file "$stage/$file") == "$expected" ]] || fail "checksum mismatch for $file"
done
manifest="$stage/BUILD-MANIFEST.txt"
grep -qx 'project=simple-tun-link' "$manifest" && grep -qx 'executable=stl' "$manifest" && grep -qx 'license=MIT' "$manifest" && grep -qx "version=$version" "$manifest" || fail 'release manifest does not describe the intended STL build'
if [[ -z $bundle ]]; then grep -qx 'mode=tag' "$manifest" || fail 'remote release must be built from a tag'; fi
commit=$(sed -n 's/^commit=//p' "$manifest")
[[ $commit =~ ^[0-9a-f]{40}$ ]] || fail 'invalid release commit metadata'
[[ $(head -n 1 "$stage/LICENSE") == 'MIT License' ]] || fail 'release LICENSE is not MIT'
install -m 0755 -- "$stage/$asset" "$stage/incoming"
metadata=$("$stage/incoming" version --json) || fail 'downloaded binary cannot report version metadata'
[[ $metadata == *\"version\":\"$version\"* && $metadata == *\"commit\":\"$commit\"* ]] || fail 'release executable and manifest identity disagree'
new_hash=$(hash_file "$stage/incoming")
record_tmp=$(mktemp "$record_dir/.install-record.XXXXXXXX")
printf 'format=1\nproject=simple-tun-link\nversion=%s\nsha256=%s\n' "$version" "$new_hash" > "$record_tmp"
chmod 0600 "$record_tmp"
new_record_hash=$(hash_file "$record_tmp")

if [[ $action == update ]]; then
  cp -p -- "$target" "$stage/previous-stl"
  cp -p -- "$record" "$stage/previous-record"
  [[ $(hash_file "$target") == "$prior_hash" ]] || fail 'installed binary changed before update'
  if [[ $prior_hash == "$new_hash" ]]; then
    printf 'stl is already installed from this exact artifact (%s).\n' "$version"
    exit 0
  fi
fi
# Incoming and canonical executable are in the same directory/filesystem.
# mv -T is an atomic rename: the old executable is never truncated in place.
mv -T -- "$stage/incoming" "$target"
if [[ -n $bundle && $prefix != /usr/local && ${STL_INSTALL_TEST_FAIL_AFTER_SWAP:-} == 1 ]]; then
  fail 'injected after-swap failure (offline isolated test only)'
fi
if [[ $action == update && -n $bundle && $prefix != /usr/local && ${STL_INSTALL_TEST_CORRUPT_BACKUP:-} == 1 ]]; then
  printf 'damaged\n' >> "$stage/previous-stl"
  fail 'injected damaged recovery source (offline isolated test only)'
fi
sync -f "$target" "$bin_dir" || fail 'binary publication sync failed'
if [[ $action == install ]]; then
  ln -s stl "$alias"
fi
if [[ $action == update ]]; then
  [[ $(hash_file "$record") == "$prior_record_hash" ]] || fail 'install record changed during binary update; reconciliation required'
else
  [[ ! -e $record && ! -L $record ]] || fail 'install record appeared during installation; refusing overwrite'
fi
mv -T -- "$record_tmp" "$record"
[[ $(hash_file "$record") == "$new_record_hash" && $(hash_file "$target") == "$new_hash" && -L $alias && $(readlink -- "$alias") == stl ]] || fail 'post-publication identity check failed'
sync -f "$record" "$record_dir" || fail 'installation metadata sync failed'
printf '%s stl %s for linux/%s; stlink resolves to the same executable.\n' "${action^}" "$version" "$arch"
