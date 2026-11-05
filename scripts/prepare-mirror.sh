#!/usr/bin/env bash
# Prepare a static, tag-pinned HTTPS STL mirror from independently verified
# official release assets on an Internet-connected, trusted machine.
# This never installs anything and never fetches GitHub on target hosts.
set -Eeuo pipefail
umask 077

usage() {
  echo 'Usage: prepare-mirror.sh --tag vX.Y.Z --release-dir /trusted/official-assets --trusted-sums-sha256 64_LOWERCASE_HEX --url https://stl.example.com --output /new/wwwroot-dir' >&2
  exit 2
}
[[ $# == 10 ]] || usage
tag= source_dir= trusted_sums= mirror_url= output=
while (( $# )); do
  case "$1" in
    --tag) [[ -z $tag ]] || usage; tag=$2 ;;
    --release-dir) [[ -z $source_dir ]] || usage; source_dir=$2 ;;
    --trusted-sums-sha256) [[ -z $trusted_sums ]] || usage; trusted_sums=$2 ;;
    --url) [[ -z $mirror_url ]] || usage; mirror_url=$2 ;;
    --output) [[ -z $output ]] || usage; output=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ &&
   $trusted_sums =~ ^[0-9a-f]{64}$ &&
   $mirror_url =~ ^https://[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$ &&
   $mirror_url != *..* ]] || usage
[[ $source_dir == /* && -d $source_dir && ! -L $source_dir &&
   $(realpath -e "$source_dir") == "$source_dir" ]] || usage
[[ $output != / && $output != . && -n $output && ! -e $output && ! -L $output ]] || usage
parent=$(dirname -- "$output")
[[ -d $parent && ! -L $parent && $(realpath -e "$parent") == "$parent" &&
   $(stat -c %u -- "$parent") == "$EUID" ]] || usage
parent_mode=$(stat -c %a -- "$parent")
[[ $parent_mode =~ ^[0-7]{3,4}$ ]] && (( (8#$parent_mode & 8#022) == 0 )) ||
  { echo 'Mirror output parent must be owner-controlled, not group/other writable.' >&2; exit 1; }
outdir="$parent/$(basename -- "$output")"
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
mirror_source="$script_dir/quick-install.sh"
[[ -f $mirror_source && ! -L $mirror_source &&
   $(tail -n 1 "$mirror_source") == 'quick_install_main "${1:-}" "" "" "" "${@:2}"' ]] ||
  { echo 'Mirror bootstrap source contract changed; inspect before preparing an upload.' >&2; exit 1; }
regular() { [[ -f $1 && ! -L $1 && -s $1 ]]; }
expected() {
  local name=$1 actual
  # Exactly one checksum line, no ambiguous aliases or paths.
  actual=$(awk -v n="$name" '$2 == n { print $1 }' "$source_dir/SHA256SUMS")
  [[ $actual =~ ^[0-9a-f]{64}$ ]] || { echo "Missing/duplicate official checksum for $name" >&2; exit 1; }
  printf '%s' "$actual"
}
regular "$source_dir/SHA256SUMS" || { echo 'Official release SHA256SUMS missing.' >&2; exit 1; }
[[ $(sha256sum "$source_dir/SHA256SUMS" | awk '{print $1}') == "$trusted_sums" ]] ||
  { echo 'Release checksum manifest differs from independently trusted digest; nothing prepared.' >&2; exit 1; }
files=(BUILD-MANIFEST.txt LICENSE stl-bootstrap.sh
       "stl_${tag}_linux_amd64" "stl_${tag}_linux_arm64"
       "stl_${tag}_linux_amd64_local-install.tar.gz"
       "stl_${tag}_linux_arm64_local-install.tar.gz")
for file in "${files[@]}"; do
  regular "$source_dir/$file" || { echo "Official release asset missing or unsafe: $file" >&2; exit 1; }
  [[ $(sha256sum "$source_dir/$file" | awk '{print $1}') == "$(expected "$file")" ]] ||
    { echo "Official release checksum mismatch: $file" >&2; exit 1; }
done
grep -Fxq 'project=simple-tun-link' "$source_dir/BUILD-MANIFEST.txt" &&
  grep -Fxq "version=$tag" "$source_dir/BUILD-MANIFEST.txt" &&
  grep -Eq '^commit=[0-9a-f]{40}$' "$source_dir/BUILD-MANIFEST.txt" &&
  grep -Fxq 'mode=tag' "$source_dir/BUILD-MANIFEST.txt" &&
  grep -Fxq 'source=https://github.com/ach1992/simple-tun-link' "$source_dir/BUILD-MANIFEST.txt" ||
  { echo 'Official manifest version/commit identity invalid.' >&2; exit 1; }

stage=$(mktemp -d "$parent/.stl-mirror.XXXXXXXX")
cleanup() { [[ -d $stage && ! -L $stage ]] && rm -rf --one-file-system -- "$stage"; }
trap cleanup EXIT
mkdir -m 0700 -p -- "$stage/releases/$tag"
for file in "${files[@]}" SHA256SUMS; do
  install -m 0644 -- "$source_dir/$file" "$stage/releases/$tag/$file"
done
# Canonical installer source is shipped inside each independently hashed
# architecture-specific official archive; both must be byte-identical.
for arch in amd64 arm64; do
  tar -xOzf "$source_dir/stl_${tag}_linux_${arch}_local-install.tar.gz" install.sh > "$stage/canonical-$arch.sh" ||
    { echo "Could not extract trusted $arch canonical installer" >&2; exit 1; }
  bash -n "$stage/canonical-$arch.sh" ||
    { echo "Canonical $arch installer failed shell syntax" >&2; exit 1; }
done
cmp -s "$stage/canonical-amd64.sh" "$stage/canonical-arm64.sh" ||
  { echo 'Release architectures contain different canonical installers.' >&2; exit 1; }
# The mirror bootstrap must be generated from the EXACT published and hashed
# Stable source, not from whichever future checkout happens to be active.
release_canonical_sha=$(sha256sum < "$stage/canonical-amd64.sh")
release_canonical_sha=${release_canonical_sha%% *}
[[ $(tail -n 1 "$source_dir/stl-bootstrap.sh") == "quick_install_main \"$tag\" \"\" \"$release_canonical_sha\" \"\" \"\$@\"" ]] &&
  cmp -s <(sed '$d' "$source_dir/stl-bootstrap.sh") <(sed '$d' "$mirror_source") &&
  cmp -s "$stage/canonical-amd64.sh" "$script_dir/install.sh" ||
  { echo 'Local release-preparation source differs from official hashed bootstrap/installer. Use the exact released source/tag.' >&2; exit 1; }
grep -q 'release-sums-sha256)' "$stage/canonical-amd64.sh" ||
  { echo 'This Stable does not support standalone HTTPS mirror installation; publish a newer reviewed release.' >&2; exit 1; }
install -m 0644 "$stage/canonical-amd64.sh" "$stage/releases/$tag/install.sh"
installer_sha=$(sha256sum "$stage/releases/$tag/install.sh" | awk '{print $1}')
[[ $installer_sha == "$release_canonical_sha" ]] || {
  echo 'Verified canonical installer changed while staging the mirror.' >&2
  exit 1
}
# Inject only validated, source-pinned constants into the final invocation.
# The full bootstrap stays byte-for-byte based on canonical quick-install.sh.
sed '$d' "$mirror_source" > "$stage/install.sh"
printf "quick_install_main '%s' '%s/releases/%s' '%s' '%s' \"\$@\"\n" \
  "$tag" "$mirror_url" "$tag" "$installer_sha" "$trusted_sums" >> "$stage/install.sh"
bash -n "$stage/install.sh"
chmod 0644 "$stage/install.sh"
[[ $(tail -n 1 "$stage/install.sh") == quick_install_main* &&
   $(grep -c '^quick_install_main ' "$stage/install.sh") == 1 ]] ||
  { echo 'Mirror bootstrap final invocation failed verification.' >&2; exit 1; }
# Pin the final validated PRIVATE bootstrap, never the published path.
first_hop_sha=$(sha256sum < "$stage/install.sh")
first_hop_sha=${first_hop_sha%% *}
rm -f -- "$stage/canonical-amd64.sh" "$stage/canonical-arm64.sh"
chmod 0755 "$stage" "$stage/releases" "$stage/releases/$tag"
[[ ! -e $outdir && ! -L $outdir ]] || { echo 'Output appeared concurrently; no overwrite.' >&2; exit 1; }
mv -T -n -- "$stage" "$outdir"
[[ ! -e $stage && -d $outdir && ! -L $outdir ]] ||
  { echo 'Mirror output raced with another publisher; not reporting success.' >&2; exit 1; }
trap - EXIT
printf 'MIRROR_PREPARED=PASS\nTAG=%s\nMIRROR_URL=%s\nUPLOAD_ROOT=%s\n' "$tag" "$mirror_url" "$outdir"
# The operator copies this command from the trusted preparation machine,
# NOT the mirror. Pin the first downloaded shell against independently
# prepared bytes before executing any of its content, even as non-root.
operator_command=$(cat <<'STL_OPERATOR_COMMAND'
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fsSs --proto "=https" --max-redirs 0 --connect-timeout 10 --max-time 45 MIRROR_INSTALL_URL | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && { [ "$(/usr/bin/sha256sum < "$f")" = "TRUSTED_BOOTSTRAP_SHA256  -" ] || { echo "STL: mirror bootstrap SHA256 mismatch" >&2; exit 1; }; } && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl
STL_OPERATOR_COMMAND
)
mirror_install="$mirror_url/install.sh"
operator_command=${operator_command/MIRROR_INSTALL_URL/$mirror_install}
operator_command=${operator_command/TRUSTED_BOOTSTRAP_SHA256/$first_hop_sha}
printf 'BOOTSTRAP_SHA256=%s\nINSTALL_COMMAND=%s\nUPDATE_COMMAND=%s update\n' "$first_hop_sha" "$operator_command" "$operator_command"
