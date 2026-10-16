#!/usr/bin/env bash
# Render one immutable, tag-pinned Stable bootstrap asset for GitHub's
# permanent releases/latest/download/stl-bootstrap.sh entrypoint.
# Does not install packages or modify the machine.
set -Eeuo pipefail
umask 077

if [[ $# -ne 2 ]]; then
  echo 'Usage: render-stable-bootstrap.sh <stable-tag> <new-output-file>' >&2
  exit 2
fi
tag=$1
output=$2
[[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo 'Only a stable semantic version can supply the latest Stable bootstrap' >&2
  exit 2
}
[[ -n $output && $output != / && $output != . &&
  ! -e $output && ! -L $output ]] || {
  echo 'Output must be a new regular file path' >&2
  exit 2
}
parent=$(dirname -- "$output")
[[ -d $parent && ! -L $parent ]] || {
  echo 'Output parent must exist and not be a symlink' >&2
  exit 2
}
root="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
source_file="$root/scripts/quick-install.sh"
[[ -f $source_file && ! -L $source_file ]] || exit 1
[[ $(grep -Fxc 'quick_install_main "$@"' "$source_file") -eq 1 &&
  $(tail -n 1 "$source_file") == 'quick_install_main "$@"' ]] || {
  echo 'Quick-install entrypoint changed; release template must be reviewed' >&2
  exit 1
}
tmp=$(mktemp "$parent/.stl-bootstrap.XXXXXXXX")
trap 'rm -f -- "$tmp"' EXIT
# Only the final invocation changes: all HTTPS, privilege, truncated
# stream, root/TTY and canonical-installer boundaries are preserved.
sed '$d' "$source_file" > "$tmp"
printf 'quick_install_main "%s" "$@"\n' "$tag" >> "$tmp"
bash -n "$tmp"
[[ $(grep -Fc 'quick_install_main "' "$tmp") -eq 1 ]] || {
  echo 'Generated bootstrap contains unexpected entrypoints' >&2
  exit 1
}
mv -T -n -- "$tmp" "$output"
[[ -f $output && ! -e $tmp ]] || exit 1
trap - EXIT
