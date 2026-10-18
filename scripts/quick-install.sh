#!/usr/bin/env bash
# Complete, tag-pinned bootstrap that defers all install effects until the
# entire function body and final invocation have arrived. This also prevents
# an abruptly interrupted curl-to-bash stream from running half a wrapper.
set -Eeuo pipefail
STL_BOOTSTRAP_STARTED=0
bootstrap_incomplete_guard() {
  if [[ $STL_BOOTSTRAP_STARTED != 1 ]]; then
    echo '[FAILED] STL quick installer was not received completely; nothing installed.' >&2
    exit 2
  fi
}
trap bootstrap_incomplete_guard EXIT

quick_install_main() {
  STL_BOOTSTRAP_STARTED=1
  umask 077
  usage() {
    echo "Usage: bash quick-install.sh <existing-published-tag> [native|native,wireguard] [update]" >&2
    echo "For an already installer-owned STL: bash quick-install.sh <tag> update" >&2
    exit 2
  }
  [[ $# -ge 1 && $# -le 3 ]] || usage
  version=$1
  backends=native,wireguard
  action=install
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || usage
  if [[ $# -ge 2 ]]; then
    case "$2" in
      native|native,wireguard) backends=$2 ;;
      update) action=update ;;
      *) usage ;;
    esac
  fi
  if [[ $# == 3 ]]; then
    [[ $action == install && $3 == update ]] || usage
    action=update
  fi
  # Do not trust a mutable latest endpoint. Download the canonical installer
  # for the exact tag, check it is complete and parses before privilege elevation.
  source_url="https://raw.githubusercontent.com/ach1992/simple-tun-link/$version/scripts/install.sh"
  tmp=$(mktemp)
  trap 'rm -f -- "$tmp"' EXIT
  if ! curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 150 -o "$tmp" "$source_url"; then
    echo '[FAILED] STL installer download failed before execution. Check HTTPS/DNS reachability of raw.githubusercontent.com and the exact official release; no installer started.' >&2
    return 1
  fi
  [[ -s $tmp ]] || { echo '[FAILED] STL installer download is empty; no installer started. Verify the official release and retry the download.' >&2; return 1; }
  if ! bash -n "$tmp"; then
    echo '[FAILED] STL installer syntax validation failed; no installer started. Verify the tagged release and its installer before retrying.' >&2
    return 1
  fi
  local install_status=0
  if (( EUID == 0 )); then
    bash "$tmp" "$action" --version "$version" --backends "$backends" || install_status=$?
  else
    sudo bash "$tmp" "$action" --version "$version" --backends "$backends" || install_status=$?
  fi
  if (( install_status != 0 )); then
    printf '[FAILED] STL %s %s did not complete (exit %d). Read the preceding installer stage/error; inspect dpkg --audit, STL install-record and any retained recovery before retrying. A partial APT or binary transaction may persist.\n' "$version" "$action" "$install_status" >&2
    return "$install_status"
  fi
  echo "[OK] STL $version $action completed. Opening the menu on this terminal..."
  # When a bootstrap script is piped into bash, fd 0 is the script content,
  # not interactive menu input. Reattach to the controlling terminal only.
  if [[ -t 1 ]] && { exec {stl_menu_tty}<>/dev/tty; } 2>/dev/null; then
    rm -f -- "$tmp"
    trap - EXIT
    if (( EUID == 0 )); then
      exec stl menu <&"$stl_menu_tty" >&"$stl_menu_tty" 2>&1
    else
      exec sudo stl menu <&"$stl_menu_tty" >&"$stl_menu_tty" 2>&1
    fi
  fi
  echo "[INFO] No interactive terminal detected. Start it later with: sudo stl menu"
}
quick_install_main "$@"
