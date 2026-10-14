#!/usr/bin/env bash
# Complete, tag-pinned bootstrap that defers all install effects until the
# entire function body and final invocation have arrived. This also prevents
# an abruptly interrupted curl-to-bash stream from running half a wrapper.
set -Eeuo pipefail
STL_BOOTSTRAP_STARTED=0
bootstrap_incomplete_guard() {
  if [[ $STL_BOOTSTRAP_STARTED != 1 ]]; then
    echo 'STL quick installer was not received completely; nothing installed.' >&2
    exit 2
  fi
}
trap bootstrap_incomplete_guard EXIT

quick_install_main() {
  STL_BOOTSTRAP_STARTED=1
  umask 077
  usage() {
    echo "Usage: bash quick-install.sh <existing-published-tag> [native|native,wireguard]" >&2
    exit 2
  }
  [[ $# == 1 || $# == 2 ]] || usage
  version=$1
  backends=native,wireguard
  if [[ $# == 2 ]]; then backends=$2; fi
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || usage
  case "$backends" in
    native|native,wireguard) ;;
    *) usage ;;
  esac
  # Do not trust a mutable latest endpoint. Download the canonical installer
  # for the exact tag, check it is complete and parses before privilege elevation.
  source_url="https://raw.githubusercontent.com/ach1992/simple-tun-link/$version/scripts/install.sh"
  tmp=$(mktemp)
  trap 'rm -f -- "$tmp"' EXIT
  curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 -o "$tmp" "$source_url"
  [[ -s $tmp ]] || { echo "STL installer was not downloaded." >&2; exit 1; }
  bash -n "$tmp"
  if (( EUID == 0 )); then
    bash "$tmp" install --version "$version" --backends "$backends"
  else
    sudo bash "$tmp" install --version "$version" --backends "$backends"
  fi
  echo "STL $version installed. Opening the menu on this terminal..."
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
  echo "No interactive terminal detected. Start it later with: sudo stl menu"
}
quick_install_main "$@"
