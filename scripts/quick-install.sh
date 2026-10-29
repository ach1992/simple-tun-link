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
    echo "Usage: STL bootstrap [optional-exact-stable-tag] [native|native,wireguard] [update]" >&2
    exit 2
  }
  [[ $# -ge 1 && $# -le 4 ]] || usage
  version=$1
  bootstrap_version=$version
  shift
  # The immutable Latest Stable bootstrap pins the default tag. One optional
  # explicit published Stable tag follows the same short public command;
  # never interpolate a path, branch, arbitrary tag or user shell code.
  if [[ $# -gt 0 && $1 =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    version=$1
    shift
  fi
  backends=native,wireguard
  action=install
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ && $# -le 2 ]] || usage
  if [[ $# -ge 1 ]]; then
    case "$1" in
      native|native,wireguard) backends=$1 ;;
      update) action=update ;;
      *) usage ;;
    esac
  fi
  if [[ $# -eq 2 ]]; then
    [[ $action == install && $2 == update ]] || usage
    action=update
  fi
  workdir=$(mktemp -d)
  trap 'rm -rf -- "$workdir"' EXIT
  # The bootstrap's pinned immutable Stable supplies the ONLY executable
  # installer. User-selected historical tags are never shell-source paths.
  # Admit them as data only after GitHub confirms an exact complete immutable
  # published Stable release; no privileged process can start on failure.
  if [[ $version != "$bootstrap_version" ]]; then
    command -v python3 >/dev/null 2>&1 || {
      echo '[FAILED] Exact historical Stable selection requires Python 3 for verified release metadata; no installer started.' >&2
      return 1
    }
    release_json="$workdir/release.json"
    release_status=
    release_url="https://api.github.com/repos/ach1992/simple-tun-link/releases/tags/$version"
    if ! release_status=$(curl -fsSs --proto "=https" --proto-redir "=https" --max-redirs 0 --tlsv1.2 --connect-timeout 10 --max-time 25 -H 'Accept: application/vnd.github+json' -H 'User-Agent: simple-tun-link-operator' -w '%{http_code}' -o "$release_json" "$release_url" 2>/dev/null) ||
       [[ $release_status != 200 ]] ||
       ! python3 -I - "$release_json" "$version" <<'STL_RELEASE_JSON'
import datetime
import json
import os
import re
import sys

path, tag = sys.argv[1:]
try:
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("invalid tag")
    if os.stat(path).st_size > 262144:
        raise ValueError("release metadata too large")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON property")
            result[key] = value
        return result
    with open(path, "r", encoding="utf-8") as stream:
        release = json.load(stream, object_pairs_hook=unique_pairs)
    if not isinstance(release, dict) or type(release.get("id")) is not int or release["id"] <= 0:
        raise ValueError("release identity unavailable")
    if (release.get("tag_name") != tag or release.get("immutable") is not True or
        release.get("draft") is not False or release.get("prerelease") is not False):
        raise ValueError("release not exact published immutable Stable")
    published = release.get("published_at")
    if not isinstance(published, str) or not published.endswith("Z"):
        raise ValueError("release publication missing")
    datetime.datetime.fromisoformat(published.replace("Z", "+00:00"))
    assets = release.get("assets")
    if not isinstance(assets, list) or not (5 <= len(assets) <= 100):
        raise ValueError("release asset catalogue incomplete")
    approved = set()
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise ValueError("invalid release asset")
        name = asset["name"]
        if name in approved:
            raise ValueError("duplicate release asset")
        if asset.get("state") == "uploaded" and type(asset.get("size")) is int and asset["size"] > 0:
            approved.add(name)
    required = {"stl_" + tag + "_linux_amd64", "stl_" + tag + "_linux_arm64",
                "BUILD-MANIFEST.txt", "SHA256SUMS", "LICENSE"}
    if not required.issubset(approved):
        raise ValueError("release missing verified required assets")
except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
    sys.exit(1)
STL_RELEASE_JSON
    then
      rm -f -- "$release_json"
      echo '[FAILED] Selected tag is not a verified complete immutable published Stable, or the official release API is unavailable. No installer started.' >&2
      return 1
    fi
    rm -f -- "$release_json"
  fi
  # Download the trusted current immutable canonical installer completely,
  # and syntax-check it BEFORE any sudo/root execution.
  source_url="https://raw.githubusercontent.com/ach1992/simple-tun-link/$bootstrap_version/scripts/install.sh"
  tmp="$workdir/install.sh"
  if ! curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 150 -o "$tmp" "$source_url" >/dev/null 2>&1; then
    echo '[FAILED] STL installer download failed before execution. Check HTTPS/DNS reachability of raw.githubusercontent.com and the exact official release; no installer started.' >&2
    return 1
  fi
  [[ -s $tmp ]] || { echo '[FAILED] STL installer download is empty; no installer started. Verify the official release and retry the download.' >&2; return 1; }
  if ! bash -n "$tmp" >/dev/null 2>&1; then
    echo '[FAILED] STL installer syntax validation failed; no installer started. Verify the tagged release and its installer before retrying.' >&2
    return 1
  fi
  # Even an authenticated installer can invoke APT and hooks with private
  # repository URLs. Do not expose raw stdout/stderr, and do not buffer an
  # unbounded transaction log in memory or a temporary file.
  quick_install_safe_output() {
    local line announced_wait=0 announced_packages=0 announced_failure=0
    while IFS= read -r -n 1024 line || [[ -n $line ]]; do
      case "$line" in
        'stl installer [FAILED]: legacy_binary_bridge_required:'*)
          echo '[ACTION] This installed Stable cannot directly downgrade. First UPDATE it to the next official Stable using the permanent one-line installer without an old tag; then select the older official version in its installed Update menu.' ;;
        'stl installer [INFO]: Another APT process holds the lists lock'*)
          if (( ! announced_wait )); then
            echo '[INFO] STL is waiting for a known temporary APT lists lock to clear.'
            announced_wait=1
          fi ;;
        '[INFO] Installing verified missing packages on '*)
          if (( ! announced_packages )); then
            echo '[INFO] STL is installing only the verified selected dependencies.'
            announced_packages=1
          fi ;;
        'stl installer [FAILED]: partial failure; inspect retained recovery directory:'*)
          echo '[WARNING] Canonical installer reported uncertain recovery. Inspect retained private recovery evidence before retrying.' ;;
        'stl installer [FAILED]:'*)
          if (( ! announced_failure )); then
            echo '[WARNING] Canonical installer reported a failure. No automatic retry will occur.'
            announced_failure=1
          fi ;;
      esac
    done
  }
  local install_status=0
  echo "[INFO] Running STL $action for $version. Raw package diagnostics are withheld; this can take several minutes."
  if (
    if (( EUID == 0 )); then
      bash "$tmp" "$action" --version "$version" --backends "$backends"
    else
      sudo bash "$tmp" "$action" --version "$version" --backends "$backends"
    fi
  ) 2>&1 | quick_install_safe_output; then
    install_status=0
  else
    # pipefail preserves the canonical installer's exit status if the
    # read-only sanitizer completes. Filter failure also fails closed.
    install_status=$?
  fi
  if (( install_status != 0 )); then
    printf '[FAILED] STL %s %s did not complete (exit %d). Review the reported stage (if any); inspect dpkg --audit, STL install-record and any retained recovery before retrying. A partial APT or binary transaction may persist.\n' "$version" "$action" "$install_status" >&2
    return "$install_status"
  fi
  echo "[OK] STL $version $action completed. Opening the menu on this terminal..."
  # When a bootstrap script is piped into bash, fd 0 is the script content,
  # not interactive menu input. Reattach to the controlling terminal only.
  if [[ -t 1 ]] && { exec {stl_menu_tty}<>/dev/tty; } 2>/dev/null; then
    rm -f -- "$tmp"
    rmdir -- "$workdir"
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
