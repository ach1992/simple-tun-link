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
  # Distribution trust comes ONLY from the exact reviewed final invocation.
  # Never accept STL_MIRROR_* inherited environment variables as origin pins.
  [[ $# -ge 4 && $# -le 7 ]] || usage
  local bootstrap_version=$1 mirror_url=$2 pinned_install_sha=$3 mirror_sums_sha=$4
  shift 4
  version=$bootstrap_version
  if [[ -n $mirror_url ]]; then
    [[ $bootstrap_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ &&
       $mirror_url =~ ^https://[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?/releases/v[0-9]+\.[0-9]+\.[0-9]+$ &&
       $mirror_url == */releases/$bootstrap_version && $mirror_url != *..* &&
       $pinned_install_sha =~ ^[0-9a-f]{64}$ &&
       $mirror_sums_sha =~ ^[0-9a-f]{64}$ ]] || {
      echo '[FAILED] Invalid pinned mirror metadata; no installer started.' >&2
      return 2
    }
  else
    [[ -z $mirror_sums_sha && ( -z $pinned_install_sha || $pinned_install_sha =~ ^[0-9a-f]{64}$ ) ]] || usage
  fi
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
  # A self-hosted mirror is pinned to one Stable version. Historical release
  # selection would need a separately prepared version-specific mirror asset;
  # never fall back to GitHub API when the target is isolated.
  if [[ $mirror_url != '' && $version != "$bootstrap_version" ]]; then
    echo '[FAILED] This mirror bootstrap serves only its pinned Stable. Publish the desired exact-version mirror bootstrap; no GitHub fallback.' >&2
    return 1
  fi
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
  tmp="$workdir/install.sh"
  # The local-release archive already limits the canonical install.sh to
  # 1 MiB. Apply the SAME bound while receiving bytes, not after curl has
  # filled a live host's temporary storage. --max-filesize helps reject
  # known Content-Length early; head enforces the hard streaming cap also
  # on old Debian/Ubuntu curl versions and chunked/unknown-length responses.
  # pipefail makes a truncated response or a broken curl fail closed.
  local canonical_limit=1048576 canonical_rc=0 canonical_bytes
  if [[ -n $mirror_url ]]; then
    source_url="$mirror_url/install.sh"
    curl -fsSs --proto "=https" --proto-redir "=https" --max-redirs 0 --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 150 --max-filesize "$canonical_limit" "$source_url" 2>/dev/null |
      head -c "$((canonical_limit + 1))" > "$tmp" || canonical_rc=$?
  else
    source_url="https://raw.githubusercontent.com/ach1992/simple-tun-link/$bootstrap_version/scripts/install.sh"
    curl -fLSs --proto "=https" --proto-redir "=https" --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 150 --max-filesize "$canonical_limit" "$source_url" 2>/dev/null |
      head -c "$((canonical_limit + 1))" > "$tmp" || canonical_rc=$?
  fi
  canonical_bytes=$(wc -c < "$tmp")
  if (( canonical_bytes > canonical_limit )); then
    echo '[FAILED] Canonical installer exceeds the 1 MiB streaming limit; no installer started. Check the trusted release or HTTPS mirror.' >&2
    return 1
  fi
  if (( canonical_rc != 0 )); then
    if [[ -n $mirror_url ]]; then
      echo '[FAILED] Mirror canonical installer unavailable, incomplete or oversized. Check HTTPS and the verified mirror files; no GitHub fallback or installer started.' >&2
    else
      echo '[FAILED] STL installer download failed before execution. Check HTTPS/DNS reachability of raw.githubusercontent.com and the exact official release; no installer started.' >&2
    fi
    return 1
  fi
  [[ -s $tmp ]] || { echo '[FAILED] STL installer download is empty; no installer started. Verify the official release and retry the download.' >&2; return 1; }
  # A rendered immutable Stable bootstrap carries the exact reviewed
  # canonical installer's SHA256; the Mirror carries that same source pin
  # alongside its independently authenticated release checksum manifest.
  if [[ -n $pinned_install_sha ]]; then
    # Use the system binary, not an exported shell function from the
    # operator's environment, to establish the pre-privilege digest.
    [[ $(/usr/bin/sha256sum < "$tmp") == "$pinned_install_sha  -" ]] || {
      if [[ -n $mirror_url ]]; then
        echo '[FAILED] Mirror canonical installer differs from the independently pinned SHA256; no installer started.' >&2
      else
        echo '[FAILED] Official canonical installer differs from the immutable Stable bootstrap SHA256 pin; no installer started.' >&2
      fi
      return 1
    }
  fi
  if ! bash -n "$tmp" >/dev/null 2>&1; then
    echo '[FAILED] STL installer syntax validation failed; no installer started. Verify the tagged release and its installer before retrying.' >&2
    return 1
  fi
  # Preserve the pre-privilege digest across sudo authentication. The
  # user-owned download is NEVER executed as root: sudo copies at most 1 MiB+1
  # into a fresh root-owned 0700 directory, hashes that private copy against
  # this digest, and runs ONLY the authenticated root-private file.
  local privileged_digest=$pinned_install_sha
  if [[ -z $privileged_digest ]]; then
    # Maintainer-direct bootstrap without a rendered release pin still binds
    # the bytes seen before sudo to the bytes executed by root. It does not
    # independently authenticate the publisher; rendered Stable/Mirror do.
    privileged_digest=$(/usr/bin/sha256sum < "$tmp")
    privileged_digest=${privileged_digest%% *}
  fi
  [[ $privileged_digest =~ ^[0-9a-f]{64}$ ]] || {
    echo '[FAILED] Canonical source digest is missing or invalid; no installer started.' >&2
    return 1
  }
  local privileged_stage
  privileged_stage=$(cat <<'STL_ROOT_SNAPSHOT'
set -Eeuo pipefail
umask 077
source=$1
expected=$2
shift 2
[[ $source == /* && -f $source && ! -L $source && $expected =~ ^[0-9a-f]{64}$ ]] || {
  echo 'STL_ROOT_SNAPSHOT_INVALID' >&2
  exit 71
}
stage=$(/usr/bin/mktemp -d /root/.stl-quick-bootstrap.XXXXXXXX) || {
  echo 'STL_ROOT_SNAPSHOT_UNAVAILABLE' >&2
  exit 72
}
cleanup() { [[ -d $stage && ! -L $stage ]] && /bin/rm -rf --one-file-system -- "$stage"; }
trap cleanup EXIT
/usr/bin/head -c 1048577 -- "$source" > "$stage/install.sh" || {
  echo 'STL_ROOT_SNAPSHOT_COPY_FAILED' >&2
  exit 73
}
bytes=$(/usr/bin/wc -c < "$stage/install.sh")
(( bytes > 0 && bytes <= 1048576 )) || {
  echo 'STL_ROOT_SNAPSHOT_SIZE_INVALID' >&2
  exit 74
}
[[ $(/usr/bin/sha256sum < "$stage/install.sh") == "$expected  -" ]] || {
  echo 'STL_ROOT_SNAPSHOT_SHA256_MISMATCH' >&2
  exit 75
}
/bin/bash "$stage/install.sh" "$@"
STL_ROOT_SNAPSHOT
)
  # Explicitly admitted transport overrides are the only environment data
  # forwarded to the privileged subprocess; never use sudo -E. Root Bash
  # starts under env -i, so BASH_ENV and exported functions cannot cross.
  local -a root_exec=(
    /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin
    HTTPS_PROXY="${HTTPS_PROXY-}" NO_PROXY="${NO_PROXY-}"
    CURL_CA_BUNDLE="${CURL_CA_BUNDLE-}"
    /bin/bash -c "$privileged_stage" stl "$tmp" "$privileged_digest"
  )
  # Even an authenticated installer can invoke APT and hooks with private
  # repository URLs. Do not expose raw stdout/stderr, and do not buffer an
  # unbounded transaction log in memory or a temporary file.
  quick_install_safe_output() {
    local line announced_wait=0 announced_packages=0 announced_failure=0
    while IFS= read -r -n 1024 line || [[ -n $line ]]; do
      case "$line" in
        'STL_ROOT_SNAPSHOT_SHA256_MISMATCH')
          echo '[FAILED] Privileged private snapshot SHA256 mismatch after sudo. The transferred source changed; no installer code was executed as root.' ;;
        'STL_ROOT_SNAPSHOT_INVALID'|'STL_ROOT_SNAPSHOT_UNAVAILABLE'|\
        'STL_ROOT_SNAPSHOT_COPY_FAILED'|'STL_ROOT_SNAPSHOT_SIZE_INVALID')
          echo '[FAILED] Privileged installer snapshot could not be safely authenticated; no installer code was executed as root.' ;;
        'stl installer [FAILED]: installed_version_mismatch: prior='*)
          local remainder prior
          remainder=${line#'stl installer [FAILED]: installed_version_mismatch: prior='}
          prior=${remainder%% *}
          if [[ $prior =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ &&
                $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ &&
                $prior != "$version" &&
                $line == "stl installer [FAILED]: installed_version_mismatch: prior=$prior target=$version; install cannot replace a different installer-owned release; use an explicit update" ]]; then
            if [[ -n $mirror_url ]]; then
              printf '[ACTION] STL %s is already installed. install will not replace it with %s. Rerun this same verified HTTPS mirror command with update as the final argument; the built-in Update menu requires GitHub. No automatic upgrade was performed.\n' "$prior" "$version"
            else
              printf '[ACTION] STL %s is already installed. install will not replace it with %s. Run sudo stl menu -> Update, or rerun the same trusted bootstrap with update as its final argument. No automatic upgrade was performed.\n' "$prior" "$version"
            fi
          else
            echo '[WARNING] STL install cannot safely replace the existing artifact. Inspect ownership and the installed version; do not force an update.'
          fi ;;
        'stl installer [FAILED]: mirror_checksum_mismatch:'*)
          echo '[FAILED] The mirror SHA256SUMS does not match this bootstrap release pin. Check uploads and independent release hashes; no binary published.' ;;
        'stl installer [FAILED]: mirror_download_oversized:'*)
          echo '[FAILED] Mirror release asset exceeds the authenticated streaming-size limit. Inspect the mirror and use independently trusted release files; no binary published.' ;;
        'stl installer [FAILED]: checksum mismatch for '*)
          echo '[FAILED] Release asset SHA256 mismatch. Recheck the independently trusted release and transferred files; no binary published.' ;;
        'stl installer [FAILED]: mirror_download_failed:'*)
          echo '[FAILED] Required release file is unavailable on the HTTPS mirror. Upload the complete verified version directory; no GitHub fallback.' ;;
        'stl installer [FAILED]: APT_INDEX_REFRESH failed;'*)
          echo '[ACTION] APT could not refresh signed package indexes. Check the configured reachable domestic/signed distro mirror and dpkg --audit; no package install was started by this attempt.' ;;
        'stl installer [FAILED]: APT_DEPENDENCY_PLAN failed;'*)
          echo '[ACTION] APT cannot resolve the selected verified packages. Check authenticated repository configuration and package availability; no packages changed.' ;;
        'stl installer [FAILED]: APT_PACKAGE_INSTALL failed;'*)
          echo '[WARNING] APT package installation failed or is partially applied. Inspect dpkg --audit, active APT tasks and retained recovery before trying again; no automatic retry.' ;;
        'stl installer [FAILED]: no STL installer-owned installation found'*)
          echo '[ACTION] Update requires an existing verified STL installation. Check for foreign/partial STL files and recovery first; use fresh install only on a confirmed clean host.' ;;
        'stl installer [FAILED]: STL ownership record is missing or not regular'*|\
        'stl installer [FAILED]: invalid ownership record'*|\
        'stl installer [FAILED]: installed stl differs from recorded owned binary'*|\
        'stl installer [FAILED]: unreconciled STL installer recovery directory exists'*)
          echo '[WARNING] STL ownership or retained recovery is unverified. Inspect the existing files/journal; do not overwrite, delete recovery, or force Update.' ;;
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
    arguments=("$action" --version "$version" --backends "$backends")
    [[ -z $mirror_url ]] || arguments+=(--release-base "$mirror_url" --release-sums-sha256 "$mirror_sums_sha")
    if (( EUID == 0 )); then
      "${root_exec[@]}" "${arguments[@]}"
    else
      /usr/bin/sudo "${root_exec[@]}" "${arguments[@]}"
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
# Direct source execution is official-only. Published official and self-hosted
# scripts replace ONLY this final invocation with constant, reviewed pins.
quick_install_main "${1:-}" "" "" "" "${@:2}"
