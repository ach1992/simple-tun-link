#!/usr/bin/env bash
# Offline regression of immutable Stable bootstrap and version-free first-hop.
# Host effects are simulated by fake curl/sudo in a private scratch dir.
# All fake tooling and side effects remain inside a disposable directory.
set -Eeuo pipefail
umask 077
repo="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
# Stable release bumps must keep the permanent first-hop install/update text.
mapfile -t published_commands < <(grep '^bash -c ' "$repo/README.md")
[[ ${#published_commands[@]} -eq 2 ]] || {
  echo 'README must contain precisely two fixed safe-download quick commands.' >&2
  exit 1
}
# Public commands must NEVER need a changing tag, branch or token.
# The immutable Stable asset itself pins the exact release tag.
stable_url='https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh'
# Source is complete only after curl exits 0. The script must not be
# interpreted in a pipe where a late curl error can follow root effects.
for idx in 0 1; do
  line="${published_commands[$idx]}"
  [[ "$line" == *'set -e; umask 077; d=$(mktemp -d);'* &&
     "$line" == *" -o \"\$d/stl-bootstrap.sh\" $stable_url; test -s \"\$d/stl-bootstrap.sh\"; bash -n \"\$d/stl-bootstrap.sh\"; bash \"\$d/stl-bootstrap.sh\""* &&
     "$line" != *' | bash'* ]] || {
    echo 'Public installer must download completely to a private file before any script execution.' >&2
    exit 1
  }
done
for public_cmd in "${published_commands[@]}"; do
  if [[ "$public_cmd" =~ v[0-9]+\.[0-9]+\.[0-9]+ ]] ||
     [[ "$public_cmd" == *raw.githubusercontent.com* ]]; then
    echo 'Public command must not contain versions or mutable main URLs.' >&2
    exit 1
  fi
done
export STL_TEST_PUBLIC_TAG=v0.1.0
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
bash "$repo/scripts/render-stable-bootstrap.sh" "$STL_TEST_PUBLIC_TAG" "$scratch/stl-bootstrap.sh"
export STL_TEST_STABLE_BOOTSTRAP="$scratch/stl-bootstrap.sh"
export STL_TEST_FIRST_HOP_PATHS="$scratch/first-hop-paths"
: > "$STL_TEST_FIRST_HOP_PATHS"
bash -n "$STL_TEST_STABLE_BOOTSTRAP"
# This nearly-complete asset remains parseable and includes the
# privileged call, despite missing the final newline. A failing curl
# MUST prevent its execution.
head -c -1 "$STL_TEST_STABLE_BOOTSTRAP" > "$scratch/almost-complete.sh"
bash -n "$scratch/almost-complete.sh"
grep -Fx 'quick_install_main "v0.1.0" "$@"' "$scratch/almost-complete.sh" >/dev/null
assert_first_hop_cleanup() {
  local path
  while IFS= read -r path; do
    [[ ! -e $path && ! -d $(dirname -- "$path") ]] || {
      echo "Leaked first-hop private temporary download: $path" >&2
      exit 1
    }
  done < "$STL_TEST_FIRST_HOP_PATHS"
  : > "$STL_TEST_FIRST_HOP_PATHS"
}
[[ "$(tail -n 1 "$STL_TEST_STABLE_BOOTSTRAP")" == 'quick_install_main "v0.1.0" "$@"' ]] || {
  echo 'Stable bootstrap did not pin its exact release tag.' >&2
  exit 1
}
bash "$repo/scripts/render-stable-bootstrap.sh" "$STL_TEST_PUBLIC_TAG" "$scratch/stl-bootstrap-repeat.sh"
cmp -s "$STL_TEST_STABLE_BOOTSTRAP" "$scratch/stl-bootstrap-repeat.sh" || {
  echo 'Stable bootstrap generation was not deterministic.' >&2
  exit 1
}
if bash "$repo/scripts/render-stable-bootstrap.sh" 'v0.1.0-rc.7' "$scratch/rc-not-allowed.sh" >/dev/null 2>&1; then
  echo 'RC bootstrap illegally became latest Stable.' >&2
  exit 1
fi
mkdir -p "$scratch/bin"
cat > "$scratch/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
destination=
url=
while (($#)); do
  case "$1" in
    -o) destination=$2; shift 2 ;;
    https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
# Simulate exact public first-hop curl output-to-file. No network.
if [[ "$url" == "https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh" ]]; then
  [[ -n "$destination" ]] || exit 44
  [[ -d $(dirname -- "$destination") &&
     $(stat -c %a -- "$(dirname -- "$destination")") == 700 ]] || exit 46
  printf '%s\n' "$destination" >> "$STL_TEST_FIRST_HOP_PATHS"
  case "${STL_TEST_FIRST_HOP:-}" in
    no-bytes) : > "$destination"; exit 47 ;;
    truncated) sed '$d' "$STL_TEST_STABLE_BOOTSTRAP" > "$destination"; exit 48 ;;
    almost-complete) head -c -1 "$STL_TEST_STABLE_BOOTSTRAP" > "$destination"; exit 48 ;;
    complete-then-error) cat "$STL_TEST_STABLE_BOOTSTRAP" > "$destination"; exit 48 ;;
    missing-invocation-success) sed '$d' "$STL_TEST_STABLE_BOOTSTRAP" > "$destination"; exit 0 ;;
    empty-success) : > "$destination"; exit 0 ;;
    syntax-error) printf '%s\n' 'if (( (' > "$destination"; exit 0 ;;
    "") cat "$STL_TEST_STABLE_BOOTSTRAP" > "$destination"; exit 0 ;;
    *) exit 49 ;;
  esac
fi
if [[ "$url" != 'https://raw.githubusercontent.com/ach1992/simple-tun-link/v0.1.0-rc.123/scripts/install.sh' &&
      "$url" != "https://raw.githubusercontent.com/ach1992/simple-tun-link/$STL_TEST_PUBLIC_TAG/scripts/install.sh" ]]; then
  exit 44
fi
[[ -n "$destination" ]] || exit 44
[[ -z "$STL_TEST_DOWNLOAD_FAIL" ]] || {
  printf '%s\n' 'STL_TEST_DOWNLOAD_SENSITIVE_SENTINEL' >&2
  printf '%s\n' 'STL_TEST_DOWNLOAD_SENSITIVE_SENTINEL'
  exit 45
}
if [[ -n "$STL_TEST_SYNTAX_FAIL" ]]; then
  printf '%s\n' 'if (( STL_TEST_SYNTAX_SENSITIVE_SENTINEL (' > "$destination"
else
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "test fake installer" >> "$STL_TEST_EXECUTIONS"' > "$destination"
fi
CURL
cat > "$scratch/bin/sudo" <<'SUDO'
#!/usr/bin/env bash
set -euo pipefail
printf 'sudo' >> "$STL_TEST_EXECUTIONS"
printf ' %s' "$@" >> "$STL_TEST_EXECUTIONS"
printf '\n' >> "$STL_TEST_EXECUTIONS"
if [[ ${STL_TEST_SUDO_FAIL:-} == 1 && ${1:-} == bash ]]; then
  printf '%s\n' 'STL_TEST_INSTALLER_SENSITIVE_SENTINEL' >&2
  printf '%s\n' 'STL_TEST_INSTALLER_SENSITIVE_SENTINEL'
  exit 42
fi
if [[ "$#" -eq 2 && "$1" == stl && "$2" == menu ]]; then
  printf '%s\n' 'FAKE_STL_MENU_RENDERED'
fi
exit 0
SUDO
chmod 0755 "$scratch/bin/curl" "$scratch/bin/sudo"
export PATH="$scratch/bin:$PATH"
export STL_TEST_EXECUTIONS="$scratch/record"
export STL_TEST_DOWNLOAD_FAIL=
export STL_TEST_SYNTAX_FAIL=
export STL_TEST_QUICK_INSTALL_FILE="$repo/scripts/quick-install.sh"
: > "$STL_TEST_EXECUTIONS"
# Offline non-tty startup should not start a menu or make a network call.
bash "$repo/scripts/quick-install.sh" v0.1.0-rc.123 native,wireguard > "$scratch/out" 2>"$scratch/err"
grep -q 'No interactive terminal detected' "$scratch/out"
grep -q 'v0.1.0-rc.123' "$scratch/out"
if ((EUID==0));then
  grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
else
  grep -q 'sudo bash .* install --version v0.1.0-rc.123 --backends native,wireguard' "$STL_TEST_EXECUTIONS"
fi
# Operator upgrades must use the canonical update transaction rather than
# quietly running install over an existing version (which correctly refuses).
: > "$STL_TEST_EXECUTIONS"
bash "$repo/scripts/quick-install.sh" v0.1.0-rc.123 update > "$scratch/out" 2>"$scratch/err"
if ((EUID==0));then
  grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
else
  grep -q 'sudo bash .* update --version v0.1.0-rc.123 --backends native,wireguard' "$STL_TEST_EXECUTIONS"
fi
: > "$STL_TEST_EXECUTIONS"
bash "$repo/scripts/quick-install.sh" v0.1.0-rc.123 native update > "$scratch/out" 2>"$scratch/err"
if ((EUID==0));then
  grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
else
  grep -q 'sudo bash .* update --version v0.1.0-rc.123 --backends native' "$STL_TEST_EXECUTIONS"
fi
before="$(wc -c < "$STL_TEST_EXECUTIONS")"
for invalid in 'v0.1.0-rc.123;rm' 'latest' '../main' 'v0.1.0-rc.123--bad/path'; do
  if bash "$repo/scripts/quick-install.sh" "$invalid" > "$scratch/out" 2>"$scratch/err"; then
    echo 'Bootstrap incorrectly accepted invalid version.' >&2
    exit 1
  fi
done
for invalid in 'native,wireguard,ipsec' 'upgrade' 'native,update'; do
  if bash "$repo/scripts/quick-install.sh" v0.1.0-rc.123 "$invalid" > "$scratch/out" 2> "$scratch/err"; then
    echo 'Bootstrap incorrectly accepted invalid action/backends.' >&2
    exit 1
  fi
done
if bash "$repo/scripts/quick-install.sh" v0.1.0-rc.123 update update > "$scratch/out" 2>"$scratch/err"; then
  echo 'Bootstrap accepted duplicate update flags.' >&2
  exit 1
fi
[[ "$before" == "$(wc -c < "$STL_TEST_EXECUTIONS")" ]] || {
  echo 'Invalid tag invoked privileged installer.' >&2
  exit 1
}
for scenario in STL_TEST_DOWNLOAD_FAIL STL_TEST_SYNTAX_FAIL; do
  if env "$scenario=1" bash "$repo/scripts/quick-install.sh" v0.1.0-rc.123 > "$scratch/out" 2>"$scratch/err"; then
    echo "Bootstrap incorrectly accepted $scenario" >&2
    exit 1
  fi
  if [[ $scenario == STL_TEST_DOWNLOAD_FAIL ]]; then
    grep -q 'download failed before execution' "$scratch/err" || { echo 'Missing download stage guidance' >&2; exit 1; }
  else
    grep -q 'syntax validation failed' "$scratch/err" || { echo 'Missing syntax stage guidance' >&2; exit 1; }
  fi
  if grep -q 'STL_TEST_.*SENSITIVE_SENTINEL' "$scratch/out" "$scratch/err"; then
    echo "Untrusted $scenario diagnostic leaked to operator" >&2
    exit 1
  fi
done
[[ "$before" == "$(wc -c < "$STL_TEST_EXECUTIONS")" ]] || {
  echo 'Bad or partial installer passed privilege elevation.' >&2
  exit 1
}
# Failed canonical install/update is not a successful bootstrap. Fake sudo
# exits with a controlled status after recording the action; no host effects.
if (( EUID != 0 )); then
  for action in install update; do
    : > "$STL_TEST_EXECUTIONS"
    args=()
    [[ $action != update ]] || args=(update)
    if STL_TEST_SUDO_FAIL=1 bash "$repo/scripts/quick-install.sh" v0.1.0-rc.123 "${args[@]}" > "$scratch/out" 2>"$scratch/err"; then
      echo "Bootstrap falsely accepted failed canonical $action" >&2
      exit 1
    fi
    grep -q 'did not complete (exit 42)' "$scratch/err" || { echo "Missing $action recovery guidance" >&2; exit 1; }
    grep -q 'retained recovery' "$scratch/err" || { echo "Missing uncertain-transaction guidance" >&2; exit 1; }
    if grep -q 'STL_TEST_INSTALLER_SENSITIVE_SENTINEL' "$scratch/out" "$scratch/err"; then
      echo "Raw canonical $action stdout/stderr leaked to operator" >&2
      exit 1
    fi
    if grep -q 'FAKE_STL_MENU_RENDERED' "$scratch/out" || grep -q 'sudo stl menu' "$STL_TEST_EXECUTIONS"; then
      echo "Failed $action launched STL menu" >&2
      exit 1
    fi
  done
fi
# The most important user journey: a bootstrap streamed to bash should
# reattach fd 0 to the actual terminal after its install step and launch STL.
if command -v script >/dev/null 2>&1; then
  script -q -e -c "cat '$repo/scripts/quick-install.sh' | bash -s -- v0.1.0-rc.123 native,wireguard" /dev/null \
    < /dev/null > "$scratch/pty-out" 2> "$scratch/pty-err"
  grep -q 'FAKE_STL_MENU_RENDERED' "$scratch/pty-out" || {
    echo 'Quick installer did not launch menu in the controlling PTY.' >&2
    exit 1
  }
  grep -q 'sudo stl menu' "$STL_TEST_EXECUTIONS" || {
    echo 'Quick installer did not invoke STL menu after verifying install.' >&2
    exit 1
  }
fi
# Execute the ACTUAL README one-liners with fake curl/sudo. Both command
# paths must observe complete first-hop transport and syntax validation
# before they can start any canonical installer or privileged action.
for idx in 0 1; do
  published_cmd="${published_commands[$idx]}"
  [[ "$published_cmd" == *"$stable_url"* ]] || {
    echo 'Published commands must use the immutable latest Stable asset.' >&2
    exit 1
  }
  grep -Fx -- "$published_cmd" "$repo/docs/INSTALL.md" >/dev/null || {
    echo 'User and maintainer public bootstrap commands disagree.' >&2
    exit 1
  }
  action=install
  if [[ "$idx" == 1 ]]; then action=update; fi
  # Positive path: successful completed bootstrap => canonical installer
  # with correct action and exact tag, followed by private-file cleanup.
  : > "$STL_TEST_EXECUTIONS"
  bash -c "$published_cmd" > "$scratch/out" 2>"$scratch/err"
  if (( EUID == 0 )); then
    grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
  else
    grep -Eq "^sudo bash .* $action --version $STL_TEST_PUBLIC_TAG --backends native,wireguard$" "$STL_TEST_EXECUTIONS"
  fi
  assert_first_hop_cleanup
  # The subtle case: the final invocation is present and parseable, but
  # curl returns a failure after producing almost/all of the bytes.
  # Neither install nor update may start, even briefly.
  for first_hop_failure in no-bytes truncated almost-complete complete-then-error missing-invocation-success empty-success syntax-error; do
    : > "$STL_TEST_EXECUTIONS"
    if STL_TEST_FIRST_HOP="$first_hop_failure" bash -c "$published_cmd" > "$scratch/out" 2>"$scratch/err"; then
      echo "Published $action first-hop $first_hop_failure falsely succeeded." >&2
      exit 1
    fi
    [[ ! -s "$STL_TEST_EXECUTIONS" ]] || {
      echo "Published $action first-hop $first_hop_failure invoked installer/sudo before transport success." >&2
      exit 1
    }
    assert_first_hop_cleanup
  done
done
# Separately downloaded, verified asset supports the documented advanced
# native-only update syntax; it is NOT an argument appended to the one-liner.
: > "$STL_TEST_EXECUTIONS"
bash "$STL_TEST_STABLE_BOOTSTRAP" native update > "$scratch/out" 2>"$scratch/err"
if (( EUID == 0 )); then
  grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
else
  grep -Eq "^sudo bash .* update --version $STL_TEST_PUBLIC_TAG --backends native$" "$STL_TEST_EXECUTIONS"
fi
# A successful private-file bootstrap still must reconnect the real TTY
# and open STL's menu, for the permanently published install command.
if command -v script >/dev/null 2>&1; then
  : > "$STL_TEST_EXECUTIONS"
  script -q -e -c "${published_commands[0]}" /dev/null     < /dev/null > "$scratch/public-pty-out" 2>"$scratch/public-pty-err"
  grep -q 'FAKE_STL_MENU_RENDERED' "$scratch/public-pty-out" || {
    echo 'Public first-hop wrapper prevented automatic menu launch.' >&2
    exit 1
  }
  grep -q 'sudo stl menu' "$STL_TEST_EXECUTIONS" || {
    echo 'Public first-hop wrapper failed controlling-TTY handoff.' >&2
    exit 1
  }
  assert_first_hop_cleanup
fi
echo 'PUBLIC_FIRST_HOP_TRANSPORT_COMPLETE_BEFORE_EXECUTION_AND_PTY=PASS'
# Interruption before the final complete invocation must not invoke sudo,
# report fake success, or execute a partial install.
before_trunc="$(wc -c < "$STL_TEST_EXECUTIONS")"
if sed '$d' "$repo/scripts/quick-install.sh" | bash -s -- v0.1.0-rc.123 > "$scratch/out" 2> "$scratch/err"; then
  echo 'Incomplete streamed bootstrap incorrectly succeeded.' >&2
  exit 1
fi
grep -q 'not received completely' "$scratch/err"
[[ "$before_trunc" == "$(wc -c < "$STL_TEST_EXECUTIONS")" ]] || {
  echo 'Incomplete stream invoked a privileged installer.' >&2
  exit 1
}
echo 'ONE_LINE_BOOTSTRAP_OFFLINE_GUARDS_AND_PTY=PASS'
