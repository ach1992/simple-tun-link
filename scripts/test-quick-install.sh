#!/usr/bin/env bash
# Nonprivileged offline checks for the pinned one-command bootstrap.
# All fake tooling and side effects remain inside a disposable directory.
set -Eeuo pipefail
umask 077
repo="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
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
[[ -n "$destination" && "$url" == 'https://raw.githubusercontent.com/ach1992/simple-tun-link/v0.1.0-rc.123/scripts/install.sh' ]] || exit 44
[[ -z "$STL_TEST_DOWNLOAD_FAIL" ]] || exit 45
if [[ -n "$STL_TEST_SYNTAX_FAIL" ]]; then
  printf '%s\n' 'if (( (' > "$destination"
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
done
[[ "$before" == "$(wc -c < "$STL_TEST_EXECUTIONS")" ]] || {
  echo 'Bad or partial installer passed privilege elevation.' >&2
  exit 1
}
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
