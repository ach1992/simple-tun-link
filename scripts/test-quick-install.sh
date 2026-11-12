#!/usr/bin/env bash
# Offline regression of immutable Stable bootstrap and version-free first-hop.
# Host effects are simulated by fake curl/sudo in a private scratch dir.
# All fake tooling and side effects remain inside a disposable directory.
set -Eeuo pipefail
# This unit harness intercepts sudo but cannot safely intercept an already
# root process. Privileged cases run separately in disposable root guests.
if (( EUID == 0 )); then
  echo 'STL_TEST_QUICK_INSTALL_REFUSED: run as non-root' >&2
  exit 77
fi
umask 077
repo="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
# Stable release bumps must keep the permanent first-hop install/update text.
mapfile -t published_commands < <(grep '^/usr/bin/env -i HOME=/ .*stl-bootstrap.sh' "$repo/docs/INSTALL.md")
[[ ${#published_commands[@]} -eq 3 ]] || {
  echo 'INSTALL.md must contain three verified official commands (latest, exact, update).' >&2
  exit 1
}
# README exposes the literal latest Install and Update commands. Verify they
# are exactly the commands exercised from INSTALL.md, not unchecked variants.
mapfile -t readme_commands < <(grep '^/usr/bin/env -i HOME=/ .*stl-bootstrap.sh' "$repo/README.md")
[[ ${#readme_commands[@]} -eq 2 ]] || {
  echo 'README must contain the two tested official commands (latest install and update).' >&2
  exit 1
}
[[ ${readme_commands[0]} == "${published_commands[0]}" &&
   ${readme_commands[1]} == "${published_commands[2]}" ]] || {
  echo 'README Install/Update commands differ from tested INSTALL.md commands.' >&2
  exit 1
}
# Public commands must NEVER need a changing tag, branch or token.
# The immutable Stable asset itself pins the exact release tag.
stable_url='https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh'
# The first-hop command substitution must finish with curl exit 0 and
# valid Bash syntax before it executes any part of the downloaded script.
for line in "${published_commands[@]}"; do
  [[ "$line" == '/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM:-dumb}" /bin/bash -c '* &&
     "$line" == *'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '* &&
     "$line" == *'/usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 '* &&
     "$line" == *' | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"'* &&
     "$line" != *' | bash'* ]] || {
    echo 'Public installer must finish its bounded download before execution.' >&2
    exit 1
  }
done
for idx in 0 1 2; do
  public_cmd="${published_commands[$idx]}"
  if [[ "$idx" != 1 && "$public_cmd" =~ v[0-9]+\.[0-9]+\.[0-9]+ ]] ||
     [[ "$idx" == 1 && "$public_cmd" != *' stl v0.1.9' ]] ||
     [[ "$public_cmd" == *raw.githubusercontent.com* ]]; then
    echo 'Only the exact-version example may append an immutable release tag.' >&2
    exit 1
  fi
done
export STL_TEST_PUBLIC_TAG=v0.1.0
export STL_TEST_CANONICAL_SOURCE="$repo/scripts/install.sh"
canonical_sha=$(sha256sum < "$STL_TEST_CANONICAL_SOURCE")
canonical_sha=${canonical_sha%% *}
[[ $canonical_sha =~ ^[0-9a-f]{64}$ ]] || exit 1
expected_stable_invocation="quick_install_main \"$STL_TEST_PUBLIC_TAG\" \"\" \"$canonical_sha\" \"\" \"\$@\""
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
bash "$repo/scripts/render-stable-bootstrap.sh" "$STL_TEST_PUBLIC_TAG" "$scratch/stl-bootstrap.sh"
export STL_TEST_STABLE_BOOTSTRAP="$scratch/stl-bootstrap.sh"
bash -n "$STL_TEST_STABLE_BOOTSTRAP"
# This nearly-complete asset remains parseable and includes the
# privileged call, despite missing the final newline. A failing curl
# MUST prevent its execution.
head -c -1 "$STL_TEST_STABLE_BOOTSTRAP" > "$scratch/almost-complete.sh"
bash -n "$scratch/almost-complete.sh"
grep -Fx "$expected_stable_invocation" "$scratch/almost-complete.sh" >/dev/null
[[ "$(tail -n 1 "$STL_TEST_STABLE_BOOTSTRAP")" == "$expected_stable_invocation" ]] || {
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
# The unit's non-root sudo/curl are intentionally simulated, so substitute
# ONLY the absolute sudo invocation in private copies. The real release
# source and actual privileged root/sudo behavior are tested separately.
sed -e 's|/usr/bin/sudo "${root_exec\[@\]}"|sudo "${root_exec[@]}"|' \
  -e 's|exec /usr/bin/sudo /usr/local/bin/stl menu|exec sudo /usr/local/bin/stl menu|' "$STL_TEST_STABLE_BOOTSTRAP" > "$scratch/test-stable.sh"
sed -e 's|/usr/bin/sudo "${root_exec\[@\]}"|sudo "${root_exec[@]}"|' \
  -e 's|exec /usr/bin/sudo /usr/local/bin/stl menu|exec sudo /usr/local/bin/stl menu|' "$repo/scripts/quick-install.sh" > "$scratch/test-direct.sh"
grep -Fq 'sudo "${root_exec[@]}"' "$scratch/test-stable.sh"
grep -Fq 'sudo "${root_exec[@]}"' "$scratch/test-direct.sh"
# The clean first-hop PATH omits /usr/local/bin, where the core is installed.
# Both root and sudo menu handoffs must use the absolute installed path.
grep -Fq 'exec /usr/local/bin/stl menu' "$repo/scripts/quick-install.sh"
grep -Fq 'exec /usr/bin/sudo /usr/local/bin/stl menu' "$repo/scripts/quick-install.sh"
export STL_TEST_STABLE_BOOTSTRAP="$scratch/test-stable.sh"
export STL_TEST_QUICK_INSTALL_FILE="$scratch/test-direct.sh"
# The production first-hop must start Bash only AFTER env -i and use trusted
# absolute tools. Unit network simulation swaps only these boundaries, while
# separate real loopback HTTPS tests execute the hardened literal entrypoint.
prepare_mock_public_command() {
  local command=$1
  local prefix='/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM:-dumb}" /bin/bash -c'
  [[ $command == "$prefix "* ]] || return 1
  command="/bin/bash -c${command#"$prefix"}"
  command=${command/\/usr\/bin\/curl -q /curl -q }
  printf '%s' "$command"
}
mkdir -p "$scratch/bin"
cat > "$scratch/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
destination=
url=
while (($#)); do
  case "$1" in
    -o|-fsSLo) destination=$2; shift 2 ;;
    https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
# Simulate stdout-to-memory first-hop curl. No network/privilege.
if [[ "$url" == "https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh" ]]; then
  [[ -z "$destination" ]] || exit 44
  case "${STL_TEST_FIRST_HOP:-}" in
    no-bytes) exit 47 ;;
    truncated) sed '$d' "$STL_TEST_STABLE_BOOTSTRAP"; exit 48 ;;
    almost-complete) head -c -1 "$STL_TEST_STABLE_BOOTSTRAP"; exit 48 ;;
    complete-then-error) cat "$STL_TEST_STABLE_BOOTSTRAP"; exit 48 ;;
    missing-invocation-success) sed '$d' "$STL_TEST_STABLE_BOOTSTRAP"; exit 0 ;;
    empty-success) exit 0 ;;
    syntax-error) printf '%s\n' 'if (( ('; exit 0 ;;
    oversized-chunked)
      printf '#!/usr/bin/env bash\n'
      head -c 200000 /dev/zero | tr '\000' '#'
      exit 0 ;;
    "") cat "$STL_TEST_STABLE_BOOTSTRAP"; exit 0 ;;
    *) exit 49 ;;
  esac
fi
if [[ "$url" == "https://api.github.com/repos/ach1992/simple-tun-link/releases/tags/v0.1.9" ]]; then
  [[ -n "$destination" ]] || exit 44
  case "${STL_TEST_RELEASE_CASE:-}" in
    network-error) printf 'INTERNAL_CREDENTIAL=DO_NOT_LEAK\n' >&2; exit 47 ;;
    redirect) printf '302'; exit 0 ;;
    truncated) printf '{"id":123' > "$destination"; printf '200'; exit 0 ;;
    empty) : > "$destination"; printf '200'; exit 0 ;;
    oversized) head -c 262145 /dev/zero > "$destination"; printf '200'; exit 0 ;;
  esac
  tag=v0.1.9
  immutable=true
  draft=false
  prerelease=false
  assets=present
  case "${STL_TEST_RELEASE_CASE:-}" in
    mismatched-tag) tag=v0.1.10 ;;
    mutable) immutable=false ;;
    unpublished) draft=true ;;
    prerelease) prerelease=true ;;
    incomplete) assets=missing ;;
    duplicate-json) ;;
    unknown) exit 44 ;;
  esac
  if [[ "$assets" == missing ]]; then
    assets_json='[]'
  else
    assets_json='[{"name":"stl_v0.1.9_linux_amd64","size":111,"state":"uploaded"},{"name":"stl_v0.1.9_linux_arm64","size":111,"state":"uploaded"},{"name":"BUILD-MANIFEST.txt","size":111,"state":"uploaded"},{"name":"SHA256SUMS","size":111,"state":"uploaded"},{"name":"LICENSE","size":111,"state":"uploaded"}]'
  fi
  extra=
  [[ "${STL_TEST_RELEASE_CASE:-}" != duplicate-json ]] || extra=',"immutable":false'
  printf '{"id":123,"tag_name":"%s","immutable":%s,"draft":%s,"prerelease":%s,"published_at":"2026-10-21T15:46:41Z","assets":%s%s}\n' \
    "$tag" "$immutable" "$draft" "$prerelease" "$assets_json" "$extra" > "$destination"
  printf '200'
  exit 0
fi
# No user-selected historical tag may ever supply executable installer shell.
if [[ "$url" != 'https://raw.githubusercontent.com/ach1992/simple-tun-link/v0.1.0-rc.123/scripts/install.sh' &&
      "$url" != "https://raw.githubusercontent.com/ach1992/simple-tun-link/$STL_TEST_PUBLIC_TAG/scripts/install.sh" ]]; then
  exit 44
fi
# The canonical first hop uses bounded stdout streaming, never curl -o.
[[ -z "$destination" ]] || exit 44
[[ -z "$STL_TEST_DOWNLOAD_FAIL" ]] || {
  printf '%s\n' 'STL_TEST_DOWNLOAD_SENSITIVE_SENTINEL' >&2
  printf '%s\n' 'STL_TEST_DOWNLOAD_SENSITIVE_SENTINEL'
  exit 45
}
if [[ -n "${STL_TEST_OVERSIZE_DOWNSTREAM:-}" ]]; then
  printf '#!/usr/bin/env bash\n'
  head -c 1048580 /dev/zero | tr '\\000' '#'
  exit 0
fi
if [[ -n "$STL_TEST_SYNTAX_FAIL" ]]; then
  printf '%s\n' 'if (( STL_TEST_SYNTAX_SENSITIVE_SENTINEL ('
elif [[ "$url" == "https://raw.githubusercontent.com/ach1992/simple-tun-link/$STL_TEST_PUBLIC_TAG/scripts/install.sh" ]]; then
  if [[ -n "${STL_TEST_OFFICIAL_CANONICAL_TAMPERED:-}" ]]; then
    # Valid, maliciously changed shell must fail the pin before sudo.
    printf '%s\n' '#!/usr/bin/env bash' 'touch "$STL_TEST_EXECUTIONS"'
  else
    cat "$STL_TEST_CANONICAL_SOURCE"
  fi
else
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "test fake installer" >> "$STL_TEST_EXECUTIONS"'
fi
CURL
cat > "$scratch/bin/sudo" <<'SUDO'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -eq 2 && "$1" == /usr/local/bin/stl && "$2" == menu ]]; then
  printf '%s\n' 'sudo /usr/local/bin/stl menu' >> "$STL_TEST_EXECUTIONS"
  printf '%s\n' 'FAKE_STL_MENU_RENDERED'
  printf 'FAKE_STL_TERM=%s\n' "${TERM:-unset}"
  exit 0
fi
[[ ${1:-} == /usr/bin/env && ${2:-} == -i ]] || exit 85
# The private test-only shim records the intended canonical transaction.
# Real sudo/root snapshot execution is covered by an isolated root guest.
args=("$@")
found=0
for ((i=0; i + 6 < ${#args[@]}; i++)); do
  if [[ ${args[i]} == stl && ${args[i+3]} =~ ^(install|update)$ &&
        ${args[i+4]} == --version && ${args[i+6]} == --backends ]]; then
    action=${args[i+3]}
    version=${args[i+5]}
    backends=${args[i+7]}
    found=1
    break
  fi
done
[[ $found == 1 ]] || exit 86
printf 'sudo root-snapshot test fake installer %s --version %s --backends %s\n' "$action" "$version" "$backends" >> "$STL_TEST_EXECUTIONS"
if [[ ${STL_TEST_SUDO_PUBLIC_ERROR:-} == apt-index ]]; then
  printf '%s\n' 'stl installer [FAILED]: APT_INDEX_REFRESH failed; SECRET_PRIVATE_REPO_URL=DO_NOT_LEAK' >&2
  exit 42
fi
if [[ ${STL_TEST_SUDO_FAIL:-} == 1 ]]; then
  printf '%s\n' 'STL_TEST_INSTALLER_SENSITIVE_SENTINEL' >&2
  exit 42
fi
exit 0
SUDO
chmod 0755 "$scratch/bin/curl" "$scratch/bin/sudo"
export PATH="$scratch/bin:$PATH"
export STL_TEST_EXECUTIONS="$scratch/record"
export STL_TEST_DOWNLOAD_FAIL=
export STL_TEST_SYNTAX_FAIL=
export STL_TEST_QUICK_INSTALL_FILE="$scratch/test-direct.sh"
: > "$STL_TEST_EXECUTIONS"
# Offline non-tty startup should not start a menu or make a network call.
bash "$STL_TEST_QUICK_INSTALL_FILE" v0.1.0-rc.123 native,wireguard > "$scratch/out" 2>"$scratch/err"
grep -q 'No interactive terminal detected' "$scratch/out"
grep -q 'v0.1.0-rc.123' "$scratch/out"
if ((EUID==0));then
  grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
else
  grep -q 'sudo root-snapshot test fake installer install --version v0.1.0-rc.123 --backends native,wireguard' "$STL_TEST_EXECUTIONS"
fi
# The official source and generated official bootstrap must ignore ambient
# operator/caller-supplied mirror pins completely, including malformed ones.
# Fake curl accepts ONLY the official tag-pinned source in this test.
for official_source in "$STL_TEST_QUICK_INSTALL_FILE" "$STL_TEST_STABLE_BOOTSTRAP"; do
  : > "$STL_TEST_EXECUTIONS"
  if [[ $official_source == "$STL_TEST_STABLE_BOOTSTRAP" ]]; then
    args=()
  else
    args=(v0.1.0-rc.123)
  fi
  STL_MIRROR_URL=https://attacker.invalid/releases/v0.1.0 \
    STL_MIRROR_INSTALL_SHA=$(printf '%064d' 9) \
    STL_MIRROR_SUMS_SHA=$(printf '%064d' 8) \
    bash "$official_source" "${args[@]}" > "$scratch/out" 2> "$scratch/err" || {
    echo 'Official bootstrap accepted ambient mirror override.' >&2; exit 1;
  }
  if (( EUID == 0 )); then
    grep -q 'test fake installer' "$STL_TEST_EXECUTIONS" ||
      { echo 'Official installer did not run.' >&2; exit 1; }
  else
    grep -q '^sudo root-snapshot test fake installer install --version ' "$STL_TEST_EXECUTIONS" ||
      { echo 'Official installer did not run from its canonical source.' >&2; exit 1; }
  fi
  if grep -q 'release-base' "$STL_TEST_EXECUTIONS"; then
    echo 'Official installer was redirected by ambient mirror configuration.' >&2; exit 1
  fi
done
# Operator upgrades must use the canonical update transaction rather than
# quietly running install over an existing version (which correctly refuses).
: > "$STL_TEST_EXECUTIONS"
bash "$STL_TEST_QUICK_INSTALL_FILE" v0.1.0-rc.123 update > "$scratch/out" 2>"$scratch/err"
if ((EUID==0));then
  grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
else
  grep -q 'sudo root-snapshot test fake installer update --version v0.1.0-rc.123 --backends native,wireguard' "$STL_TEST_EXECUTIONS"
fi
: > "$STL_TEST_EXECUTIONS"
bash "$STL_TEST_QUICK_INSTALL_FILE" v0.1.0-rc.123 native update > "$scratch/out" 2>"$scratch/err"
if ((EUID==0));then
  grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
else
  grep -q 'sudo root-snapshot test fake installer update --version v0.1.0-rc.123 --backends native' "$STL_TEST_EXECUTIONS"
fi
before="$(wc -c < "$STL_TEST_EXECUTIONS")"
for invalid in 'v0.1.0-rc.123;rm' 'latest' '../main' 'v0.1.0-rc.123--bad/path'; do
  if bash "$STL_TEST_QUICK_INSTALL_FILE" "$invalid" > "$scratch/out" 2>"$scratch/err"; then
    echo 'Bootstrap incorrectly accepted invalid version.' >&2
    exit 1
  fi
done
for invalid in 'native,wireguard,ipsec' 'upgrade' 'native,update'; do
  if bash "$STL_TEST_QUICK_INSTALL_FILE" v0.1.0-rc.123 "$invalid" > "$scratch/out" 2> "$scratch/err"; then
    echo 'Bootstrap incorrectly accepted invalid action/backends.' >&2
    exit 1
  fi
done
if bash "$STL_TEST_QUICK_INSTALL_FILE" v0.1.0-rc.123 update update > "$scratch/out" 2>"$scratch/err"; then
  echo 'Bootstrap accepted duplicate update flags.' >&2
  exit 1
fi
[[ "$before" == "$(wc -c < "$STL_TEST_EXECUTIONS")" ]] || {
  echo 'Invalid tag invoked privileged installer.' >&2
  exit 1
}
for scenario in STL_TEST_DOWNLOAD_FAIL STL_TEST_SYNTAX_FAIL STL_TEST_OVERSIZE_DOWNSTREAM; do
  if env "$scenario=1" bash "$STL_TEST_QUICK_INSTALL_FILE" v0.1.0-rc.123 > "$scratch/out" 2>"$scratch/err"; then
    echo "Bootstrap incorrectly accepted $scenario" >&2
    exit 1
  fi
  if [[ $scenario == STL_TEST_DOWNLOAD_FAIL ]]; then
    grep -q 'download failed before execution' "$scratch/err" || { echo 'Missing download stage guidance' >&2; exit 1; }
  elif [[ $scenario == STL_TEST_SYNTAX_FAIL ]]; then
    grep -q 'syntax validation failed' "$scratch/err" || { echo 'Missing syntax stage guidance' >&2; exit 1; }
  else
    grep -q '1 MiB streaming limit' "$scratch/err" || { echo 'Missing streaming-byte-limit guidance' >&2; exit 1; }
  fi
  # Transport errors and verified-installer syntax errors are operator
  # diagnostics. Keep them visible without ever executing the rejected file.
  case "$scenario" in
    STL_TEST_DOWNLOAD_FAIL)
      grep -q 'STL_TEST_DOWNLOAD_SENSITIVE_SENTINEL' "$scratch/err" ||
        { echo 'Curl failure detail was suppressed.' >&2; exit 1; } ;;
    STL_TEST_SYNTAX_FAIL)
      grep -Eq 'unexpected EOF|syntax error' "$scratch/err" ||
        { echo 'Bash syntax location/details were suppressed.' >&2; exit 1; } ;;
    STL_TEST_OVERSIZE_DOWNSTREAM)
      ! grep -q 'STL_TEST_.*SENSITIVE_SENTINEL' "$scratch/out" "$scratch/err" ||
        { echo 'Oversize body unexpectedly reached terminal.' >&2; exit 1; } ;;
  esac
done
[[ "$before" == "$(wc -c < "$STL_TEST_EXECUTIONS")" ]] || {
  echo 'Bad or partial installer passed privilege elevation.' >&2
  exit 1
}
# Publisher-pinned official release bootstrap must reject a syntactically
# valid, substituted canonical installer before calling sudo or Bash on it.
: > "$STL_TEST_EXECUTIONS"
if STL_TEST_OFFICIAL_CANONICAL_TAMPERED=1 bash "$STL_TEST_STABLE_BOOTSTRAP" > "$scratch/out" 2>"$scratch/err"; then
  echo 'Immutable Stable bootstrap executed substituted canonical source.' >&2
  exit 1
fi
grep -q 'immutable Stable bootstrap SHA256 pin' "$scratch/err" || {
  echo 'Missing official source pin-mismatch diagnostic.' >&2
  exit 1
}
[[ ! -s "$STL_TEST_EXECUTIONS" ]] || {
  echo 'Official source pin mismatch reached privileged execution.' >&2
  exit 1
}
# An inherited exported Bash function may not spoof the SHA checker.
sha256sum() { printf '%s  -\n' "$canonical_sha"; }
export -f sha256sum
: > "$STL_TEST_EXECUTIONS"
if STL_TEST_OFFICIAL_CANONICAL_TAMPERED=1 bash "$STL_TEST_STABLE_BOOTSTRAP" > "$scratch/out" 2>"$scratch/err"; then
  echo 'Inherited SHA256 function bypassed the official release pin.' >&2
  exit 1
fi
[[ ! -s "$STL_TEST_EXECUTIONS" ]] || {
  echo 'Inherited SHA256 function reached privileged installer.' >&2
  exit 1
}
unset -f sha256sum
echo 'OFFICIAL_STABLE_CANONICAL_PIN_PRE_PRIVILEGE=PASS'
# Failed canonical install/update is not a successful bootstrap. Fake sudo
# exits with a controlled status after recording the action; no host effects.
if (( EUID != 0 )); then
  for action in install update; do
    : > "$STL_TEST_EXECUTIONS"
    args=()
    [[ $action != update ]] || args=(update)
    if STL_TEST_SUDO_FAIL=1 bash "$STL_TEST_QUICK_INSTALL_FILE" v0.1.0-rc.123 "${args[@]}" > "$scratch/out" 2>"$scratch/err"; then
      echo "Bootstrap falsely accepted failed canonical $action" >&2
      exit 1
    fi
    grep -q 'exited with status 42' "$scratch/err" || { echo "Missing $action exit-status guidance" >&2; exit 1; }
    grep -q 'retained recovery' "$scratch/err" || { echo "Missing uncertain-transaction guidance" >&2; exit 1; }
    grep -q 'STL_TEST_INSTALLER_SENSITIVE_SENTINEL' "$scratch/out" || {
      echo "Canonical $action diagnostic was lost to the operator." >&2
      exit 1
    }
    if grep -q 'FAKE_STL_MENU_RENDERED' "$scratch/out" || grep -q 'sudo /usr/local/bin/stl menu' "$STL_TEST_EXECUTIONS"; then
      echo "Failed $action launched STL menu" >&2
      exit 1
    fi
  done
fi
# Trusted, authored error categories must survive the bootstrap sanitizer
# without replaying sensitive APT output from the canonical child.
if (( EUID != 0 )); then
  if STL_TEST_SUDO_PUBLIC_ERROR=apt-index bash "$STL_TEST_QUICK_INSTALL_FILE" v0.1.0-rc.123 > "$scratch/out" 2> "$scratch/err"; then
    echo 'Classified APT failure was incorrectly accepted.' >&2; exit 1
  fi
  grep -q 'APT_INDEX_REFRESH failed; SECRET_PRIVATE_REPO_URL=DO_NOT_LEAK' "$scratch/out" || {
    echo 'APT stage and actual failing source context were lost.' >&2
    exit 1
  }
  grep -q 'exited with status 42' "$scratch/err" || {
    echo 'APT failure omitted its real child exit status.' >&2
    exit 1
  }
fi
# The most important user journey: a bootstrap streamed to bash should
# reattach fd 0 to the actual terminal after its install step and launch STL.
if command -v script >/dev/null 2>&1; then
  for action in install update; do
    args=
    [[ $action != update ]] || args=update
    : > "$STL_TEST_EXECUTIONS"
    TERM=xterm-256color PATH="$scratch/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      script -q -e -c "cat '$STL_TEST_QUICK_INSTALL_FILE' | bash -s -- v0.1.0-rc.123 native,wireguard $args" /dev/null \
      < /dev/null > "$scratch/pty-out" 2> "$scratch/pty-err"
    grep -q 'FAKE_STL_MENU_RENDERED' "$scratch/pty-out" || {
      echo "Quick $action did not launch menu under a restricted PATH." >&2
      exit 1
    }
    grep -q 'FAKE_STL_TERM=xterm-256color' "$scratch/pty-out" || {
      echo "Quick $action lost terminal type before the auto-menu handoff." >&2
      exit 1
    }
    grep -q 'sudo /usr/local/bin/stl menu' "$STL_TEST_EXECUTIONS" || {
      echo "Quick $action did not invoke the absolute installed STL menu." >&2
      exit 1
    }
  done
fi
# Execute all three published commands through the real short downloader.
# Every action needs complete first-hop transport and syntax validation
# before they can start any canonical installer or privileged action.
# A clean first hop retains only the terminal capability required for
# the post-success full-screen menu, never shell hooks or PATH overrides.
observed_term=$(export TERM=xterm-256color; /usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM:-dumb}" /bin/bash -c 'printf %s "$TERM"')
[[ $observed_term == xterm-256color ]] || {
  echo 'Clean first hop lost interactive terminal capabilities.' >&2
  exit 1
}
observed_term=$(export TERM=dumb; /usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM:-dumb}" /bin/bash -c 'printf %s "$TERM"')
[[ $observed_term == dumb ]] || {
  echo 'Clean first hop overrode explicit dumb terminal setting.' >&2
  exit 1
}
for idx in 0 1 2; do
  published_cmd="${published_commands[$idx]}"
  mocked_cmd=$(prepare_mock_public_command "$published_cmd")
  [[ "$published_cmd" == *"$stable_url"* ]] || {
    echo 'Published commands must use the immutable latest Stable asset.' >&2
    exit 1
  }
  grep -Fx -- "$published_cmd" "$repo/docs/INSTALL.md" >/dev/null || {
    echo 'User and maintainer public bootstrap commands disagree.' >&2
    exit 1
  }
  action=install
  expected_tag=$STL_TEST_PUBLIC_TAG
  if [[ "$idx" == 1 ]]; then expected_tag=v0.1.9; fi
  if [[ "$idx" == 2 ]]; then action=update; fi
  # Positive path: successful completed bootstrap => canonical installer
  # with correct action and exact tag, without executing partial downloads.
  : > "$STL_TEST_EXECUTIONS"
  if ! bash -c "$mocked_cmd" > "$scratch/out" 2>"$scratch/err"; then
    echo "Published installer failed: $(cat "$scratch/err")" >&2
    exit 1
  fi
  if (( EUID == 0 )); then
    grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
  else
    grep -Eq "^sudo root-snapshot test fake installer $action --version $expected_tag --backends native,wireguard$" "$STL_TEST_EXECUTIONS"
  fi
  # The subtle case: the final invocation is present and parseable, but
  # curl returns a failure after producing almost/all of the bytes.
  # Neither install nor update may start, even briefly.
  for first_hop_failure in no-bytes truncated almost-complete complete-then-error missing-invocation-success empty-success syntax-error oversized-chunked; do
    : > "$STL_TEST_EXECUTIONS"
    if STL_TEST_FIRST_HOP="$first_hop_failure" bash -c "$mocked_cmd" > "$scratch/out" 2>"$scratch/err"; then
      echo "Published $action first-hop $first_hop_failure falsely succeeded." >&2
      exit 1
    fi
    [[ ! -s "$STL_TEST_EXECUTIONS" ]] || {
      echo "Published $action first-hop $first_hop_failure invoked installer/sudo before transport success." >&2
      exit 1
    }
    done
done
# A selected historical tag is NEVER a shell path. Rejected metadata must
# fail before execution, including transport failure, redirects and truncation.
for release_case in network-error redirect truncated empty oversized mismatched-tag mutable unpublished prerelease incomplete duplicate-json; do
  : > "$STL_TEST_EXECUTIONS"
  if STL_TEST_RELEASE_CASE="$release_case" bash "$STL_TEST_STABLE_BOOTSTRAP" v0.1.9 > "$scratch/out" 2> "$scratch/err"; then
    echo "Unverified release $release_case accepted by official bootstrap." >&2
    exit 1
  fi
  [[ ! -s "$STL_TEST_EXECUTIONS" ]] || {
    echo "Unverified release $release_case invoked the canonical installer." >&2
    exit 1
  }
  if [[ $release_case == network-error ]]; then
    grep -Fq 'INTERNAL_CREDENTIAL=DO_NOT_LEAK' "$scratch/err" || {
      echo 'Release API transport diagnostic was suppressed.' >&2
      exit 1
    }
  elif grep -q 'DO_NOT_LEAK' "$scratch/out" "$scratch/err"; then
    echo 'Unexpected release API body was forwarded.' >&2
    exit 1
  fi
done
# Separately downloaded, verified asset supports the documented advanced
# native-only update syntax; it is NOT an argument appended to the one-liner.
: > "$STL_TEST_EXECUTIONS"
bash "$STL_TEST_STABLE_BOOTSTRAP" native update > "$scratch/out" 2>"$scratch/err"
if (( EUID == 0 )); then
  grep -q 'test fake installer' "$STL_TEST_EXECUTIONS"
else
  grep -Eq "^sudo root-snapshot test fake installer update --version $STL_TEST_PUBLIC_TAG --backends native$" "$STL_TEST_EXECUTIONS"
fi
# A successful memory-captured bootstrap still must reconnect the real TTY
# and open STL's menu, for the permanently published install command.
if command -v script >/dev/null 2>&1; then
  : > "$STL_TEST_EXECUTIONS"
  TERM=xterm-256color PATH="$scratch/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    script -q -e -c "$(prepare_mock_public_command "${published_commands[0]}")" /dev/null \
    < /dev/null > "$scratch/public-pty-out" 2>"$scratch/public-pty-err"
  grep -q 'FAKE_STL_MENU_RENDERED' "$scratch/public-pty-out" || {
    echo 'Public first-hop wrapper prevented automatic menu launch.' >&2
    exit 1
  }
  grep -q 'FAKE_STL_TERM=xterm-256color' "$scratch/public-pty-out" || {
    echo 'Public first-hop failed to preserve interactive TERM.' >&2
    exit 1
  }
  grep -q 'sudo /usr/local/bin/stl menu' "$STL_TEST_EXECUTIONS" || {
    echo 'Public first-hop wrapper failed controlling-TTY handoff.' >&2
    exit 1
  }
fi
echo 'PUBLIC_FIRST_HOP_TRANSPORT_COMPLETE_BEFORE_EXECUTION_AND_PTY=PASS'
# Interruption before the final complete invocation must not invoke sudo,
# report fake success, or execute a partial install.
before_trunc="$(wc -c < "$STL_TEST_EXECUTIONS")"
if sed '$d' "$STL_TEST_QUICK_INSTALL_FILE" | bash -s -- v0.1.0-rc.123 > "$scratch/out" 2> "$scratch/err"; then
  echo 'Incomplete streamed bootstrap incorrectly succeeded.' >&2
  exit 1
fi
grep -q 'not received completely' "$scratch/err"
[[ "$before_trunc" == "$(wc -c < "$STL_TEST_EXECUTIONS")" ]] || {
  echo 'Incomplete stream invoked a privileged installer.' >&2
  exit 1
}
echo 'ONE_LINE_BOOTSTRAP_OFFLINE_GUARDS_AND_PTY=PASS'
