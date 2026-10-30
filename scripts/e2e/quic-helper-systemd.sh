#!/usr/bin/env bash
# Actual systemd/process contract only, on disposable GitHub-hosted Linux.
# The fixtures start bounded sleep processes, never Hysteria, Links or network rules.
set -euo pipefail

test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted
test "${GITHUB_REPOSITORY:-}" = ach1992/simple-tun-link
test "${GITHUB_EVENT_NAME:-}" = pull_request
[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]]
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]]
test -x /usr/bin/sleep
test -x /usr/bin/systemd-run
test -x /usr/bin/systemctl
test "$(cat /proc/1/comm)" = systemd

scratch="$(mktemp -d -t stl-quic-systemd-fixture.XXXXXXXX)"
cleanup() {
  # Only this invocation's private build directory. Service/process cleanup
  # belongs to retained pidfds or the managed fixture's exact verified unit
  # stop after owner/process readback; there is no broad name cleanup.
  rm -rf -- "$scratch"
}
trap cleanup EXIT

go test -c -o "$scratch/quichelper.test" ./internal/quichelper
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  GITHUB_REPOSITORY=ach1992/simple-tun-link \
  GITHUB_RUN_ID="$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
  STL_QUIC_HELPER_DISPOSABLE_SYSTEMD=approved \
  "$scratch/quichelper.test" \
  -test.run '^TestQUICHelperDisposableSystemd(Original|Managed)$' -test.count=1 -test.v -test.timeout=120s

echo 'DISPOSABLE_QUIC_HELPER_SYSTEMD_ORIGINAL_AND_MANAGED=PASS'
