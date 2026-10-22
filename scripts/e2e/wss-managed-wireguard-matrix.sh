#!/usr/bin/env bash
# Explicit opt-in, ROOTLESS real-kernel WSS acceptance on a disposable host.
# This only composes the separately fenced namespace harness; no new network
# code path, installer, service or privileged host-namespace effect.
set -Eeuo pipefail
[[ $# == 0 ]] || { echo "usage: bash scripts/e2e/wss-managed-wireguard-matrix.sh" >&2; exit 2; }
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo"
[[ $(id -u) != 0 ]] || { echo "Refusing root: rootless namespaces only" >&2; exit 2; }
[[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || {
  echo "Commit and inspect all tracked/untracked source changes before accepting a candidate" >&2; exit 3;
}
lab="$repo/.r1-lab"
[[ -d $lab && ! -L $lab && $(stat -c %u -- "$lab") == $(id -u) ]] || {
  echo "Expected task-owned disposable .r1-lab fixture" >&2; exit 2;
}
lock="$lab/.wss-matrix.lock"
[[ ! -L $lock && ( ! -e $lock || ( -f $lock && $(stat -c %u -- "$lock") == $(id -u) ) ) ]] || {
  echo "Foreign test suite lock" >&2; exit 2;
}
( umask 077; : >> "$lock" )
exec 8>>"$lock"
flock -n -x 8 || { echo "Another WSS acceptance matrix owns this fixture" >&2; exit 3; }
sha=$(git rev-parse HEAD)
tree=$(git rev-parse HEAD^{tree})
out="$lab/acceptance-${sha:0:12}"
[[ ! -L $out && ( ! -e $out || ( -d $out && $(stat -c %u -- "$out") == $(id -u) ) ) ]] || {
  echo "Foreign test evidence directory" >&2; exit 2;
}
mkdir -p -- "$out"
# The inner harness owns a nonblocking EXCLUSIVE lock per complete
# namespace lifetime. Matrix orchestration never touches host netns.
test -z "$(find "$lab/run-netns" -mindepth 1 -maxdepth 1 -print -quit)"
go test -c -tags stl_e2e_lab -o "$lab/bin/stl-lab" ./cmd/stl
echo "WSS_MATRIX_SOURCE_HEAD=$sha"
echo "WSS_MATRIX_SOURCE_TREE=$tree"
echo "WSS_MATRIX_DISPOSABLE_BINARY_BUILT"
count=0
run_case() {
  local label="$1"; shift
  # Discard ambient injection flags. Only this case's explicit test-only
  # fault parameters may reach its new disposable rootless namespace.
  if env -u STL_WSS_R2_CRASH_TEST -u STL_WSS_R2_AMBIGUOUS_TEST \
    -u STL_WSS_R2_REMOVE_CRASH_TEST -u STL_WSS_R2_DRIFT_TEST \
    -u STL_WSS_R3_ORIGINAL_TEST -u STL_WSS_R3_REPAIR_TEST \
    -u STL_WSS_R3_FOREIGN_TEST -u STL_WSS_R4_PARTIAL_WG_TEST \
    -u STL_WSS_R4_GUARD_INTERLOPER -u STL_WSS_R5_MIGRATED_WG_TEST \
    -u STL_WSS_R7_COLD_BOOT_TEST -u STL_WSS_R7_DRIFT_TEST -u STL_WSS_R8_MIGRATED_ORDINARY_TEST \
    "$@" bash scripts/e2e/wss-managed-wireguard-r1.sh > "$out/$label.log" 2>&1; then
    count=$((count+1))
    echo "PASS $label"
  else
    echo "FAIL $label; see $out/$label.log" >&2
    tail -n 65 -- "$out/$label.log" >&2
    exit 1
  fi
}
run_case normal
run_case guard-interloper STL_WSS_R4_GUARD_INTERLOPER=port
run_case original-partial STL_WSS_R4_PARTIAL_WG_TEST=key-port
run_case original-nft STL_WSS_R2_CRASH_TEST=1 STL_WSS_R3_ORIGINAL_TEST=1
run_case kernel-crash STL_WSS_R2_AMBIGUOUS_TEST=kernel-crash STL_WSS_R3_ORIGINAL_TEST=1
run_case helper-crash STL_WSS_R2_AMBIGUOUS_TEST=helper-crash STL_WSS_R3_ORIGINAL_TEST=1
run_case committed-repair STL_WSS_R3_REPAIR_TEST=1
for point in stop guard; do
  run_case "remove-$point" "STL_WSS_R2_REMOVE_CRASH_TEST=$point" STL_WSS_R3_ORIGINAL_TEST=1
done
for mode in guard wg wg-global staged staged-tagged staged-foreign helper; do
  run_case "provenance-$mode" STL_WSS_R2_CRASH_TEST=1 STL_WSS_R3_ORIGINAL_TEST=1 "STL_WSS_R3_FOREIGN_TEST=$mode"
done
for mode in nft-error nft-timeout nft-cancel helper-error helper-timeout helper-cancel; do
  run_case "ambiguous-$mode" "STL_WSS_R2_AMBIGUOUS_TEST=$mode" STL_WSS_R3_ORIGINAL_TEST=1
done
for mode in firewall legacy unit; do
  run_case "drift-$mode" "STL_WSS_R2_DRIFT_TEST=$mode"
done
for mode in down active; do
  run_case "moved-$mode" "STL_WSS_R5_MIGRATED_WG_TEST=$mode"
done
for mode in fwmark ipv6; do
  run_case "ordinary-wg-drift-$mode" "STL_WSS_R7_DRIFT_TEST=$mode"
done
run_case virtual-boot-deny-guard STL_WSS_R2_CRASH_TEST=1 STL_WSS_R7_COLD_BOOT_TEST=guard
run_case virtual-boot-deny-remove STL_WSS_R2_REMOVE_CRASH_TEST=guard STL_WSS_R7_COLD_BOOT_TEST=remove
for mode in active externally-lost;do
  run_case "ordinary-migrated-$mode" "STL_WSS_R8_MIGRATED_ORDINARY_TEST=$mode"
done
[[ $count == 33 ]] || { echo "Incomplete WSS matrix $count/33" >&2; exit 3; }
[[ $(git rev-parse HEAD) == "$sha" && $(git rev-parse HEAD^{tree}) == "$tree" &&
   -z $(git status --porcelain=v1 --untracked-files=all) ]] || {
  echo "Source changed during WSS acceptance; do not trust results" >&2; exit 3;
}
echo "PASS WSS_33_33_ROOTLESS_REAL_KERNEL_E2E HEAD=$sha TREE=$tree"
