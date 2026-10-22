#!/usr/bin/env bash
# No physical host effects: parent user/net/mount NS is never shared.
set -euo pipefail
if [[ "${1:-}" == --nsroot ]]; then
  lab=/lab
else
  repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
  lab="$repo/.r1-lab"
fi
if [[ "${1:-}" != --inside && "${1:-}" != --nsroot ]]; then
  [[ $(id -u) != 0 ]] || { echo "Run as an unprivileged user (rootless network namespaces only)" >&2; exit 2; }
  for file in "$lab/bin/wstunnel" "$lab/bin/stl-lab" "$lab/bin/wg-extract/usr/bin/wg"               "$lab/bin/iptables-extract/usr/sbin/xtables-nft-multi" "$lab/bin/shims/systemctl"; do
    [[ -f $file || -L $file ]] || { echo "Missing isolated test prerequisite: $file" >&2; exit 2; }
  done
  [[ $(sha256sum "$lab/bin/wstunnel" | cut -d' ' -f1) == 6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49 ]] || { echo "Pinned test wstunnel digest mismatch" >&2; exit 2; }
  [[ $(uname -m) == x86_64 ]] || { echo "Current isolated E2E fixture supports amd64; do not claim ARM64 E2E" >&2; exit 2; }
  # Prevent use of the separately mapped --inside and --nsroot entrypoints
  # on the caller's real root/host namespaces. All witness files are 0700.
  umask 077
  printf '%s\n' "$(readlink /proc/self/ns/user)" > "$lab/host-user-ns-id"
  token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  printf '%s\n' "$token" > "$lab/namespace-guard"
  export STL_WSS_R1_TEST_GUARD="$token"
  cp -- "$repo/scripts/e2e/wss-managed-wireguard-r1.sh" "$lab/wss-real-e2e.sh"
  cp -- "$repo/scripts/e2e/wss-negative-probe.py" "$lab/wss-negative-probe.py"
  # Always stage the exact source-tracked disposable supervisor. Never rely
  # on a stale, untracked prior lab copy as an acceptance dependency.
  install -m 0755 "$repo/scripts/e2e/wss-r1-supervisor.py" "$lab/bin/shims/systemd_shim.py"
  if [[ ${STL_WSS_R2_CRASH_TEST:-0} == 1 || -n "${STL_WSS_R2_AMBIGUOUS_TEST:-}" || -n "${STL_WSS_R2_REMOVE_CRASH_TEST:-}" ]]; then
    # All effects stay in disposable rootless namespaces. Do not override a
    # foreign executable: the staging dir is task-owned and non-shared.
    if [[ -e "$lab/bin/shims/nft" || -L "$lab/bin/shims/nft" ]]; then
      [[ -f "$lab/bin/shims/nft" && ! -L "$lab/bin/shims/nft" &&
         $(stat -c %u "$lab/bin/shims/nft") == $(id -u) &&
         $(head -n 2 "$lab/bin/shims/nft" | tail -n 1) == '"""Disposable namespace-only crash injection at the FIRST successful nft' ]] || {
           echo "foreign nft test executable; refusing to overwrite" >&2; exit 2;
         }
    fi
    install -m 0755 "$repo/scripts/e2e/wss-r2-nft-crash.py" "$lab/bin/shims/nft"
    if [[ $(printenv STL_WSS_R2_AMBIGUOUS_TEST || :) == kernel-crash ]]; then
       install -m 0755 "$repo/scripts/e2e/wss-r2-wg-crash.py" "$lab/bin/shims/wg"
    fi
  fi


  if [[ $(printenv STL_WSS_R2_DRIFT_TEST || :) == legacy ]];then
    for name in iptables-legacy-save ip6tables-legacy-save;do
      install -m 0755 "$repo/scripts/e2e/wss-r2-legacy-drift.py" "$lab/bin/shims/$name"
    done
  fi
  rm -rf -- "$lab/alpha-state" "$lab/beta-state" "$lab/alpha/runtime" "$lab/beta/runtime"
  mkdir -p "$lab/run-netns" "$lab/alpha" "$lab/beta"
  readlink /proc/self/ns/net > "$lab/host-ns-id"
  exec unshare -Urnmpf bash "$0" --inside
fi
# Treat internal entrypoints as UNTRUSTED. Before *any* mount/network
# effect, prove that this is the launcher-created root-mapped user+net NS.
# A direct --inside invocation from root must not alter the real host.
if [[ "${1:-}" == --inside || "${1:-}" == --nsroot ]]; then
  [[ -n "${STL_WSS_R1_TEST_GUARD:-}" && -f "$lab/namespace-guard" &&
     ! -L "$lab/namespace-guard" && -f "$lab/host-user-ns-id" &&
     -f "$lab/host-ns-id" ]] || {
       echo "R1 isolated namespace launcher evidence missing" >&2; exit 2;
     }
  [[ $(cat "$lab/namespace-guard") == "$STL_WSS_R1_TEST_GUARD" &&
     $(id -u) == 0 &&
     $(readlink /proc/self/ns/user) != $(cat "$lab/host-user-ns-id") &&
     $(readlink /proc/self/ns/net) != $(cat "$lab/host-ns-id") &&
     $(awk 'NF==3 && $1=="0" && $3=="1"{n++} END{print n+0}' /proc/self/uid_map) == 1 ]] || {
       echo "R1 internal entrypoint is not inside a fresh root-mapped user+net namespace" >&2; exit 2;
     }
fi
if [[ "${1:-}" == --inside ]]; then
  # Private synthetic root has the correct root-owned ancestors for the
  # exact same production executable/credential admission. Original /usr
  # and /etc mounts are visible below separate synthetic root-owned nodes.
  mount --make-rprivate /
  root="$lab/ns-root"
  mkdir -p "$root"
  mount -t tmpfs tmpfs "$root"
  for d in usr/bin usr/sbin usr/lib usr/lib64 etc proc sys dev tmp run var/lib usr/local lab; do
    mkdir -p "$root/$d"
  done
  ln -s usr/bin "$root/bin"
  ln -s usr/sbin "$root/sbin"
  ln -s usr/lib "$root/lib"
  ln -s usr/lib64 "$root/lib64"
  for d in usr/bin usr/sbin usr/lib usr/lib64 etc; do
    mount --bind "/$d" "$root/$d"
  done
  mount -t proc proc "$root/proc"
  mount -t sysfs sysfs "$root/sys"
  mount --rbind /dev "$root/dev"
  mount --bind "$lab" "$root/lab"
  chmod 01777 "$root/tmp"
  exec chroot "$root" /usr/bin/bash /lab/wss-real-e2e.sh --nsroot
fi
[[ -n "${STL_WSS_R1_TEST_GUARD:-}" && -f "$lab/namespace-guard" &&
   $(cat "$lab/namespace-guard") == "$STL_WSS_R1_TEST_GUARD" &&
   $(readlink /proc/self/ns/user) != $(cat "$lab/host-user-ns-id") ]] || {
  echo "Missing bounded rootless namespace witness" >&2; exit 2;
}
if [[ $(id -u) != 0 || $(readlink /proc/self/ns/net) == $(cat "$lab/host-ns-id") ]]; then
  echo "Isolated namespaces required" >&2; exit 2
fi
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
mount --bind "$lab/run-netns" /run/netns
mount -t tmpfs tmpfs /usr/local
mkdir -p /usr/local/libexec/stl /usr/local/bin
cp "$lab/bin/stl-lab" /usr/local/bin/stl-lab
chmod 0755 /usr/local/bin/stl-lab
cp "$lab/bin/wstunnel" /usr/local/libexec/stl/wstunnel
chmod 0755 /usr/local/libexec/stl/wstunnel
printf '%s  %s\n' 6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49 /usr/local/libexec/stl/wstunnel | sha256sum -c -
mount -t tmpfs tmpfs /var/lib
mkdir -m 0700 /var/lib/stl-r1-state
export PATH="$lab/bin/shims:$lab/bin/wg-extract/usr/bin:$lab/bin/iptables-extract/usr/sbin:$PATH"
export LD_LIBRARY_PATH="$lab/bin/iptables-extract/usr/lib/x86_64-linux-gnu"
ip netns add alpha
ip netns add beta
cleanup(){
 for side in alpha beta; do
    for f in "$lab/$side"/runtime/*.json; do
      [[ -f $f ]] || continue
      pid=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pid"])' "$f")
      kill "$pid" 2>/dev/null || :
    done
 done
 ip netns delete alpha 2>/dev/null || :
 ip netns delete beta 2>/dev/null || :
}
trap cleanup EXIT
ip link add veth-alpha type veth peer name veth-beta
ip link set veth-alpha netns alpha
ip link set veth-beta netns beta
ip netns exec alpha ip link set lo up
ip netns exec beta ip link set lo up
ip netns exec alpha ip address add 198.51.100.21/24 dev veth-alpha
ip netns exec beta ip address add 198.51.100.22/24 dev veth-beta
ip netns exec alpha ip link set veth-alpha up
ip netns exec beta ip link set veth-beta up
for side in alpha beta; do
  mkdir -p "$lab/$side-state/handoff" "$lab/$side/runtime"
  chmod 0700 "$lab/$side-state" "$lab/$side-state/handoff" "$lab/$side/runtime"
done
echo "UNDERLAY:"
ip netns exec alpha ping -c 1 -W 2 198.51.100.22
printf '%s\n' '{"schema_version":1,"link_id":"lnk_0123456789abcdef0123456789abcdef","underlay":{"local":"198.51.100.21","peer":"198.51.100.22"},"addresses":{"local":"10.75.0.1/30","peer":"10.75.0.2/30"},"listen_port":51821,"peer_port":51822,"role":"listen","tcp_port":59443,"remote_forward_udp_port":53001,"local_keepalive":25,"peer_keepalive":25}' > "$lab/alpha/create.json"
invoke(){
  local side=$1; shift
  export STL_R1_SIDE_ROOT="$lab/$side"
  echo "STL $side $*" >&2
  local args_json
  args_json=$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")
  export STL_E2E_ARGS="$args_json"
  ip netns exec "$side" unshare -m bash -c '
    mount --make-rprivate /
    mount --bind "$1" /var/lib/stl-r1-state
    exec /usr/local/bin/stl-lab -test.run ^TestWSSLabCLI$ -test.v=false
  ' _ "$lab/$side-state"
}
if [[ -n "${STL_WSS_R2_AMBIGUOUS_TEST:-}" ]]; then
  case "$STL_WSS_R2_AMBIGUOUS_TEST" in
    nft-error|nft-timeout|nft-cancel|helper-error|helper-timeout|helper-cancel|helper-crash|kernel-crash) ;;
    *) echo "invalid isolated fault mode" >&2; exit 2;;
  esac
  kind=$STL_WSS_R2_AMBIGUOUS_TEST
  echo "INJECT DISPATCHED-THEN-ERROR: $kind"
  if invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/receiver.json < "$lab/alpha/create.json" > "$lab/alpha/ambiguous-effect.log" 2>&1;then
    echo "Unexpected success after injected command failure" >&2;exit 1
  fi
  id=lnk_0123456789abcdef0123456789abcdef
  guard=$(python3 -c 'import hashlib;print("stlwss_"+hashlib.sha256(b"lnk_0123456789abcdef0123456789abcdef").hexdigest()[:16])')
  jq -e '.links|length==0' "$lab/alpha-state/state.json" >/dev/null
  jq -e '(.wss_crash_operations|length)==1 and .wss_crash_operations[0].operation=="ensure"' "$lab/alpha-state/state.json" >/dev/null
  ip netns exec alpha /usr/sbin/nft -j list table inet "$guard" >/dev/null
  if [[ "$kind" == helper-* ]];then
    ip netns exec alpha ip link show stlwg0123456789 >/dev/null
    export STL_R1_SIDE_ROOT="$lab/alpha"
    systemctl show "stl-wss-0123456789abcdef0123456789abcdef.service" | grep -q '^LoadState=loaded'
    echo "DENY_PASS AMBIGUOUS_HELPER_REMAINS_WITH_NFT_PROTECTION"
  elif [[ "$kind" == kernel-crash ]];then
    ip netns exec alpha ip link show stlwg0123456789 >/dev/null
    echo "DENY_PASS CRASH_AFTER_REAL_KERNEL_WG_CHANGE_RETAINS_JOURNAL_AND_GUARD"
  else
    if ip netns exec alpha ip link show stlwg0123456789 >/dev/null 2>&1;then
      echo "kernel WG created despite uncertain nft guard" >&2;exit 1
    fi
    echo "DENY_PASS AMBIGUOUS_NFT_GUARD_NOT_DELETED"
  fi
  jq -c '{"schema_version":3,"link":.wss_crash_operations[0].intent}' "$lab/alpha-state/state.json" > "$lab/alpha/ambiguous-retry.json"
  if invoke alpha link ensure --stdin < "$lab/alpha/ambiguous-retry.json" > "$lab/alpha/ambiguous-retry.log" 2>&1;then
    echo "replayed uncertain WSS mutation" >&2;exit 1
  fi
  if invoke alpha link reconcile-wss-vacant "$id" --confirm "$id" > "$lab/alpha/ambiguous-clear.log" 2>&1;then
    echo "live orphan was adopted by vacancy reconciliation" >&2;exit 1
  fi
  ip netns exec alpha /usr/sbin/nft -j list table inet "$guard" >/dev/null
  echo "SUCCESS AMBIGUOUS_WSS_HOST_EFFECT_PRESERVED_AND_JOURNALED: $kind"
  if [[ $(printenv STL_WSS_R3_ORIGINAL_TEST || :) == 1 ]];then
    # The deliberately failing external command was a ONE-TIME injected
    # post-effect fault. Reattempt recovery in a new CLI invocation after
    # that fault has ended; otherwise the test continually sabotages its
    # own cleanup and cannot distinguish product recovery from a persistent
    # broken nft/systemd binary.
    unset STL_WSS_R2_AMBIGUOUS_TEST
    invoke alpha link reconcile-wss-original "$id" --confirm "$id"
    if invoke alpha link reconcile-wss-original "$id" --confirm "$id" > "$lab/alpha/original-repeat-denied.log" 2>&1;then
      echo "repeat recovery falsely found an original live journal" >&2;exit 1
    fi
    jq -e '(.wss_crash_operations//[]|length)==0 and (.links|length)==0' "$lab/alpha-state/state.json" >/dev/null
    if ip netns exec alpha /usr/sbin/nft list table inet "$guard" >/dev/null 2>&1;then
      echo "original compensation did not remove its journal-tagged nft guard" >&2;exit 1
    fi
    if ip netns exec alpha ip link show stlwg0123456789 >/dev/null 2>&1;then
      echo "original compensation did not collect its kernel WG interface" >&2;exit 1
    fi
    export STL_R1_SIDE_ROOT="$lab/alpha"
    systemctl show stl-wss-0123456789abcdef0123456789abcdef.service | grep -q '^LoadState=not-found'
    echo "SUCCESS ORIGINAL_LIVE_HOST_CRASH_RECOVERY: $kind"
  fi
  exit 0
fi

if [[ ${STL_WSS_R2_CRASH_TEST:-0} == 1 ]]; then
  echo "WSS R2: INJECT HARD CRASH AFTER REAL NFT GUARD CREATION, BEFORE STATE COMMIT"
  export STL_WSS_R2_CRASH_AFTER_GUARD=1
  if invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/receiver.json < "$lab/alpha/create.json" > "$lab/alpha/injected-crash.log" 2>&1; then
    echo "WSS R2 FAILED: host mutation did not kill the CLI" >&2; exit 1
  fi
  unset STL_WSS_R2_CRASH_AFTER_GUARD
  link_id=lnk_0123456789abcdef0123456789abcdef
  guard=$(python3 -c 'import hashlib;print("stlwss_"+hashlib.sha256(b"lnk_0123456789abcdef0123456789abcdef").hexdigest()[:16])')
  jq -e '.links|length==0' "$lab/alpha-state/state.json" >/dev/null
  jq -e '.wss_crash_operations | length==1 and .[0].operation=="ensure" and .[0].intent.backend=="wireguard-wss" and (.[0].nonce|length)==32' "$lab/alpha-state/state.json" >/dev/null
  ip netns exec alpha /usr/sbin/nft -j list table inet "$guard" | jq -e '[.nftables[] | .rule? | .comment? | strings | select(startswith("stl:"))] | length==1' >/dev/null
  jq -c '{"schema_version":3,"link":.wss_crash_operations[0].intent}' "$lab/alpha-state/state.json" > "$lab/alpha/recovery-ensure.json"
  if invoke alpha link ensure --stdin < "$lab/alpha/recovery-ensure.json" > "$lab/alpha/recovery-blocked.log" 2>&1; then
    echo "WSS R2 FAILED: prepared crash transaction was silently replayed" >&2;exit 1
  fi
  if invoke alpha link reconcile-wss-vacant "$link_id" --confirm "$link_id" > "$lab/alpha/guard-clear-denied.log" 2>&1; then
    echo "WSS R2 FAILED: reconciliation adopted/deleted a live nft guard" >&2;exit 1
  fi
  ip netns exec alpha /usr/sbin/nft -j list table inet "$guard" >/dev/null
  echo "DENY_PASS PRECOMMIT_JOURNAL_BLOCKED_RETRY_AND_LIVE_GUARD_RECONCILIATION"
  original_case=$(printenv STL_WSS_R3_FOREIGN_TEST || :)
  case "$original_case" in
    ''|guard|wg|wg-global|staged|staged-tagged|staged-foreign|helper) ;;
    *) echo "unsupported original-provenance test case" >&2;exit 2 ;;
  esac
  nonce=$(jq -r '.wss_crash_operations[0].nonce' "$lab/alpha-state/state.json")
  stage=$(python3 - "$link_id" "$nonce" <<'STAGING'
import sys,hashlib,base64
digest=hashlib.sha256((sys.argv[1]+":wss:"+sys.argv[2]).encode()).digest()
print("w"+base64.b32encode(digest).decode().lower()[:14])
STAGING
)
  if [[ "$original_case" == guard ]];then
    # Test-only replacement: exact SAME table/chain/rule and public name,
    # with a DIFFERENT original creation nonce. The replacement is foreign
    # despite its matching packet policy and untrusted public names.
    ip netns exec alpha /usr/sbin/nft delete table inet "$guard"
    ip netns exec alpha /usr/sbin/nft -f - <<NFT
create table inet $guard
create chain inet $guard ingress { type filter hook input priority -250; policy accept; }
add rule inet $guard ingress iifname != "lo" udp dport 51821 counter drop comment "stl:$link_id:wg-udp-guard:51821:tx:ffffffffffffffffffffffffffffffff"
NFT
  elif [[ "$original_case" == wg ]];then
    ip netns exec alpha ip link add stlwg0123456789 type wireguard
    ip netns exec alpha ip link set stlwg0123456789 alias "stl:$link_id:tx:ffffffffffffffffffffffffffffffff"
  elif [[ "$original_case" == wg-global ]];then
    # The original WSS ifindex is absent. Another (foreign) WG interface
    # holds the same reserved UDP port; removing the guard would expose it.
    ip netns exec alpha ip link add foreignwg0 type wireguard
    ip netns exec alpha wg set foreignwg0 listen-port 51821
  elif [[ "$original_case" == staged || "$original_case" == staged-tagged || "$original_case" == staged-foreign ]];then
    ip netns exec alpha ip link add "$stage" type wireguard
    if [[ "$original_case" == staged-tagged ]];then
      ip netns exec alpha ip link set "$stage" alias "stl:$link_id:tx:$nonce"
    elif [[ "$original_case" == staged-foreign ]];then
      ip netns exec alpha ip link set "$stage" up
    fi
  elif [[ "$original_case" == helper ]];then
    python3 - "$lab/alpha/runtime/stl-wss-0123456789abcdef0123456789abcdef.service.json" <<'FOREIGN'
import json,sys
path=sys.argv[1]
d={"unit":"stl-wss-0123456789abcdef0123456789abcdef.service",
   "pid":-1,"argv":["/usr/local/libexec/stl/wstunnel"],
   "description":"STL-WSS-foreign-replacement","env":{},
   "properties":{},"collect":True}
with open(path,"w") as f:json.dump(d,f)
FOREIGN
  fi
  if [[ "$original_case" == guard || "$original_case" == wg ||
        "$original_case" == wg-global || "$original_case" == staged-foreign ||
        "$original_case" == helper ]];then
    if invoke alpha link reconcile-wss-original "$link_id" --confirm "$link_id" > "$lab/alpha/foreign-recovery-denied.log" 2>&1;then
      echo "FOREIGN HOST RESOURCE WAS MUTATED/ADOPTED" >&2;exit 1
    fi
    jq -e '(.links|length)==0 and (.wss_crash_operations|length)==1' "$lab/alpha-state/state.json" >/dev/null
    ip netns exec alpha /usr/sbin/nft -j list table inet "$guard" >/dev/null
    case "$original_case" in
      wg) ip netns exec alpha ip -details link show stlwg0123456789 | grep -F 'ffffffffffffffffffffffffffffffff' >/dev/null ;;
      wg-global) ip netns exec alpha wg show foreignwg0 listen-port | grep -q '^51821$' ;;
      staged-foreign) ip netns exec alpha ip -details link show "$stage" | grep -q 'state UNKNOWN\|state UP' ;;
      helper) test -f "$lab/alpha/runtime/stl-wss-0123456789abcdef0123456789abcdef.service.json" ;;
      guard) ip netns exec alpha nft -j list table inet "$guard" | jq -e '[.nftables[]|.rule?.comment? | strings | select(endswith("ffffffffffffffffffffffffffffffff"))]|length==1' >/dev/null ;;
    esac
    echo "DENY_PASS FOREIGN_SAME_NAME_ORIGINAL_RESOURCE_PRESERVED: $original_case"
    exit 0
  fi
  if [[ $(printenv STL_WSS_R3_ORIGINAL_TEST || :) == 1 ]];then
    invoke alpha link reconcile-wss-original "$link_id" --confirm "$link_id"
    if invoke alpha link reconcile-wss-original "$link_id" --confirm "$link_id" > "$lab/alpha/original-repeat-denied.log" 2>&1;then
      echo "initial original recovery repeated after journal consumption" >&2;exit 1
    fi
    if ip netns exec alpha /usr/sbin/nft list table inet "$guard" >/dev/null 2>&1;then
      echo "WSS original-owner compensation did not collect its nft guard" >&2;exit 1
    fi
    echo "SUCCESS ORIGINAL_NFT_GUARD_HOST_COMPENSATION"
    if [[ "$original_case" == staged || "$original_case" == staged-tagged ]];then
      if ip netns exec alpha ip link show "$stage" >/dev/null 2>&1;then
        echo "original nonce-derived staging kernel object survived recovery" >&2;exit 1
      fi
      echo "SUCCESS ORIGINAL_STAGED_KERNEL_WG_CRASH_RECOVERY: $original_case"
      exit 0
    fi
  else
    # Historical R2 vacancy-only test with separate harness-owned cleanup.
    ip netns exec alpha /usr/sbin/nft delete table inet "$guard"
    invoke alpha link reconcile-wss-vacant "$link_id" --confirm "$link_id"
  fi
  jq -e '(.wss_crash_operations // []) | length==0' "$lab/alpha-state/state.json" >/dev/null
  invoke alpha link ensure --stdin < "$lab/alpha/recovery-ensure.json"
  echo "SUCCESS PRECOMMIT_NFT_HARD_CRASH_JOURNAL_VACANCY_AND_EXACT_RETRY"
else
  invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/receiver.json < "$lab/alpha/create.json"
fi
test -f "$lab/alpha-state/handoff/receiver.json"
invoke beta link preview-wss --stdin --json < "$lab/alpha-state/handoff/receiver.json" | tee "$lab/beta/preview.json"
confirm=$(grep -m1 '^{' "$lab/beta/preview.json" | jq -r .confirmation_sha256)
invoke beta link import-wss --stdin --confirm "$confirm" < "$lab/alpha-state/handoff/receiver.json"

if [[ -n "$(printenv STL_WSS_R2_DRIFT_TEST || :)" ]];then
  mode=$STL_WSS_R2_DRIFT_TEST
  case "$mode" in firewall|legacy|unit) ;; *) echo "unsupported drift mode" >&2;exit 2;;esac
  echo "WSS R2 EXISTING GUARD DRIFT INJECTION: $mode"
  jq -c '{"schema_version":3,"link":.links[0].desired}' "$lab/alpha-state/state.json" > "$lab/alpha/drift-ensure.json"
  case "$mode" in
    firewall)
      ip netns exec alpha /usr/sbin/nft -f - <<'NFT'
create table inet foreign_pre_wss
create chain inet foreign_pre_wss early_input { type filter hook input priority -350; policy accept; }
add rule inet foreign_pre_wss early_input meta l4proto udp counter accept
NFT
      ;;
    legacy) export STL_WSS_R2_LEGACY_DRIFT=1 ;;
    unit)
      python3 - "$lab/alpha/runtime/stl-wss-0123456789abcdef0123456789abcdef.service.json" <<'PYTHON'
import json,sys
p=sys.argv[1]
d=json.load(open(p))
d["properties"]["PrivateTmp"]="no"
with open(p,"w") as fp:json.dump(d,fp)
PYTHON
      ;;
  esac
  if invoke alpha link ensure --stdin <"$lab/alpha/drift-ensure.json" >"$lab/alpha/drift-ensure-denied.log" 2>&1;then
    echo "existing WSS guard bypassed foreign host drift" >&2;exit 1
  fi
  if invoke alpha link restore --all >"$lab/alpha/drift-restore-denied.log" 2>&1;then
    echo "WSS boot restore bypassed foreign host drift" >&2;exit 1
  fi
  export STL_R1_SIDE_ROOT="$lab/alpha"
  if [[ "$mode" == firewall ]];then
    ip netns exec alpha /usr/sbin/nft -j list table inet foreign_pre_wss >/dev/null
    ip netns exec alpha /usr/sbin/nft delete table inet foreign_pre_wss
  elif [[ "$mode" == legacy ]];then
    unset STL_WSS_R2_LEGACY_DRIFT
  else
    systemctl show stl-wss-0123456789abcdef0123456789abcdef.service | grep -q '^PrivateTmp=no'
  fi
  guard=$(python3 -c 'import hashlib;print("stlwss_"+hashlib.sha256(b"lnk_0123456789abcdef0123456789abcdef").hexdigest()[:16])')
  ip netns exec alpha /usr/sbin/nft -j list table inet "$guard" >/dev/null
  echo "DENY_PASS EXISTING_GUARD_FIREWALL_OR_UNIT_DRIFT: $mode"
  exit 0
fi

echo "INTERFACES:"
ip netns exec alpha ip -brief addr
ip netns exec beta ip -brief addr
echo "WG STATUS:"
ip netns exec alpha wg show
ip netns exec beta wg show
echo "WG UDP, WSS TCP sockets before traffic:"
ip netns exec beta ss -unp | head -25
ip netns exec alpha ss -lntp | head -20
echo "LINK ICMP:"
sleep 7
ip netns exec beta ping -I 10.75.0.2 -c 3 -W 3 10.75.0.1
ip netns exec alpha ping -I 10.75.0.1 -c 3 -W 3 10.75.0.2
echo "SUCCESS REAL ICMP WSS+WG"
echo "WSS KERNEL HANDSHAKE:"
ip netns exec alpha wg show stlwg0123456789 latest-handshakes
ip netns exec beta wg show stlwg0123456789 latest-handshakes
echo "WSS REAL TCP:"
ip netns exec alpha python3 -m http.server 39080 --bind 10.75.0.1 --directory /lab/alpha > "$lab/alpha/tcp.log" 2>&1 &
tcp_pid=$!
sleep 0.4
ip netns exec beta curl --fail --silent --show-error --interface 10.75.0.2 --max-time 8 \
  "http://10.75.0.1:39080/create.json" | jq -e '.schema_version==1 and .tcp_port==59443' >/dev/null
kill "$tcp_pid" 2>/dev/null || :
wait "$tcp_pid" 2>/dev/null || :
echo "SUCCESS REAL TCP FORWARDED VIA WSS WG"
echo "WSS REAL UDP:"
ip netns exec alpha python3 -u -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(12);s.bind(("10.75.0.1",39081));d,p=s.recvfrom(1024);s.sendto(d+b"/ack",p);s.close()' > "$lab/alpha/udp.log" 2>&1 &
udp_pid=$!
sleep 0.3
ip netns exec beta python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("10.75.0.2",0));s.settimeout(7);s.sendto(b"actual-udp",("10.75.0.1",39081));d,p=s.recvfrom(1024);assert d==b"actual-udp/ack",d;print("SUCCESS REAL UDP ACK FROM",p);s.close()'
wait "$udp_pid"
echo "WSS DIAGNOSTICS FROM STL:"
invoke alpha link diagnose-wss lnk_0123456789abcdef0123456789abcdef --json
invoke beta link diagnose-wss lnk_0123456789abcdef0123456789abcdef --json
echo "WSS NEGATIVE mTLS/BEARER/PATH:"
for rejected in no-mtls wrong-bearer wrong-path; do
  ip netns exec beta python3 /lab/wss-negative-probe.py "$rejected"
done
echo "DIRECT PUBLIC WIREGUARD UDP MUST BE REJECTED:"
guard=$(python3 -c 'import hashlib;print("stlwss_"+hashlib.sha256(b"lnk_0123456789abcdef0123456789abcdef").hexdigest()[:16])')
rule_packets(){
 ip netns exec alpha nft -j list table inet "$guard" | jq '[.nftables[]|.rule?.expr[]?.counter?.packets // empty] | add // 0'
}
before=$(rule_packets)
ip netns exec beta python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b"direct-public-udp",("198.51.100.21",51821));s.close()'
sleep 0.1
after=$(rule_packets)
echo "guard_before=$before guard_after=$after"
if (( after <= before )); then echo "direct UDP was not confirmed blocked" >&2; exit 1; fi
echo "SUCCESS PUBLIC WG UDP DROP VERIFIED"
echo "WSS RESTART AFTER CRASH:"
beta_service="$lab/beta/runtime/stl-wss-0123456789abcdef0123456789abcdef.service.json"
pid=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pid"])' "$beta_service")
kill -9 "$pid"
sleep 0.3
jq -c '{"schema_version":3,"link":.links[0].desired}' "$lab/beta-state/state.json" > "$lab/beta/ensure.json"
if [[ $(printenv STL_WSS_R3_REPAIR_TEST || :) == 1 ]];then
  echo "R3 COMMITTED LINK HELPER REPAIR CRASH"
  if invoke beta link ensure --stdin < "$lab/beta/ensure.json" > "$lab/beta/committed-repair-killed.log" 2>&1;then
    echo "helper repair unexpectedly completed despite hard kill" >&2;exit 1
  fi
  jq -e '(.links|length)==1 and (.wss_crash_operations|length)==1 and .wss_crash_operations[0].operation=="ensure" and .wss_crash_operations[0].had_committed_link==true' "$lab/beta-state/state.json" >/dev/null
  original_nonce=$(jq -r '.links[0].wss_original_object_nonce' "$lab/beta-state/state.json")
  if invoke beta link restore --all > "$lab/beta/repair-restore-denied.log" 2>&1;then
    echo "unsafe committed repair was replayed on RestoreAll" >&2;exit 1
  fi
  if invoke beta link reconcile-wss-vacant lnk_0123456789abcdef0123456789abcdef --confirm lnk_0123456789abcdef0123456789abcdef > "$lab/beta/repair-wrong-mode-denied.log" 2>&1;then
    echo "initial-Ensure recovery accepted committed repair" >&2;exit 1
  fi
  invoke beta link reconcile-wss-original lnk_0123456789abcdef0123456789abcdef --confirm lnk_0123456789abcdef0123456789abcdef
  jq -e '(.links|length)==1 and (.wss_crash_operations//[]|length)==0' "$lab/beta-state/state.json" >/dev/null
  test "$(jq -r '.links[0].wss_original_object_nonce' "$lab/beta-state/state.json")" == "$original_nonce"
  if invoke beta link reconcile-wss-original lnk_0123456789abcdef0123456789abcdef --confirm lnk_0123456789abcdef0123456789abcdef > "$lab/beta/repair-repeat-denied.log" 2>&1;then
    echo "repeat original repair recovery falsely found a journal" >&2;exit 1
  fi
  invoke beta link restore --all
  echo "SUCCESS ORIGINAL_COMMITTED_WSS_REPAIR_CRASH_AND_RESTORE_ALL"
else
  invoke beta link ensure --stdin < "$lab/beta/ensure.json"
fi
sleep 7
ip netns exec beta ping -I 10.75.0.2 -c 2 -W 3 10.75.0.1
echo "SUCCESS HELPER CRASH RECOVERED BY STL ENGINE"
# A failed/restarting transient unit is still an owned resource. Remove
# must stop/collect it, not mistake an inactive process for absent service
# and prematurely retire the private TLS material.
crash_unit="$lab/beta/runtime/stl-wss-0123456789abcdef0123456789abcdef.service.json"
crash_pid=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pid"])' "$crash_unit")
kill -9 "$crash_pid"
sleep 0.15
[[ -f $crash_unit ]] || { echo "expected a failed-but-loaded transient unit"; exit 1; }
echo "WSS REMOVE AFTER FAILED HELPER:"
if [[ -n "$(printenv STL_WSS_R2_REMOVE_CRASH_TEST || :)" ]];then
  case "$STL_WSS_R2_REMOVE_CRASH_TEST" in
    stop|guard) ;;
    *) echo "unsupported isolated Remove crash point";exit 2;;
  esac
  point=$STL_WSS_R2_REMOVE_CRASH_TEST
  export STL_R1_SIDE_ROOT="$lab/alpha"
  echo "WSS R2: CRASH DURING REMOVE AT $point"
  id=lnk_0123456789abcdef0123456789abcdef
  if invoke alpha link remove "$id" --confirm "$id" > "$lab/alpha/remove-hard-crash.log" 2>&1;then
    echo "interrupted WSS Remove unexpectedly completed";exit 1
  fi
  jq -e '(.links|length)==1 and .wss_crash_operations[0].operation=="remove" and .wss_crash_operations[0].had_committed_link==true' "$lab/alpha-state/state.json" >/dev/null
  if invoke alpha link remove "$id" --confirm "$id" > "$lab/alpha/remove-retry-denied.log" 2>&1;then
    echo "replayed ambiguous WSS Remove";exit 1
  fi
  if invoke alpha link reconcile-wss-vacant "$id" --confirm "$id" > "$lab/alpha/remove-vacancy-denied.log" 2>&1;then
    echo "vacancy-only recovery erased committed WSS Remove history";exit 1
  fi
  if [[ $(printenv STL_WSS_R3_ORIGINAL_TEST || :) == 1 ]];then
    invoke alpha link reconcile-wss-original "$id" --confirm "$id"
    if invoke alpha link reconcile-wss-original "$id" --confirm "$id" > "$lab/alpha/original-repeat-denied.log" 2>&1;then
      echo "interrupted Remove recovery repeated after receipt publication" >&2;exit 1
    fi
    jq -e '(.links|length)==0 and (.wss_crash_operations//[]|length)==0 and (.removal_receipts|length)==1' "$lab/alpha-state/state.json" >/dev/null
    invoke alpha link retire-wss "$id" --confirm "$id"
    jq -e '.removal_receipts[0].retired==true' "$lab/alpha-state/state.json" >/dev/null
    test ! -e "$lab/alpha-state/credentials/wss/$id"
    if ip netns exec alpha ip link show stlwg0123456789 >/dev/null 2>&1 ||
      ip netns exec alpha /usr/sbin/nft list table inet "$guard" >/dev/null 2>&1;then
      echo "original Remove left kernel/guard objects live" >&2;exit 1
    fi
    echo "SUCCESS ORIGINAL_INTERRUPTED_COMMITTED_REMOVE_RECOVERED: $point"
    exit 0
  fi
  if [[ "$point" == stop ]];then
    if invoke alpha link reconcile-wss-removed "$id" --confirm "$id" > "$lab/alpha/stop-vacancy-denied.log" 2>&1;then
      echo "completed Remove while live kernel WG and ingress guard remain";exit 1
    fi
    ip netns exec alpha ip link show stlwg0123456789 >/dev/null
    guard=$(python3 -c 'import hashlib;print("stlwss_"+hashlib.sha256(b"lnk_0123456789abcdef0123456789abcdef").hexdigest()[:16])')
    ip netns exec alpha /usr/sbin/nft -j list table inet "$guard" >/dev/null
  else
    if ip netns exec alpha ip link show stlwg0123456789 >/dev/null 2>&1;then
      echo "kernel WG lingered after final remove phase";exit 1
    fi
    invoke alpha link reconcile-wss-removed "$id" --confirm "$id"
    jq -e '(.links|length)==0 and (.wss_crash_operations//[]|length)==0 and (.removal_receipts|length)==1 and (.removal_receipts[0].retired//false)==false' "$lab/alpha-state/state.json" >/dev/null
    invoke alpha link retire-wss "$id" --confirm "$id"
    jq -e '.removal_receipts[0].retired==true' "$lab/alpha-state/state.json" >/dev/null
    test ! -e "$lab/alpha-state/credentials/wss/$id"
    echo "SUCCESS EXACT_HOST_VACANT_COMMITTED_REMOVE_AND_ORIGINAL_CREDENTIAL_RETIREMENT"
  fi
  echo "SUCCESS HARD_CRASH_COMMITTED_WSS_REMOVE_JOURNAL_QUARANTINE: $point"
  exit 0
fi

echo "WSS SCOPED REMOVAL:"
id=lnk_0123456789abcdef0123456789abcdef
# This is an isolated, test-owned noncredential file to force a committed
# Remove receipt with pending retirement. Never touch a real host State.
alpha_unit="$lab/alpha/runtime/stl-wss-0123456789abcdef0123456789abcdef.service.json"
alpha_saved="$lab/alpha/test-only-original-transient-unit.json"
cp -- "$alpha_unit" "$alpha_saved"
test_owned_blocker="$lab/alpha-state/credentials/wss/$id/owned-test-retirement-blocker"
printf 'isolated-test-only\n' > "$test_owned_blocker"
chmod 0600 "$test_owned_blocker"
invoke beta link remove "$id" --confirm "$id"
if invoke alpha link remove "$id" --confirm "$id" > "$lab/alpha/pending-retirement-expected.log" 2>&1;then
    echo "FAIL: test-only unexpected private file did not block immediate credential retirement" >&2;exit 1
fi
jq -e '(.links|length)==0 and (.removal_receipts|length)==1 and (.removal_receipts[0].retired//false)==false' "$lab/alpha-state/state.json" >/dev/null
test -d "$lab/alpha-state/credentials/wss/$id"
rm -- "$test_owned_blocker"
test ! -e "$alpha_unit"
python3 - "$alpha_saved" "$alpha_unit" <<'PYTHON'
import json,sys
d=json.load(open(sys.argv[1]))
d["pid"]=-1
with open(sys.argv[2],"w") as f:json.dump(d,f)
PYTHON
chmod 0600 "$alpha_unit"
if invoke alpha link retire-wss "$id" --confirm "$id" > "$lab/alpha/failed-loaded-retire-denied.log" 2>&1;then
    echo "FAIL: failed-but-loaded exact helper permitted credential retirement" >&2;exit 1
fi
test -d "$lab/alpha-state/credentials/wss/$id"
rm -- "$alpha_unit"
echo "DENY_PASS FAILED_BUT_LOADED_HELPER_BLOCKS_PENDING_CREDENTIAL_RETIREMENT"
if ip netns exec alpha ip link show stlwg0123456789 >/dev/null 2>&1 ||
  ip netns exec beta ip link show stlwg0123456789 >/dev/null 2>&1; then
   echo "FAILED WG interface cleanup" >&2; exit 1
fi
if ip netns exec alpha nft list table inet "$guard" >/dev/null 2>&1 ||
  ip netns exec beta nft list table inet "$guard" >/dev/null 2>&1; then
   echo "FAILED nft guard cleanup" >&2; exit 1
fi
# Consumed receipt is an idempotent READ-ONLY success when absent.
for side in alpha beta; do
  invoke "$side" link retire-wss "$id" --confirm "$id"
  invoke "$side" link retire-wss "$id" --confirm "$id"
done
# The receipt MUST NOT delete new files if a retired identity reappears.
reappeared="$lab/alpha-state/credentials/wss/$id"
mkdir -m 0700 "$reappeared"
printf 'do-not-delete\n' > "$reappeared/client-key.pem"
chmod 0600 "$reappeared/client-key.pem"
if invoke alpha link retire-wss "$id" --confirm "$id" > "$lab/alpha/retire-denied.log" 2>&1; then
  echo "FAIL: consumed WSS receipt deleted or accepted new private material" >&2
  exit 1
fi
[[ $(cat "$reappeared/client-key.pem") == do-not-delete ]] ||
  { echo "FAIL: consumed receipt touched reappeared private material" >&2; exit 1; }
echo "DENY_PASS retired-identity-material-preserved"
rm -- "$reappeared/client-key.pem"
rmdir -- "$reappeared"
for side in alpha beta; do
  remaining=$(find "$lab/$side-state/credentials" -type f | wc -l)
  [[ $remaining == 0 ]] || { echo "WSS private material remained on $side after canonical Remove" >&2; exit 1; }
  jq -e '.removal_receipts[0].backend=="wireguard-wss" and .removal_receipts[0].retired==true' "$lab/$side-state/state.json" >/dev/null || exit 1
done
echo "SUCCESS MANAGED WSS LINK CREATE, ICMP, TCP, UDP, DIRECT-UDP-DROP, CRASH-REPAIR, RETIRE SECRETS, AND REMOVE"
