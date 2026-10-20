#!/usr/bin/env bash
# Explicit, opt-in upstream acceptance for STL's WSS command/policy template.
# Runs with a verified official wstunnel v11.0.0 binary inside a new
# unprivileged user+network namespace: NEVER binds real host interfaces.
# This is NOT a WireGuard/STL-managed Link, install, or deployment.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

# Both public and internal entrypoints must independently reject a different
# binary/version before any network or namespace mutation.
readonly pinned=6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49
verify_pinned() {
  local candidate="$1"
  [[ "$candidate" = /* && -f "$candidate" && ! -L "$candidate" ]] || {
    echo 'Expected a regular absolute, non-symlink wstunnel executable' >&2; exit 2;
  }
  [[ "$(sha256sum "$candidate" | awk '{print $1}')" == "$pinned" ]] || {
    echo 'Not the approved upstream wstunnel v11.0.0 executable' >&2; exit 2;
  }
  [[ "$("$candidate" --version)" == 'wstunnel-cli 11.0.0' ]] || {
    echo 'Wrong wstunnel upstream version' >&2; exit 2;
  }
}
isolated_namespace_required() {
  local fixture="$1" own_user own_net base_user base_net guard uidmap
  # This capability is an accidental-host-mutation safety gate, NOT a
  # privileged sandbox for untrusted callers. The normal entrypoint writes
  # the parent namespace IDs and an unpredictable nonce to a private 0700
  # fixture before invoking unshare -Urn. An unauthenticated direct --inside
  # call must fail before the first IP operation.
  [[ "$(id -u)" == 0 ]] || { echo 'Namespace test requires unshared root mapping' >&2; exit 2; }
  [[ -f "$fixture/parent-namespaces" && ! -L "$fixture/parent-namespaces" &&
     -f "$fixture/namespace-guard" && ! -L "$fixture/namespace-guard" ]] || {
    echo 'WSS test namespace parent evidence missing' >&2; exit 2;
  }
  guard=$(cat "$fixture/namespace-guard")
  [[ -n "$guard" && "${STL_WSS_ACCEPTANCE_NSGUARD:-}" == "$guard" ]] || {
    echo 'WSS internal test cannot prove parent launcher authorization' >&2; exit 2;
  }
  base_user=$(sed -n '1p' "$fixture/parent-namespaces")
  base_net=$(sed -n '2p' "$fixture/parent-namespaces")
  own_user=$(readlink /proc/self/ns/user)
  own_net=$(readlink /proc/self/ns/net)
  uidmap=$(awk 'NF==3 && $1=="0" && $3=="1" {n++} END{print n+0}' /proc/self/uid_map)
  [[ -n "$own_user" && -n "$own_net" && -n "$base_user" && -n "$base_net" &&
     "$own_user" != "$base_user" && "$own_net" != "$base_net" &&
     "$uidmap" == 1 ]] || {
    echo 'WSS internal test is not in a mapped, fresh user/net namespace' >&2
    exit 2
  }
}

if [[ "${1:-}" == "--inside" ]]; then
  test "$#" -eq 3 || exit 2
  readonly CN=stl0123456789abcdef0123456789abcdef
  bin="$2"; tmp="$3"
  verify_pinned "$bin"
  isolated_namespace_required "$tmp"
  [[ -d "$tmp" && ! -L "$tmp" ]] || { echo 'Untrusted test fixture directory' >&2; exit 2; }
  cd "$tmp"
  ip link set lo up
  # Documentation-only physical underlay endpoints, local to this netns.
  ip addr add 198.51.100.21/32 dev lo
  ip addr add 203.0.113.34/32 dev lo
  pids=()
  cleanup_ns() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || :; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || :; done
  }
  trap cleanup_ns EXIT

  # Prove BOTH permitted and forbidden UDP destinations are reachable within
  # the namespace; denial is therefore not a missing-socket false positive.
  cat > echo.py <<'PY'
import select, socket
udp = []
for port in (53000, 53009):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    udp.append(s)
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("127.0.0.1", 53000))
tcp.listen(6)
while True:
    ready, _, _ = select.select(udp + [tcp], [], [])
    for s in ready:
        if s is tcp:
            peer, _ = tcp.accept()
            with peer:
                peer.settimeout(1)
                try:
                    data = peer.recv(4096)
                    peer.sendall(b"echo-" + data)
                except (TimeoutError, OSError):
                    pass
        else:
            data, addr = s.recvfrom(65535)
            s.sendto(b"echo-" + data, addr)
PY
  python3 echo.py >echo.log 2>&1 &
  pids+=("$!")
  timeout 50s "$bin" server \
    --tls-certificate server.pem \
    --tls-private-key server.key \
    --tls-client-ca-certs ca.pem \
    --restrict-config restrictions.yaml \
    wss://198.51.100.21:59443 >server.log 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 40); do
    if ss -lnt | grep -q '198.51.100.21:59443'; then break; fi
    sleep 0.1
  done
  if ! ss -lnt | grep -q '198.51.100.21:59443'; then
    echo 'WSS server did not listen in isolated namespace' >&2
    tail -n 14 server.log >&2
    exit 1
  fi
  launch_udp() {
    local who="$1" local_port="$2" dst="$3" ca_bundle="${4:-ca.pem}" auth_file="${5:-authorization-headers}"
    local -a extra=()
    if [[ "$auth_file" != none ]]; then extra+=(--http-headers-file "$auth_file"); fi
    if [[ "$who" == missingcn ]]; then
      # Explicitly force the otherwise authorized path even when upstream
      # cannot extract a CN. The server's bearer rule MUST still reject
      # this trusted-CA credential when it lacks the Link secret.
      extra+=(--http-upgrade-path-prefix "$CN")
    fi
    SSL_CERT_FILE="$ca_bundle" timeout 35s "$bin" client \
      --tls-verify-certificate --tls-certificate "$who.pem" \
      --tls-private-key "$who.key" "${extra[@]}" \
      -L "udp://127.0.0.1:$local_port:127.0.0.1:$dst?timeout_sec=0" \
      wss://198.51.100.21:59443 >"$who.$local_port.log" 2>&1 &
    pids+=("$!")
    sleep 0.2
  }
  cat > check.py <<'PY'
import socket, sys, time
port, allow = int(sys.argv[1]), sys.argv[2] == "allow"
deadline = time.monotonic() + (8 if allow else 3)
response = False
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(0.25)
    while time.monotonic() < deadline:
        sock.sendto(b"stl-v11-test", ("127.0.0.1", port))
        try:
            data, _ = sock.recvfrom(65535)
            if data == b"echo-stl-v11-test":
                response = True
                break
        except TimeoutError:
            pass
if response != allow:
    raise SystemExit("Unexpected WSS policy result: UDP %s" % port)
print("ALLOW_PASS" if allow else "DENY_PASS", port)
PY
  launch_udp good 53001 53000
  python3 check.py 53001 allow
  # The other trusted certificate has the correct bearer, but its
  # DIFFERENT CN is still rejected by the upstream path restriction.
  launch_udp other 53002 53000
  python3 check.py 53002 deny
  launch_udp evil 53003 53000
  python3 check.py 53003 deny
  launch_udp good 53004 53009
  python3 check.py 53004 deny
  launch_udp good 53005 53000 evil-ca.pem
  python3 check.py 53005 deny
  # Reviewer REQUIRED-01: trusted CA, missing CN, explicitly authorized
  # upgrade path, but WITHOUT the independent private Link secret.
  prior_denials=$(grep -ci 'not allowed destination' server.log || true)
  launch_udp missingcn 53007 53000 ca.pem none
  python3 check.py 53007 deny
  later_denials=$(grep -ci 'not allowed destination' server.log || true)
  if (( later_denials <= prior_denials )); then
    echo 'Missing-CN request did not prove rejection by server policy' >&2
    exit 1
  fi
  # The same trusted missing-CN leaf must also fail with the wrong
  # per-Link token even though it requests the legitimate upgrade path.
  prior_denials=$later_denials
  launch_udp missingcn 53008 53000 ca.pem authorization-headers-wrong
  python3 check.py 53008 deny
  later_denials=$(grep -ci 'not allowed destination' server.log || true)
  if (( later_denials <= prior_denials )); then
    echo 'Wrong bearer did not prove rejection by server policy' >&2
    exit 1
  fi

  SSL_CERT_FILE=ca.pem timeout 15s "$bin" client \
    --tls-verify-certificate --tls-certificate good.pem \
    --tls-private-key good.key \
    --http-headers-file authorization-headers \
    -L "tcp://127.0.0.1:53006:127.0.0.1:53000" \
    wss://198.51.100.21:59443 >tcp.log 2>&1 &
  pids+=("$!")
  sleep 0.4
  python3 - <<'PY'
import socket, time
deadline = time.monotonic() + 3
data = None
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", 53006), timeout=0.5) as conn:
            conn.settimeout(0.5)
            conn.sendall(b"stl-v11-test")
            try:
                data = conn.recv(4096)
            except (TimeoutError, OSError):
                pass
        if data == b"echo-stl-v11-test":
            raise SystemExit("WSS unexpectedly allowed forbidden TCP protocol")
    except (ConnectionRefusedError, TimeoutError, OSError):
        pass
print("DENY_PASS TCP")
PY
  grep -qi 'not allowed destination' server.log || {
    echo "Missing server-side denial evidence" >&2
    exit 1
  }
  grep -qi 'UnknownIssuer' server.log || {
    echo "Missing mTLS unknown issuer rejection" >&2
    exit 1
  }
  echo 'WSTUNNEL_V11_PINNED_POLICY_ACCEPTANCE=PASS'
  exit 0
fi

if [[ "$#" -ne 2 ]]; then
  echo "Usage: $0 ABSOLUTE_VERIFIED_WSTUNNEL_V11_BINARY EXPECTED_SHA256" >&2
  exit 2
fi
bin="$1"; expected="$2"
verify_pinned "$bin"
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$expected" == "$pinned" ]] || {
  echo 'Unexpected or malformed SHA-256 expected by caller' >&2; exit 2;
}
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  echo 'This acceptance is pinned to Linux amd64' >&2; exit 2;
}
command -v unshare >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null
command -v ip >/dev/null
command -v ss >/dev/null

umask 077
tmp=$(mktemp -d "${TMPDIR:-/var/tmp}/stl-wss-v11-XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
# Captured by the *outer* process, not by the child. The child verifies
# that BOTH namespaces differ before any network operation.
printf '%s\n%s\n' "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)" > "$tmp/parent-namespaces"
guard=$(openssl rand -hex 16)
printf '%s\n' "$guard" > "$tmp/namespace-guard"
chmod 0600 "$tmp/parent-namespaces" "$tmp/namespace-guard"
cd "$tmp"
CN=stl0123456789abcdef0123456789abcdef
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -subj /CN=STL-test-CA -keyout ca.key -out ca.pem \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -subj /CN=STL-evil-CA -keyout evil-ca.key -out evil-ca.pem \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
cat >server.ext <<'EOF_SERVER'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:198.51.100.21
EOF_SERVER
cat >client.ext <<'EOF_CLIENT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF_CLIENT
openssl req -new -newkey rsa:2048 -nodes -subj /CN=stl-server \
  -keyout server.key -out server.csr >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 2 -sha256 -extfile server.ext -out server.pem >/dev/null 2>&1
for who in good other evil missingcn; do
  case "$who" in
    other) subject=/CN=stlaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
    missingcn) subject=/O=STL-no-client-CN ;;
    *) subject="/CN=$CN" ;;
  esac
  openssl req -new -newkey rsa:2048 -nodes -subj "$subject" \
    -keyout "$who.key" -out "$who.csr" >/dev/null 2>&1
  if [[ "$who" == evil ]]; then ca=evil-ca; else ca=ca; fi
  openssl x509 -req -in "$who.csr" -CA "$ca.pem" -CAkey "$ca.key" \
    -CAcreateserial -days 2 -sha256 -extfile client.ext -out "$who.pem" >/dev/null 2>&1
done
# TEST TOKEN ONLY. This constant is public and is not a production secret.
printf 'Authorization: Bearer %s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > authorization-headers
printf 'Authorization: Bearer %s\n' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' > authorization-headers-wrong
chmod 0600 authorization-headers authorization-headers-wrong
cp "$repo/internal/carrier/wss/testdata/restrictions-v11.yaml" "$tmp/restrictions.yaml"
# The main Go unit suite also asserts the fixture is identical to Build output.
STL_WSS_ACCEPTANCE_NSGUARD="$guard" unshare -Urn "$repo/scripts/e2e/wss-v11-compat.sh" --inside "$bin" "$tmp"
