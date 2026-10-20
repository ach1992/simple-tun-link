#!/usr/bin/env bash
# Explicit, opt-in upstream acceptance for STL's WSS command/policy template.
# Runs with a verified official wstunnel v11.0.0 binary inside a new
# unprivileged user+network namespace: NEVER binds real host interfaces.
# This is NOT a WireGuard/STL-managed Link, install, or deployment.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

if [[ "${1:-}" == "--inside" ]]; then
  test "$#" -eq 3 || exit 2
  bin="$2"; tmp="$3"
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
    local who="$1" local_port="$2" dst="$3" ca_bundle="${4:-ca.pem}"
    SSL_CERT_FILE="$ca_bundle" timeout 35s "$bin" client \
      --tls-verify-certificate --tls-certificate "$who.pem" \
      --tls-private-key "$who.key" \
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
  launch_udp other 53002 53000
  python3 check.py 53002 deny
  launch_udp evil 53003 53000
  python3 check.py 53003 deny
  launch_udp good 53004 53009
  python3 check.py 53004 deny
  launch_udp good 53005 53000 evil-ca.pem
  python3 check.py 53005 deny

  SSL_CERT_FILE=ca.pem timeout 15s "$bin" client \
    --tls-verify-certificate --tls-certificate good.pem \
    --tls-private-key good.key \
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
[[ "$bin" = /* && -f "$bin" && ! -L "$bin" ]] || { echo 'Trusted binary must be an absolute regular file' >&2; exit 2; }
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo 'Malformed binary SHA-256' >&2; exit 2; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo 'Acceptance is currently pinned to Linux x86_64' >&2; exit 2; }
# SHA-256 of the actual executable extracted from the official v11.0.0
# linux_amd64.tar.gz, itself checked against release checksums.txt.
readonly pinned=6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49
[[ "$expected" == "$pinned" && "$(sha256sum "$bin" | awk '{print $1}')" == "$pinned" ]] || {
  echo 'Binary does not match pinned upstream wstunnel v11.0.0' >&2
  exit 2
}
[[ "$("$bin" --version)" == 'wstunnel-cli 11.0.0' ]] || {
  echo 'Unexpected upstream executable version' >&2
  exit 2
}
command -v unshare >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null
command -v ip >/dev/null
command -v ss >/dev/null

tmp=$(mktemp -d "${TMPDIR:-/var/tmp}/stl-wss-v11-XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
umask 077
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
for who in good other evil; do
  case "$who" in
    other) name=stlaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
    *) name="$CN" ;;
  esac
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$name" \
    -keyout "$who.key" -out "$who.csr" >/dev/null 2>&1
  if [[ "$who" == evil ]]; then ca=evil-ca; else ca=ca; fi
  openssl x509 -req -in "$who.csr" -CA "$ca.pem" -CAkey "$ca.key" \
    -CAcreateserial -days 2 -sha256 -extfile client.ext -out "$who.pem" >/dev/null 2>&1
done
cp "$repo/internal/carrier/wss/testdata/restrictions-v11.yaml" "$tmp/restrictions.yaml"
# The main Go unit suite also asserts the fixture is identical to Build output.
unshare -Urn "$repo/scripts/e2e/wss-v11-compat.sh" --inside "$bin" "$tmp"
