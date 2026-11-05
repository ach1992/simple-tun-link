#!/usr/bin/env bash
# End-to-end mirror test. TLS server binds only loopback, all system effects
# stay in explicit temporary nondefault prefixes; no real system install/APT.
set -Eeuo pipefail
# This test intercepts sudo but the real bootstrap bypasses sudo under root.
# Reject privileged execution before allocating files, building or binding TLS.
if (( EUID == 0 )); then
  echo 'MIRROR_TEST_REFUSED: requires a non-root disposable test user; no host changes attempted.' >&2
  exit 77
fi
umask 077
repo=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
scratch=$(mktemp -d)
web_pid=
cleanup() {
  [[ -z $web_pid ]] || kill "$web_pid" 2>/dev/null || true
  [[ -z $web_pid ]] || wait "$web_pid" 2>/dev/null || true
  [[ ! -L $scratch ]] && rm -rf --one-file-system -- "$scratch"
}
trap cleanup EXIT
command -v go >/dev/null && command -v python3 >/dev/null &&
  command -v openssl >/dev/null && command -v curl >/dev/null || {
  echo 'go, python3, openssl and curl are needed for isolated mirror tests.' >&2; exit 1;
}
commit=$(git -C "$repo" rev-parse HEAD)
make_release() {
  local tag=$1 out=$2 arch name archive pkg
  mkdir -p "$out"
  for arch in amd64 arm64; do
    name="stl_${tag}_linux_$arch"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X github.com/ach1992/simple-tun-link/internal/version.Version=$tag -X github.com/ach1992/simple-tun-link/internal/version.Commit=$commit" \
      -o "$out/$name" ./cmd/stl
  done
  cp LICENSE "$out/LICENSE"
  cat > "$out/BUILD-MANIFEST.txt" <<EOF
project=simple-tun-link
executable=stl
license=MIT
version=$tag
commit=$commit
build_date=2026-11-03T00:00:00Z
platforms=linux/amd64 linux/arm64
source=https://github.com/ach1992/simple-tun-link
mode=tag
EOF
  for arch in amd64 arm64; do
    name="stl_${tag}_linux_$arch"
    archive="${name}_local-install.tar.gz"
    pkg="$scratch/package-$tag-$arch"
    mkdir -m 0700 -p "$pkg"
    cp "$repo/scripts/install.sh" "$pkg/install.sh"
    cp "$out/$name" "$out/LICENSE" "$out/BUILD-MANIFEST.txt" "$pkg/"
    printf 'Test fixture for %s\n' "$tag" > "$pkg/LOCAL-INSTALL.txt"
    (
      cd "$pkg"
      sha256sum -- "$name" install.sh LICENSE BUILD-MANIFEST.txt LOCAL-INSTALL.txt > SHA256SUMS
      tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
        -cf - "$name" install.sh LICENSE BUILD-MANIFEST.txt LOCAL-INSTALL.txt SHA256SUMS |
        gzip -n > "$out/$archive"
    )
  done
  bash scripts/render-stable-bootstrap.sh "$tag" "$out/stl-bootstrap.sh"
  ( cd "$out"; sha256sum -- stl_${tag}_linux_amd64 stl_${tag}_linux_arm64 \
    LICENSE stl-bootstrap.sh BUILD-MANIFEST.txt stl_${tag}_linux_amd64_local-install.tar.gz \
    stl_${tag}_linux_arm64_local-install.tar.gz > SHA256SUMS )
}
cd "$repo"
make_release v0.9.98 "$scratch/old-release"
make_release v0.9.99 "$scratch/new-release"

# A wrong independently trusted root must fail without any output.
bad="$(printf '%064d' 1)"
if bash scripts/prepare-mirror.sh --tag v0.9.99 \
   --release-dir "$scratch/new-release" --trusted-sums-sha256 "$bad" \
   --url https://localhost:8443 --output "$scratch/rejected" >/dev/null 2>&1; then
  echo 'MIRROR_TEST_FAIL: accepted untrusted official release checksums' >&2; exit 1
fi
[[ ! -e "$scratch/rejected" ]] ||
  { echo 'MIRROR_TEST_FAIL: rejected source produced files' >&2; exit 1; }
# A writable publication parent must not serve as the local trust anchor.
mkdir -m 0700 "$scratch/untrusted-publisher"
chmod 0777 "$scratch/untrusted-publisher"
valid_sums=$(sha256sum < "$scratch/new-release/SHA256SUMS")
valid_sums=${valid_sums%% *}
if bash scripts/prepare-mirror.sh --tag v0.9.99 \
   --release-dir "$scratch/new-release" --trusted-sums-sha256 "$valid_sums" \
   --url https://localhost:8443 \
   --output "$scratch/untrusted-publisher/rejected" >/dev/null 2>&1; then
  echo 'MIRROR_TEST_FAIL: accepted group/world-writable output parent' >&2; exit 1
fi
[[ ! -e "$scratch/untrusted-publisher/rejected" ]] ||
  { echo 'MIRROR_TEST_FAIL: unsafe output parent received a publication' >&2; exit 1; }

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -keyout "$scratch/cert.key" -out "$scratch/cert.crt" \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' >/dev/null 2>&1

# Serve an HTTPS mirror on the local loopback using a test-only CA.
cat > "$scratch/serve.py" <<'PY'
import http.server
import os
import ssl
import sys
import time
root, cert, key, port_path = sys.argv[1:]
class Handler(http.server.SimpleHTTPRequestHandler):
    def oversize(self, amount, chunked):
        self.send_response(200)
        if chunked:
            self.send_header('Transfer-Encoding', 'chunked')
        else:
            self.send_header('Content-Length', str(amount))
        self.end_headers()
        try:
            while amount:
                payload = b'X' * min(32768, amount)
                if chunked:
                    self.wfile.write(('%x\r\n' % len(payload)).encode('ascii') + payload + b'\r\n')
                else:
                    self.wfile.write(payload)
                amount -= len(payload)
            if chunked:
                self.wfile.write(b'0\r\n\r\n')
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        mode_path = os.path.join(os.path.dirname(root), 'mirror-downstream-mode')
        try:
            with open(mode_path, 'r', encoding='ascii') as stream:
                mode = stream.read().strip()
        except FileNotFoundError:
            mode = ''
        release = '/releases/v0.9.99/'
        if self.path == release + 'install.sh':
            if mode == 'canonical-oversize-known':
                self.oversize(1048577, False)
                return
            if mode == 'canonical-oversize-chunked':
                self.oversize(1048577, True)
                return
        if self.path == release + 'SHA256SUMS' and mode == 'sums-oversize-chunked':
            self.oversize(65537, True)
            return
        if self.path == release + 'BUILD-MANIFEST.txt' and mode == 'manifest-oversize-known':
            self.oversize(65537, False)
            return
        if self.path == release + 'stl_v0.9.99_linux_amd64' and mode == 'asset-tamper':
            self.oversize(1024, False)
            return
        if self.path == '/chunked-oversize.sh':
            self.send_response(200)
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            chunk = b'#!/bin/bash\n' + b'#' * 32768
            for _ in range(6):
                try:
                    self.wfile.write(('%x\r\n' % len(chunk)).encode('ascii') + chunk + b'\r\n')
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break
            return
        if self.path == '/nul-padded.sh':
            # Exactly 128KiB+1 bytes with many NULs. Bash command
            # substitution strips NUL; the first-hop filter must preserve
            # the original byte count and reject, not execute the prefix.
            prefix = b'#!/bin/bash\necho NUL_BYPASS\n'
            body = prefix + b'\000' * (131073 - len(prefix))
            self.send_response(200)
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            self.wfile.write(('%x\r\n' % len(body)).encode('ascii') + body + b'\r\n0\r\n\r\n')
            return
        if self.path in ('/newline-oversize.sh', '/newline-fit.sh',
                         '/official-newline-oversize.sh', '/official-newline-fit.sh'):
            # A successful HTTPS chunked response without Content-Length.
            # Capture a valid complete script followed by ONLY trailing LF.
            # A normal-size complete bootstrap must execute; 128KiB+1 must not.
            if self.path.startswith('/official-'):
                prefix = b'#!/usr/bin/env bash\nprintf "OFFICIAL_NEWLINE_FIXTURE_EXECUTED=PASS\\n"\n'
            else:
                with open(os.path.join(root, 'install.sh'), 'rb') as source:
                    prefix = source.read()
            target_size = 131073 if 'oversize' in self.path else 32768
            assert len(prefix) < target_size
            body = prefix + b'\n' * (target_size - len(prefix))
            assert len(body) == target_size and body[-1:] == b'\n'
            self.send_response(200)
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            for offset in range(0, len(body), 32768):
                chunk = body[offset:offset+32768]
                self.wfile.write(('%x\r\n' % len(chunk)).encode('ascii') + chunk + b'\r\n')
            self.wfile.write(b'0\r\n\r\n')
            return
        if self.path == '/stall.sh':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'#!/bin/bash\n')
            self.wfile.flush()
            time.sleep(4)
            try:
                self.wfile.write(b'echo INCOMPLETE_TRANSFER\n')
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        return super().do_GET()
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=root, **kwargs)
    def log_message(self, fmt, *args):
        pass
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
with open(port_path, 'w', encoding='ascii') as stream:
    stream.write(str(server.server_port))
server.serve_forever()
PY
# We need the allocated HTTPS port before rendering the pinned mirror URL.
mkdir -p "$scratch/www"
python3 "$scratch/serve.py" "$scratch/www" "$scratch/cert.crt" "$scratch/cert.key" "$scratch/port" &
web_pid=$!
for _ in {1..100}; do
  [[ ! -s "$scratch/port" ]] || break
  kill -0 "$web_pid" 2>/dev/null || { echo 'TLS test server died' >&2; exit 1; }
  sleep 0.05
done
[[ -s "$scratch/port" ]] || { echo 'TLS test server did not become ready' >&2; exit 1; }
port=$(cat "$scratch/port")
base="https://localhost:$port"
sum_digest=$(sha256sum "$scratch/new-release/SHA256SUMS" | awk '{print $1}')
bash scripts/prepare-mirror.sh --tag v0.9.99 \
   --release-dir "$scratch/new-release" --trusted-sums-sha256 "$sum_digest" \
   --url "$base" --output "$scratch/webroot" > "$scratch/prepared.log"
# A concurrent publication-path writer must not be able to change the
# checksum reported as trusted. A disposable wrapper alters the just-
# published file AFTER mv and BEFORE the preparer prints its pin.
mkdir -m 0700 "$scratch/publish-fixture-bin"
cat > "$scratch/publish-fixture-bin/mv" <<'MV_RACE'
#!/usr/bin/env bash
set -euo pipefail
/usr/bin/mv "$@"
if [[ ${!#} == "$STL_TEST_RACE_DEST" ]]; then
  printf '\n# post-publication attacker-controlled bytes\n' >> "$STL_TEST_RACE_DEST/install.sh"
fi
MV_RACE
chmod 0700 "$scratch/publish-fixture-bin/mv"
STL_TEST_RACE_DEST="$scratch/webroot-raced" PATH="$scratch/publish-fixture-bin:$PATH" \
  bash scripts/prepare-mirror.sh --tag v0.9.99 \
  --release-dir "$scratch/new-release" --trusted-sums-sha256 "$sum_digest" \
  --url "$base" --output "$scratch/webroot-raced" > "$scratch/prepared-raced.log"
trusted_staged=$(sha256sum < "$scratch/webroot/install.sh")
trusted_staged=${trusted_staged%% *}
raced_pin=$(sed -n 's/^BOOTSTRAP_SHA256=//p' "$scratch/prepared-raced.log")
tampered_published=$(sha256sum < "$scratch/webroot-raced/install.sh")
tampered_published=${tampered_published%% *}
[[ $raced_pin == "$trusted_staged" && $tampered_published != "$raced_pin" ]] ||
  { echo 'MIRROR_TEST_FAIL: trust pin came from mutated publication path' >&2; exit 1; }
grep -F "$raced_pin" "$scratch/prepared-raced.log" >/dev/null ||
  { echo 'MIRROR_TEST_FAIL: prepared command used a nonstaged pin' >&2; exit 1; }
cp -a -- "$scratch/webroot/." "$scratch/www/"
cp -- "$scratch/webroot-raced/install.sh" "$scratch/www/post-publication-tamper.sh"
[[ -f "$scratch/www/install.sh" && -f "$scratch/www/releases/v0.9.99/install.sh" ]] ||
  { echo 'MIRROR_TEST_FAIL: expected static tree absent' >&2; exit 1; }
export CURL_CA_BUNDLE="$scratch/cert.crt"
export HTTPS_PROXY=http://127.0.0.1:9
export HTTP_PROXY=http://127.0.0.1:9
export ALL_PROXY=http://127.0.0.1:9
export NO_PROXY=localhost,127.0.0.1
export no_proxy="$NO_PROXY"
curl -fsS "$base/install.sh" -o "$scratch/fetched" || {
  echo 'MIRROR_TEST_FAIL: local TLS first hop unavailable' >&2; exit 1;
}
cmp "$scratch/fetched" "$scratch/www/install.sh"

# Intercept ONLY privilege elevation, and redirect the exact canonical
# invocation into an isolated test prefix. The canonical installer and
# actual TLS downloads are real (not a mocked download implementation).
mkdir -p "$scratch/bin"
cat > "$scratch/bin/sudo" <<'SUDO'
#!/usr/bin/env bash
set -Eeuo pipefail
# Test-only nonprivileged simulation. The actual root snapshot is separately
# exercised with the real sudo binary inside disposable package guests.
[[ ${1:-} == /usr/bin/env && ${2:-} == -i ]] || exit 87
args=("$@")
found=0
for ((i=0; i + 7 < ${#args[@]}; i++)); do
  if [[ ${args[i]} == stl && ${args[i+3]} =~ ^(install|update)$ &&
        ${args[i+4]} == --version && ${args[i+6]} == --backends ]]; then
    source=${args[i+1]}
    expected=${args[i+2]}
    command=("${args[@]:i+3}")
    found=1
    break
  fi
done
[[ $found == 1 ]] || exit 88
# Preserve the simulated root digest/copy boundary: in production it lives
# in /root with root ownership; this unprivileged guest checks a private copy.
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
head -c 1048577 -- "$source" > "$stage/install.sh"
[[ $(sha256sum < "$stage/install.sh") == "$expected  -" ]] || {
  echo 'STL_ROOT_SNAPSHOT_SHA256_MISMATCH' >&2
  exit 75
}
printf '%s\n' "${command[*]}" >> "$STL_MIRROR_SUDO_RECORD"
bash "$stage/install.sh" "${command[@]}" --prefix "$STL_MIRROR_PREFIX"
SUDO
chmod 0755 "$scratch/bin/sudo"
export PATH="$scratch/bin:$PATH"
export STL_MIRROR_SUDO_RECORD="$scratch/privileged-attempts"
export STL_MIRROR_PREFIX="$scratch/new-prefix"
mkdir -p "$STL_MIRROR_PREFIX/bin" "$STL_MIRROR_PREFIX/lib"
: > "$STL_MIRROR_SUDO_RECORD"

one_liner=$(grep -m1 '^/usr/bin/env -i HOME=/ .*stl.example.com/install.sh' "$repo/docs/MIRROR.md")
first_hop_sha=$(sed -n 's/^BOOTSTRAP_SHA256=//p' "$scratch/prepared.log")
[[ $first_hop_sha =~ ^[0-9a-f]{64}$ ]] ||
  { echo 'MIRROR_TEST_FAIL: preparer did not provide pinned first-hop checksum' >&2; exit 1; }
one_liner=${one_liner/https:\/\/stl.example.com/$base}
one_liner=${one_liner/TRUSTED_BOOTSTRAP_SHA256/$first_hop_sha}
[[ $one_liner == *"$base/install.sh"* ]] ||
  { echo 'MIRROR_TEST_FAIL: operator mirror command missing' >&2; exit 1; }
grep -Fx "INSTALL_COMMAND=$one_liner" "$scratch/prepared.log" >/dev/null ||
  { echo 'MIRROR_TEST_FAIL: prepared command differs from documented one-liner' >&2; exit 1; }
grep -Fx "UPDATE_COMMAND=$one_liner update" "$scratch/prepared.log" >/dev/null ||
  { echo 'MIRROR_TEST_FAIL: generated Update command differs from documented mirror flow' >&2; exit 1; }
# REAL literal clean-env first-hop regression: no BASH_ENV, exported shell
# function or caller PATH may act before the independently pinned digest.
# A trusted test-only CA/no-proxy is explicitly admitted after env -i.
literal_clean=${one_liner/\/bin\/bash -c /CURL_CA_BUNDLE=$scratch\/cert.crt NO_PROXY=localhost,127.0.0.1 \/bin\/bash -c }
printf '#!/bin/bash\nprintf "FIRST_HOP_CLEAN_ENV_POSITIVE=PASS\\n"\\n' > "$scratch/www/clean-fixture.sh"
clean_sha=$(sha256sum < "$scratch/www/clean-fixture.sh")
clean_sha=${clean_sha%% *}
clean_positive=${literal_clean/"$base/install.sh"/"$base/clean-fixture.sh"}
clean_positive=${clean_positive/"$first_hop_sha"/"$clean_sha"}
cat > "$scratch/poison-bash-env" <<EOF
#!/bin/bash
/usr/bin/touch "$scratch/poison-bash-env-executed"
EOF
cat > "$scratch/bin/curl" <<EOF
#!/bin/sh
/usr/bin/touch "$scratch/poison-path-curl-executed"
exit 91
EOF
chmod 0700 "$scratch/bin/curl"
# Exported function would have returned the expected digest even on a
# different payload if the mirror first-hop used a bare sha256sum lookup.
sha256sum() { printf '%s  -\\n' "$first_hop_sha"; }
export -f sha256sum
BASH_ENV="$scratch/poison-bash-env" /bin/sh -c "$clean_positive" > "$scratch/clean.out" 2> "$scratch/clean.err" ||
  { cat "$scratch/clean.err" >&2; echo 'MIRROR_TEST_FAIL: clean-env first-hop rejected trusted TLS test script' >&2; exit 1; }
grep -Fxq 'FIRST_HOP_CLEAN_ENV_POSITIVE=PASS' "$scratch/clean.out" ||
  { echo 'MIRROR_TEST_FAIL: clean-env positive bootstrap did not execute' >&2; exit 1; }
# Literal official first hop has no independent first-hop SHA pin (publisher
# trust remains out of band), but it must still ignore hostile inherited
# startup hooks, functions, and PATH before any Bash or download starts.
official_clean=$(grep -m1 '^/usr/bin/env -i HOME=/ .*stl-bootstrap.sh' "$repo/docs/INSTALL.md")
[[ -n $official_clean ]] || { echo 'MIRROR_TEST_FAIL: official literal missing' >&2; exit 1; }
official_clean=${official_clean/https:\/\/github.com\/ach1992\/simple-tun-link\/releases\/latest\/download\/stl-bootstrap.sh/$base\/official-newline-fit.sh}
official_clean=${official_clean/\/bin\/bash -c /CURL_CA_BUNDLE=$scratch\/cert.crt NO_PROXY=localhost,127.0.0.1 \/bin\/bash -c }
BASH_ENV="$scratch/poison-bash-env" /bin/sh -c "$official_clean" > "$scratch/official-clean.out" 2> "$scratch/official-clean.err" ||
  { cat "$scratch/official-clean.err" >&2; echo 'MIRROR_TEST_FAIL: official first hop inherited hostile environment' >&2; exit 1; }
grep -Fxq 'OFFICIAL_NEWLINE_FIXTURE_EXECUTED=PASS' "$scratch/official-clean.out" ||
  { echo 'MIRROR_TEST_FAIL: official literal clean-env positive not executed' >&2; exit 1; }
wrong_first_hop=${literal_clean/"$first_hop_sha"/"$(printf '%064d' 0)"}
if BASH_ENV="$scratch/poison-bash-env" /bin/sh -c "$wrong_first_hop" > "$scratch/poison.out" 2> "$scratch/poison.err"; then
  echo 'MIRROR_TEST_FAIL: inherited SHA function bypassed mirror first-hop pin' >&2; exit 1
fi
grep -q 'mirror bootstrap SHA256 mismatch' "$scratch/poison.err" ||
  { echo 'MIRROR_TEST_FAIL: clean-env negative missing pin diagnosis' >&2; exit 1; }
unset -f sha256sum
rm -- "$scratch/bin/curl"
[[ ! -e "$scratch/poison-bash-env-executed" &&
   ! -e "$scratch/poison-path-curl-executed" &&
   ! -s "$STL_MIRROR_SUDO_RECORD" ]] ||
  { echo 'MIRROR_TEST_FAIL: hostile inherited environment reached first hop or privileged operation' >&2; exit 1; }
echo 'LITERAL_MIRROR_ENV_I_BASH_ENV_FUNCTION_PATH_AND_PIN=PASS'
# For the non-root local TLS simulation, use a COPY of the same bootstrap
# with only sudo redirected to our fake shim. Keep the original authenticated
# prepared command intact above; this fixture never reaches publication.
sed 's|/usr/bin/sudo "${root_exec\[@\]}"|sudo "${root_exec[@]}"|' "$scratch/www/install.sh" > "$scratch/www/fixture-install.sh"
grep -Fq 'sudo "${root_exec[@]}"' "$scratch/www/fixture-install.sh"
fixture_sha=$(sha256sum < "$scratch/www/fixture-install.sh")
fixture_sha=${fixture_sha%% *}
one_liner=${one_liner/"$base/install.sh"/"$base/fixture-install.sh"}
one_liner=${one_liner/"$first_hop_sha"/"$fixture_sha"}
# Emulate network and privilege only in this unit harness. Literal clean-env
# entrypoints and root sudo are tested separately with real tool paths.
one_liner=${one_liner/\/usr\/bin\/env -i HOME=\/ PATH=\/usr\/sbin:\/usr\/bin:\/sbin:\/bin \/bin\/bash -c/\/bin\/bash -c}
# Execute an actual HTTPS fetch of the post-publication tampered bootstrap
# with the prepublication trusted pin. No sudo/canonical execution allowed.
raced_command=${one_liner/"$base/fixture-install.sh"/"$base/post-publication-tamper.sh"}
if bash -c "$raced_command" > "$scratch/race.out" 2> "$scratch/race.err"; then
  echo 'MIRROR_TEST_FAIL: accepted a changed published bootstrap' >&2; exit 1
fi
grep -q 'mirror bootstrap SHA256 mismatch' "$scratch/race.err" ||
  { echo 'MIRROR_TEST_FAIL: postpublication tamper had no integrity error' >&2; exit 1; }
[[ ! -s "$STL_MIRROR_SUDO_RECORD" && ! -e "$STL_MIRROR_PREFIX/bin/stl" ]] ||
  { echo 'MIRROR_TEST_FAIL: postpublication tamper crossed privilege boundary' >&2; exit 1; }
echo 'MIRROR_PRIVATE_PREPUBLICATION_PIN_AND_TAMPER_REFUSAL=PASS'
# Real TLS streaming tests: chunked payload with no Content-Length must
# be stopped at 128KiB+1 before any script is run. A stalled response must
# time out despite an initially valid shell prefix. No root/host mutation.
for fixture in "$base/newline-oversize.sh" "$base/official-newline-oversize.sh"; do
  raw_bytes=$(curl -fsS --max-time 20 "$fixture" | wc -c)
  [[ $raw_bytes == 131073 ]] ||
    { echo "MIRROR_TEST_FAIL: wire payload must be exactly 131073 bytes: $fixture ($raw_bytes)" >&2; exit 1; }
done
attempts=$(wc -l < "$STL_MIRROR_SUDO_RECORD")
oversize_cmd=${one_liner/"$base/fixture-install.sh"/"$base/chunked-oversize.sh"}
if bash -c "$oversize_cmd" > "$scratch/oversize.out" 2> "$scratch/oversize.err"; then
  echo 'MIRROR_TEST_FAIL: oversized chunked HTTPS response accepted' >&2; exit 1
fi
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: oversized first hop invoked privileged installer' >&2; exit 1; }
# The exact publicly documented official command must independently reject
# the same trailing-LF bypass. Only its first-hop URL is redirected to the
# isolated TLS fixture; the payload is deliberately harmless (no sudo).
official_url='https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh'
mapfile -t official_commands < <(grep '^/usr/bin/env -i HOME=/ .*stl-bootstrap.sh' "$repo/docs/INSTALL.md")
[[ ${#official_commands[@]} -eq 3 ]] ||
  { echo 'MIRROR_TEST_FAIL: expected three published official commands' >&2; exit 1; }
for official_line in "${official_commands[@]}"; do
  # These HTTPS fixtures need the locally trusted test-only CA. The trusted
  # operator command is otherwise unchanged (including the env -i boundary).
  official_line=${official_line/\/bin\/bash -c /CURL_CA_BUNDLE=$scratch\/cert.crt NO_PROXY=localhost,127.0.0.1 \/bin\/bash -c }
  official_bad=${official_line/"$official_url"/"$base/official-newline-oversize.sh"}
  [[ $official_bad == *"$base/official-newline-oversize.sh"* ]] ||
    { echo 'MIRROR_TEST_FAIL: official first-hop fixture substitution failed' >&2; exit 1; }
  if bash -c "$official_bad" > "$scratch/official-lf-bad.out" 2> "$scratch/official-lf-bad.err"; then
    echo 'MIRROR_TEST_FAIL: official literal command accepted 131073 trailing-LF bytes' >&2; exit 1
  fi
  ! grep -q 'OFFICIAL_NEWLINE_FIXTURE_EXECUTED' "$scratch/official-lf-bad.out" ||
    { echo 'MIRROR_TEST_FAIL: oversized official script executed' >&2; exit 1; }
  official_good=${official_line/"$official_url"/"$base/official-newline-fit.sh"}
  bash -c "$official_good" > "$scratch/official-lf-good.out" 2> "$scratch/official-lf-good.err" ||
    { echo 'MIRROR_TEST_FAIL: official literal command rejected valid within-cap trailing-LF bytes' >&2
      sed -n '1,12p' "$scratch/official-lf-good.err" >&2
      exit 1; }
  grep -Fx 'OFFICIAL_NEWLINE_FIXTURE_EXECUTED=PASS' "$scratch/official-lf-good.out" >/dev/null ||
    { echo 'MIRROR_TEST_FAIL: official within-cap fixture not executed' >&2; exit 1; }
done
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: official fixture invoked privileged installer' >&2; exit 1; }

# Generated mirror command and documented mirror command were already byte-
# checked against each other. Exercise their real pinned executable payload.
newline_bad_cmd=${one_liner/"$base/fixture-install.sh"/"$base/newline-oversize.sh"}
if bash -c "$newline_bad_cmd" > "$scratch/mirror-lf-bad.out" 2> "$scratch/mirror-lf-bad.err"; then
  echo 'MIRROR_TEST_FAIL: mirror accepted 131073 trailing-LF bytes' >&2; exit 1
fi
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: oversized newline-padded mirror reached sudo' >&2; exit 1; }
echo 'FIRST_HOP_NEWLINE_OVERFLOW_NO_EXECUTION=PASS'

nul_cmd=${one_liner/"$base/fixture-install.sh"/"$base/nul-padded.sh"}
if bash -c "$nul_cmd" > "$scratch/nul.out" 2> "$scratch/nul.err"; then
  echo 'MIRROR_TEST_FAIL: NUL-padded oversized chunked response was accepted' >&2; exit 1
fi
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: NUL-padded response invoked privileged installer' >&2; exit 1; }
! grep -q NUL_BYPASS "$scratch/nul.out" ||
  { echo 'MIRROR_TEST_FAIL: NUL-padded response executed its shell prefix' >&2; exit 1; }
stall_cmd=${one_liner/"$base/fixture-install.sh"/"$base/stall.sh"}
stall_cmd=${stall_cmd/"--max-time 45"/"--max-time 2"}
before_stall=$(date +%s)
if bash -c "$stall_cmd" > "$scratch/stall.out" 2> "$scratch/stall.err"; then
  echo 'MIRROR_TEST_FAIL: stalled HTTPS response accepted' >&2; exit 1
fi
duration=$(( $(date +%s) - before_stall ))
(( duration <= 9 )) ||
  { echo "MIRROR_TEST_FAIL: stalled transfer exceeded bounded timeout ($duration seconds)" >&2; exit 1; }
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: timed-out first hop invoked privileged installer' >&2; exit 1; }
echo 'MIRROR_FIRST_HOP_CHUNKED_SIZE_AND_TOTAL_TIMEOUT=PASS'

# Root refusal is executed before the first scratch dir is allocated. Verify
# this in the unprivileged test, without experimenting with real root.
guard_line=$(grep -n -m1 '^if (( EUID == 0 )); then' "$repo/scripts/test-mirror-install.sh" | cut -d: -f1)
scratch_line=$(grep -n -m1 '^scratch=$(mktemp -d)' "$repo/scripts/test-mirror-install.sh" | cut -d: -f1)
[[ $guard_line =~ ^[0-9]+$ && $scratch_line =~ ^[0-9]+$ ]] &&
  (( guard_line < scratch_line )) || {
  echo 'MIRROR_TEST_FAIL: root guard no longer precedes test setup' >&2; exit 1
}
echo 'MIRROR_ROOT_PREFLIGHT_BEFORE_EFFECTS=PASS'

# Inherited mirror values must not override release-pinned trusted arguments.
export STL_MIRROR_URL='https://attacker.invalid/releases/v0.9.99'
export STL_MIRROR_INSTALL_SHA=$(printf '%064d' 1)
export STL_MIRROR_SUMS_SHA=$(printf '%064d' 2)
bash -c "$one_liner" > "$scratch/install.out" 2> "$scratch/install.err" || {
  cat "$scratch/install.out" "$scratch/install.err"; echo 'MIRROR_TEST_FAIL: fresh install' >&2; exit 1;
}
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == 1 ]] ||
  { echo 'MIRROR_TEST_FAIL: not exactly one canonical privileged invocation' >&2; exit 1; }
# A within-limit, fully parseable response still MUST match the exact pinned
# bytes. Even harmless trailing LF is tampering at the first-hop trust boundary.
newline_good_cmd=${one_liner/"$base/fixture-install.sh"/"$base/newline-fit.sh"}
if bash -c "$newline_good_cmd" > "$scratch/mirror-lf-good.out" 2> "$scratch/mirror-lf-good.err"; then
  echo 'MIRROR_TEST_FAIL: modified first-hop accepted despite independent pin' >&2; exit 1
fi
grep -q 'mirror bootstrap SHA256 mismatch' "$scratch/mirror-lf-good.err" ||
  { echo 'MIRROR_TEST_FAIL: first-hop checksum rejection missing' >&2; exit 1; }
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == 1 ]] ||
  { echo 'MIRROR_TEST_FAIL: modified mirror first hop invoked privileged installer' >&2; exit 1; }
echo 'FIRST_HOP_WITHIN_LIMIT_PINNED_BYTES_ONLY=PASS'


# Edit ONLY the embedded digest constant of a separately served bootstrap.
# A well-formed shell file with a false pin cannot elevate privileges.
python3 - "$scratch/www/install.sh" "$scratch/www/bad-pins.sh" <<'PY_PINS'
from pathlib import Path
import re
import sys
src = Path(sys.argv[1]).read_text()
lines = src.splitlines(keepends=True)
assert re.search(r"'[0-9a-f]{64}'", lines[-1])
lines[-1] = re.sub(r"'[0-9a-f]{64}'", "'" + "0" * 64 + "'", lines[-1], count=1)
Path(sys.argv[2]).write_text("".join(lines))
PY_PINS
bad_pins_cmd=${one_liner/"$base/fixture-install.sh"/"$base/bad-pins.sh"}
# This controlled negative fixture pins its altered first hop independently,
# so the test can reach and exercise the canonical second-hop mismatch guard.
bad_pins_sha=$(sha256sum "$scratch/www/bad-pins.sh" | awk '{print $1}')
bad_pins_cmd=${bad_pins_cmd/"$fixture_sha"/"$bad_pins_sha"}
attempts=$(wc -l < "$STL_MIRROR_SUDO_RECORD")
if bash -c "$bad_pins_cmd" > "$scratch/bad-pin.out" 2> "$scratch/bad-pin.err"; then
  echo 'MIRROR_TEST_FAIL: invalid embedded SHA256 pin was accepted' >&2; exit 1
fi
grep -q 'differs from the independently pinned SHA256' "$scratch/bad-pin.err" ||
  { echo 'MIRROR_TEST_FAIL: wrong installer digest was not rejected at source' >&2; exit 1; }
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: invalid first-hop pin crossed the privilege boundary' >&2; exit 1; }

"$STL_MIRROR_PREFIX/bin/stl" version --json | grep -q '"version":"v0.9.99"'
sha_new=$(sha256sum "$STL_MIRROR_PREFIX/bin/stl" | awk '{print $1}')
bash -c "$one_liner" > "$scratch/repeat.out" 2> "$scratch/repeat.err" || {
  cat "$scratch/repeat.out" "$scratch/repeat.err"; echo 'MIRROR_TEST_FAIL: idempotent reinstall' >&2; exit 1;
}
[[ $(sha256sum "$STL_MIRROR_PREFIX/bin/stl" | awk '{print $1}') == "$sha_new" ]] ||
  { echo 'MIRROR_TEST_FAIL: same-version binary changed' >&2; exit 1; }

# Install old trusted release in another private prefix, then run WRONG
# 'install' against newer mirror. It must refuse and display safe Update.
export STL_MIRROR_PREFIX="$scratch/old-prefix"
mkdir -p "$STL_MIRROR_PREFIX/bin" "$STL_MIRROR_PREFIX/lib"
mkdir -p "$scratch/old-bundle"
cp "$scratch/old-release/BUILD-MANIFEST.txt" "$scratch/old-release/LICENSE" \
  "$scratch/old-release/SHA256SUMS" "$scratch/old-release/stl_v0.9.98_linux_amd64" \
  "$scratch/old-bundle/"
bash scripts/install.sh install --bundle "$scratch/old-bundle" \
  --prefix "$STL_MIRROR_PREFIX" --backends native,wireguard > "$scratch/old.out" 2> "$scratch/old.err"
before_old=$(sha256sum "$STL_MIRROR_PREFIX/bin/stl" | awk '{print $1}')
before_record=$(sha256sum "$STL_MIRROR_PREFIX/lib/simple-tun-link/install-record" | awk '{print $1}')
# The canonical successful install deliberately retains a durable COMMITTED
# journal until the next installer invocation reconciles it. A rejected
# oversized download must leave no NEW or UNCOMMITTED private staging.
preexisting_committed=$(find "$STL_MIRROR_PREFIX/bin" -maxdepth 1 -type d -name '.stl-install.*' -printf '%f\n')
# Real HTTPS downstream overflow/asset tamper cases. The first hop is
# independently authenticated and the canonical updater is entered, but
# bounded second/third-hop bytes must never exhaust temporary storage or
# replace the installed version. Both Content-Length and chunked flows run.
for failure_mode in canonical-oversize-known canonical-oversize-chunked \
                    sums-oversize-chunked manifest-oversize-known asset-tamper; do
  printf '%s\n' "$failure_mode" > "$scratch/mirror-downstream-mode.next"
  mv -f "$scratch/mirror-downstream-mode.next" "$scratch/mirror-downstream-mode"
  if bash -c "$one_liner update" > "$scratch/$failure_mode.out" 2> "$scratch/$failure_mode.err"; then
    echo "MIRROR_TEST_FAIL: accepted downstream $failure_mode" >&2
    exit 1
  fi
  case "$failure_mode" in
    canonical-oversize-known|canonical-oversize-chunked)
      grep -Eq '(1 MiB streaming limit|Mirror canonical installer unavailable, incomplete or oversized)' \
        "$scratch/$failure_mode.err" ||
        { cat "$scratch/$failure_mode.err" >&2; echo 'MIRROR_TEST_FAIL: canonical bound guidance missing' >&2; exit 1; } ;;
    sums-oversize-chunked)
      grep -Eq '(Mirror release asset exceeds the authenticated streaming-size limit|Required release file is unavailable on the HTTPS mirror)' "$scratch/$failure_mode.out" ||
        { cat "$scratch/$failure_mode.out" >&2; echo 'MIRROR_TEST_FAIL: chunked sums bound missing' >&2; exit 1; } ;;
    manifest-oversize-known)
      grep -q 'Required release file is unavailable on the HTTPS mirror' "$scratch/$failure_mode.out" ||
        { cat "$scratch/$failure_mode.out" >&2; echo 'MIRROR_TEST_FAIL: manifest bound missing' >&2; exit 1; } ;;
    asset-tamper)
      grep -q 'Release asset SHA256 mismatch' "$scratch/$failure_mode.out" ||
        { cat "$scratch/$failure_mode.out" >&2; echo 'MIRROR_TEST_FAIL: mirrored asset hash refusal missing' >&2; exit 1; } ;;
  esac
  [[ $(sha256sum "$STL_MIRROR_PREFIX/bin/stl" | awk '{print $1}') == "$before_old" &&
     $(sha256sum "$STL_MIRROR_PREFIX/lib/simple-tun-link/install-record" | awk '{print $1}') == "$before_record" ]] ||
    { echo "MIRROR_TEST_FAIL: $failure_mode changed binary/record" >&2; exit 1; }
  shopt -s nullglob
  remaining=("$STL_MIRROR_PREFIX/bin"/.stl-install.*)
  shopt -u nullglob
  for retained in "${remaining[@]}"; do
    [[ -d $retained && ! -L $retained && -f $retained/COMMITTED &&
       $(printf '%s\n' "$preexisting_committed" | grep -Fxc "${retained##*/}") == 1 ]] ||
      { echo "MIRROR_TEST_FAIL: $failure_mode retained a new/uncommitted private stage" >&2; exit 1; }
  done
done
rm -f "$scratch/mirror-downstream-mode"
echo 'MIRROR_DOWNSTREAM_HTTPS_KNOWN_CHUNKED_AND_TAMPER_BOUNDS=PASS'
if bash -c "$one_liner" > "$scratch/wrong.out" 2> "$scratch/wrong.err"; then
  echo 'MIRROR_TEST_FAIL: install incorrectly upgraded an existing version' >&2; exit 1
fi
grep -q '\[ACTION\].*v0.9.98.*v0.9.99.*mirror command with update' "$scratch/wrong.out" ||
  { cat "$scratch/wrong.out" "$scratch/wrong.err"; echo 'MIRROR_TEST_FAIL: explicit mirror Update guidance missing' >&2; exit 1; }
grep -q 'built-in Update menu requires GitHub' "$scratch/wrong.out" ||
  { cat "$scratch/wrong.out" "$scratch/wrong.err"; echo 'MIRROR_TEST_FAIL: actionable installed-version error missing' >&2; exit 1; }
[[ $(sha256sum "$STL_MIRROR_PREFIX/bin/stl" | awk '{print $1}') == "$before_old" ]] ||
  { echo 'MIRROR_TEST_FAIL: mistaken install changed existing binary' >&2; exit 1; }
# Explicit update uses the same first hop but changes the canonical action.
bash -c "$one_liner update" > "$scratch/update.out" 2> "$scratch/update.err" || {
  cat "$scratch/update.out" "$scratch/update.err"; echo 'MIRROR_TEST_FAIL: explicit Update failed' >&2; exit 1
}
"$STL_MIRROR_PREFIX/bin/stl" version --json | grep -q '"version":"v0.9.99"'

# Tampering with the mirrored canonical installer must be rejected BEFORE
# a privileged invocation. Restore the official bytes afterwards.
mv "$scratch/www/releases/v0.9.99/install.sh" "$scratch/untampered-installer"
printf '#!/bin/bash\necho STOLEN_SECRET\n' > "$scratch/www/releases/v0.9.99/install.sh"
attempts=$(wc -l < "$STL_MIRROR_SUDO_RECORD")
if bash -c "$one_liner" > "$scratch/tamper.out" 2> "$scratch/tamper.err"; then
  echo 'MIRROR_TEST_FAIL: tampered mirror installer accepted' >&2; exit 1
fi
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: tampered installer reached sudo' >&2; exit 1; }
if grep -q 'STOLEN_SECRET' "$scratch/tamper.out" "$scratch/tamper.err"; then
  echo 'MIRROR_TEST_FAIL: untrusted installer output leaked' >&2; exit 1
fi
mv "$scratch/untampered-installer" "$scratch/www/releases/v0.9.99/install.sh"

# Mirrored checksum tampering must fail inside canonical before binary
# publication and without reaching GitHub; the local proxy blocks it.
export STL_MIRROR_PREFIX="$scratch/corrupt-prefix"
mkdir -p "$STL_MIRROR_PREFIX/bin" "$STL_MIRROR_PREFIX/lib"
mv "$scratch/www/releases/v0.9.99/SHA256SUMS" "$scratch/untampered-sums"
printf '%064d  BUILD-MANIFEST.txt\n' 5 > "$scratch/www/releases/v0.9.99/SHA256SUMS"
if bash -c "$one_liner" > "$scratch/corrupt.out" 2> "$scratch/corrupt.err"; then
  echo 'MIRROR_TEST_FAIL: corrupted checksum manifest accepted' >&2; exit 1
fi
grep -q 'SHA256SUMS does not match' "$scratch/corrupt.out" ||
  { cat "$scratch/corrupt.out" "$scratch/corrupt.err"; echo 'MIRROR_TEST_FAIL: checksum guidance missing' >&2; exit 1; }
[[ ! -e "$STL_MIRROR_PREFIX/bin/stl" ]] ||
  { echo 'MIRROR_TEST_FAIL: checksum mismatch installed binary' >&2; exit 1; }
mv "$scratch/untampered-sums" "$scratch/www/releases/v0.9.99/SHA256SUMS"

# A partial or foreign installation must never be mistaken for a safely
# installer-owned older release and must not display the ordinary Update path.
export STL_MIRROR_PREFIX="$scratch/foreign-prefix"
mkdir -p "$STL_MIRROR_PREFIX/bin" "$STL_MIRROR_PREFIX/lib"
printf '#!/bin/sh\nexit 0\n' > "$STL_MIRROR_PREFIX/bin/stl"
foreign_sha=$(sha256sum "$STL_MIRROR_PREFIX/bin/stl" | awk '{print $1}')
if bash -c "$one_liner" > "$scratch/foreign.out" 2> "$scratch/foreign.err"; then
  echo 'MIRROR_TEST_FAIL: adopted foreign executable' >&2; exit 1
fi
! grep -q '\[ACTION\] STL.*already installed' "$scratch/foreign.out" ||
  { echo 'MIRROR_TEST_FAIL: misleading Update guidance for foreign executable' >&2; exit 1; }
[[ $(sha256sum "$STL_MIRROR_PREFIX/bin/stl" | awk '{print $1}') == "$foreign_sha" ]] ||
  { echo 'MIRROR_TEST_FAIL: foreign executable was overwritten' >&2; exit 1; }

# Missing mirror asset shows exact operator recovery, not fallback to GitHub.
export STL_MIRROR_PREFIX="$scratch/missing-prefix"
mkdir -p "$STL_MIRROR_PREFIX/bin" "$STL_MIRROR_PREFIX/lib"
mv "$scratch/www/releases/v0.9.99/LICENSE" "$scratch/untampered-license"
if bash -c "$one_liner" > "$scratch/missing.out" 2> "$scratch/missing.err"; then
  echo 'MIRROR_TEST_FAIL: missing mirrored asset accepted' >&2; exit 1
fi
grep -q 'Required release file is unavailable on the HTTPS mirror' "$scratch/missing.out" ||
  { cat "$scratch/missing.out" "$scratch/missing.err"; echo 'MIRROR_TEST_FAIL: missing-asset guidance unavailable' >&2; exit 1; }
[[ ! -e "$STL_MIRROR_PREFIX/bin/stl" ]] ||
  { echo 'MIRROR_TEST_FAIL: incomplete mirror created an executable' >&2; exit 1; }
mv "$scratch/untampered-license" "$scratch/www/releases/v0.9.99/LICENSE"

# Mirror cannot select an unmirrored historical tag or fall back to GitHub.
if bash -c "$one_liner v0.9.98" > "$scratch/historical.out" 2> "$scratch/historical.err"; then
  echo 'MIRROR_TEST_FAIL: unsupported mirror tag was silently accepted' >&2; exit 1
fi
grep -q 'no GitHub fallback' "$scratch/historical.err"

# Root first-hop transport failure should not run any installer either.
attempts=$(wc -l < "$STL_MIRROR_SUDO_RECORD")
if bash -c 's=$(curl -fsSL https://localhost:1/install.sh) && test -n "$s" && bash -n <<<"$s" && bash -c "$s" stl "$@"' stl > "$scratch/no-network.out" 2> "$scratch/no-network.err"; then
  echo 'MIRROR_TEST_FAIL: failed first-hop transport reported success' >&2; exit 1
fi
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: failed transport invoked privilege elevation' >&2; exit 1; }
echo 'MIRROR_TLS_REAL_CANONICAL_PRIVATE_PREFIX_INSTALL_UPDATE_AND_NEGATIVES=PASS'
