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
    def do_GET(self):
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
cp -a -- "$scratch/webroot/." "$scratch/www/"
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
[[ $# -ge 2 && $1 == bash ]] || exit 87
shift
printf '%s\n' "$*" >> "$STL_MIRROR_SUDO_RECORD"
bash "$@" --prefix "$STL_MIRROR_PREFIX"
SUDO
chmod 0755 "$scratch/bin/sudo"
export PATH="$scratch/bin:$PATH"
export STL_MIRROR_SUDO_RECORD="$scratch/privileged-attempts"
export STL_MIRROR_PREFIX="$scratch/new-prefix"
mkdir -p "$STL_MIRROR_PREFIX/bin" "$STL_MIRROR_PREFIX/lib"
: > "$STL_MIRROR_SUDO_RECORD"

one_liner=$(grep -m1 '^bash -c .*stl.example.com/install.sh' "$repo/docs/MIRROR.md")
one_liner=${one_liner/https:\/\/stl.example.com/$base}
[[ $one_liner == *"$base/install.sh"* ]] ||
  { echo 'MIRROR_TEST_FAIL: operator mirror command missing' >&2; exit 1; }
grep -Fx "INSTALL_COMMAND=$one_liner" "$scratch/prepared.log" >/dev/null ||
  { echo 'MIRROR_TEST_FAIL: prepared command differs from documented one-liner' >&2; exit 1; }
# Real TLS streaming tests: chunked payload with no Content-Length must
# be stopped at 128KiB+1 before any script is run. A stalled response must
# time out despite an initially valid shell prefix. No root/host mutation.
for fixture in "$base/newline-oversize.sh" "$base/official-newline-oversize.sh"; do
  raw_bytes=$(curl -fsS --max-time 20 "$fixture" | wc -c)
  [[ $raw_bytes == 131073 ]] ||
    { echo "MIRROR_TEST_FAIL: wire payload must be exactly 131073 bytes: $fixture ($raw_bytes)" >&2; exit 1; }
done
attempts=$(wc -l < "$STL_MIRROR_SUDO_RECORD")
oversize_cmd=${one_liner/"$base/install.sh"/"$base/chunked-oversize.sh"}
if bash -c "$oversize_cmd" > "$scratch/oversize.out" 2> "$scratch/oversize.err"; then
  echo 'MIRROR_TEST_FAIL: oversized chunked HTTPS response accepted' >&2; exit 1
fi
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: oversized first hop invoked privileged installer' >&2; exit 1; }
# The exact publicly documented official command must independently reject
# the same trailing-LF bypass. Only its first-hop URL is redirected to the
# isolated TLS fixture; the payload is deliberately harmless (no sudo).
official_url='https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh'
mapfile -t official_commands < <(grep '^bash -c .*stl-bootstrap.sh' "$repo/README.md")
[[ ${#official_commands[@]} -eq 3 ]] ||
  { echo 'MIRROR_TEST_FAIL: expected three published official commands' >&2; exit 1; }
for official_line in "${official_commands[@]}"; do
  grep -Fx -- "$official_line" "$repo/docs/INSTALL.md" >/dev/null ||
    { echo 'MIRROR_TEST_FAIL: official user commands disagree' >&2; exit 1; }
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
newline_bad_cmd=${one_liner/"$base/install.sh"/"$base/newline-oversize.sh"}
if bash -c "$newline_bad_cmd" > "$scratch/mirror-lf-bad.out" 2> "$scratch/mirror-lf-bad.err"; then
  echo 'MIRROR_TEST_FAIL: mirror accepted 131073 trailing-LF bytes' >&2; exit 1
fi
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: oversized newline-padded mirror reached sudo' >&2; exit 1; }
echo 'FIRST_HOP_NEWLINE_OVERFLOW_NO_EXECUTION=PASS'

nul_cmd=${one_liner/"$base/install.sh"/"$base/nul-padded.sh"}
if bash -c "$nul_cmd" > "$scratch/nul.out" 2> "$scratch/nul.err"; then
  echo 'MIRROR_TEST_FAIL: NUL-padded oversized chunked response was accepted' >&2; exit 1
fi
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == "$attempts" ]] ||
  { echo 'MIRROR_TEST_FAIL: NUL-padded response invoked privileged installer' >&2; exit 1; }
! grep -q NUL_BYPASS "$scratch/nul.out" ||
  { echo 'MIRROR_TEST_FAIL: NUL-padded response executed its shell prefix' >&2; exit 1; }
stall_cmd=${one_liner/"$base/install.sh"/"$base/stall.sh"}
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
# A valid within-cap chunked response that contains the fully pinned mirror
# bootstrap plus harmless trailing newlines must still succeed.
newline_good_cmd=${one_liner/"$base/install.sh"/"$base/newline-fit.sh"}
bash -c "$newline_good_cmd" > "$scratch/mirror-lf-good.out" 2> "$scratch/mirror-lf-good.err" ||
  { echo 'MIRROR_TEST_FAIL: mirror rejected valid within-cap trailing-LF bytes' >&2; exit 1; }
[[ $(wc -l < "$STL_MIRROR_SUDO_RECORD") == 2 ]] ||
  { echo 'MIRROR_TEST_FAIL: valid trailing-LF mirror did not invoke canonical installer' >&2; exit 1; }
echo 'FIRST_HOP_NEWLINE_WITHIN_LIMIT_VALID=PASS'


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
bad_pins_cmd=${one_liner/"$base/install.sh"/"$base/bad-pins.sh"}
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
