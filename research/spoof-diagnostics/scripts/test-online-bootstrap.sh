#!/usr/bin/env bash
# Only local, disposable developer/CI tests: no production download or install.
set -euo pipefail
umask 077
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
repo=$(git -C "$here" rev-parse --show-toplevel)
sha=$(git -C "$repo" rev-parse HEAD)
dir=$(mktemp -d "${TMPDIR:-/tmp}/spoofdiag-bootstrap-test.XXXXXXXX")
pid=''
cleanup(){
  if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  if [[ -d $dir && ! -L $dir ]]; then rm -rf -- "$dir"; fi
}
trap cleanup EXIT
mkdir "$dir/root"
bash "$here/scripts/package-offline.sh" "$dir/pkg" "$sha" dev-ci-online amd64 >/dev/null
archive="$dir/pkg/spoofdiag-dev-ci-online_linux_amd64.tar.gz"
expected=$(sha256sum "$archive" | cut -d ' ' -f1)
# Python is a CI-only local HTTP server, NOT an installed tool dependency.
command -v python3 >/dev/null || { echo 'CI test requires Python3 HTTP server' >&2; exit 1; }
port=$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
PY
)
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$dir/pkg" >"$dir/http.log" 2>&1 &
pid=$!
for _ in $(seq 1 50); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$port/spoofdiag-dev-ci-online_linux_amd64.tar.gz"; then break; fi
  sleep .1
done
bootstrap="$here/scripts/online-bootstrap.sh"
bash "$bootstrap" --local-url "http://127.0.0.1:$port" --version dev-ci-online --sha256 "$expected" --verify-only >"$dir/verify.log"
test ! -e "$dir/root/opt/stl-spoofdiag"
bash "$bootstrap" --local-url "http://127.0.0.1:$port" --version dev-ci-online --sha256 "$expected" --install --accept --destdir "$dir/root" >"$dir/install.log"
"$dir/root/usr/local/bin/stl-spoofdiag" version | grep -Fq 'dev-ci-online'
bash "$bootstrap" --local-url "http://127.0.0.1:$port" --version dev-ci-online --sha256 "$expected" --install --accept --destdir "$dir/root" >"$dir/reinstall.log"
if bash "$bootstrap" --local-url "http://127.0.0.1:$port" --version dev-ci-online --sha256 "$(printf 'f%.0s' {1..64})" --install --accept --destdir "$dir/root" >"$dir/badsha.log" 2>&1; then
  echo 'ERROR: wrong SHA accepted' >&2; exit 1
fi
grep -Fq 'SHA256 mismatch' "$dir/badsha.log"
if bash "$bootstrap" --local-url http://localhost:9999 --version dev-ci-online --sha256 "$expected" --verify-only >"$dir/badurl.log" 2>&1; then
  echo 'ERROR: noncanonical local URL accepted' >&2; exit 1
fi
if bash "$bootstrap" --version latest --sha256 "$expected" --verify-only >"$dir/latest.log" 2>&1; then
  echo 'ERROR: ambiguous latest accepted' >&2; exit 1
fi
if bash "$bootstrap" --local-url http://127.0.0.1:55555 --version dev-ci-online --sha256 "$expected" --verify-only >"$dir/down.log" 2>&1; then
  echo 'ERROR: unavailable download accepted' >&2; exit 1
fi
grep -Fq 'download failed' "$dir/down.log"
test -L "$dir/root/usr/local/bin/stl-spoofdiag"
printf 'LOCAL_ONLINE_BOOTSTRAP_POSITIVE_NEGATIVE=PASS\n'
