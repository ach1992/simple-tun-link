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
mkdir "$dir/root" "$dir/channel-root"
mkdir -m 0700 "$dir/inbox" "$dir/channel-inbox"
bash "$here/scripts/package-offline.sh" "$dir/pkg" "$sha" dev-ci-online amd64 >/dev/null
archive="$dir/pkg/spoofdiag-dev-ci-online_linux_amd64.tar.gz"
# Build the matching other-platform asset for an exact two-arch channel.
bash "$here/scripts/package-offline.sh" "$dir/pkg-arm64" "$sha" dev-ci-online arm64 >/dev/null
cp "$dir/pkg-arm64/spoofdiag-dev-ci-online_linux_arm64.tar.gz" "$dir/pkg/"
arm64_digest=$(sha256sum "$dir/pkg/spoofdiag-dev-ci-online_linux_arm64.tar.gz")
arm64_digest=${arm64_digest%% *}
# Official prefixed release tags must NOT accidentally double the prefix;
# the online downloader derives this exact same basename.
bash "$here/scripts/package-offline.sh" "$dir/release-pkg" "$sha" spoofdiag-v0.1.0-rc.1 amd64 > /dev/null
candidate="$dir/release-pkg/spoofdiag-v0.1.0-rc.1_linux_amd64.tar.gz"
test -f "$candidate"
test ! -e "$dir/release-pkg/spoofdiag-spoofdiag-v0.1.0-rc.1_linux_amd64.tar.gz"
( cd "$dir/release-pkg"; sha256sum -c spoofdiag-v0.1.0-rc.1_linux_amd64.tar.gz.sha256 > /dev/null )
mkdir "$dir/release-verify"
tar -xzf "$candidate" -C "$dir/release-verify"
bash "$dir/release-verify/stl-spoofdiag/install-offline.sh" --verify > "$dir/release-verify.log"
# The offline package must include the README's referenced documentation.
tar -tzf "$archive" > "$dir/package-members.txt"
for member in stl-spoofdiag/README.md stl-spoofdiag/docs/GO-REFERENCE.md stl-spoofdiag/docs/INSTALL-AND-RELEASE.md; do
  grep -Fxq "$member" "$dir/package-members.txt" || { echo "missing packaged document: $member" >&2; exit 1; }
done
expected=$(sha256sum "$archive" | cut -d ' ' -f1)
# Verify the shipped reference files are checksum-covered, not decorative.
mkdir "$dir/extracted-document-check"
tar -xzf "$archive" -C "$dir/extracted-document-check"
bundle="$dir/extracted-document-check/stl-spoofdiag"
bash "$bundle/install-offline.sh" --verify > "$dir/package-verify.log"
printf '\nTAMPERED\n' >> "$bundle/docs/GO-REFERENCE.md"
if bash "$bundle/install-offline.sh" --verify > "$dir/tampered-doc.log" 2>&1; then
  echo 'ERROR: modified packaged documentation was accepted' >&2
  exit 1
fi
grep -Fq 'bundle checksum verification failed' "$dir/tampered-doc.log"
# A fixed HTTPS publisher channel will be unpublished until a reviewed
# release exists. Use an explicit local-test channel only on loopback.
bootstrap_digest=$(sha256sum "$here/scripts/online-bootstrap.sh")
bootstrap_digest=${bootstrap_digest%% *}
cp "$here/scripts/online-bootstrap.sh" "$dir/pkg/online-bootstrap.sh"
cat > "$dir/pkg/release-channel.txt" <<CHANNEL
status=local-test
version=dev-ci-online
linux_amd64_sha256=$expected
linux_arm64_sha256=$arm64_digest
bootstrap_sha256=$bootstrap_digest
CHANNEL
# No Python on the development/test runner either: compile a temporary
# loopback-only Go stdlib file server; it is never added to a release bundle.
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0 \
  go build -o "$dir/local-fixture-server" "$here/scripts/test-fixture-http/main.go"
"$dir/local-fixture-server" --dir "$dir/pkg" --port-file "$dir/server-port" >"$dir/http.log" 2>&1 &
pid=$!
for _ in $(seq 1 50); do
  if [[ -s $dir/server-port ]]; then break; fi
  kill -0 "$pid" 2>/dev/null || { echo 'fixture HTTP server terminated prematurely' >&2; exit 1; }
  sleep .1
done
[[ -s $dir/server-port ]] || { echo 'local test HTTP listener did not start' >&2; exit 1; }
port=$(cat "$dir/server-port")
[[ $port =~ ^[0-9]+$ ]] || { echo 'invalid fixture port' >&2; exit 1; }
for _ in $(seq 1 50); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$port/spoofdiag-dev-ci-online_linux_amd64.tar.gz"; then break; fi
  sleep .1
done
bootstrap="$here/scripts/online-bootstrap.sh"
bash "$bootstrap" --local-url "http://127.0.0.1:$port" --version dev-ci-online --sha256 "$expected" --inbox "$dir/inbox" --verify-only >"$dir/verify.log"
test ! -e "$dir/root/opt/stl-spoofdiag"
bash "$bootstrap" --local-url "http://127.0.0.1:$port" --version dev-ci-online --sha256 "$expected" --inbox "$dir/inbox" --install --accept --destdir "$dir/root" >"$dir/install.log"
"$dir/root/usr/local/bin/stl-spoofdiag" version | grep -Fq 'dev-ci-online'
bash "$bootstrap" --local-url "http://127.0.0.1:$port" --version dev-ci-online --sha256 "$expected" --inbox "$dir/inbox" --install --accept --destdir "$dir/root" >"$dir/reinstall.log"
if bash "$bootstrap" --local-url "http://127.0.0.1:$port" --version dev-ci-online --sha256 "$(printf 'f%.0s' {1..64})" --inbox "$dir/inbox" --install --accept --destdir "$dir/root" >"$dir/badsha.log" 2>&1; then
  echo 'ERROR: wrong SHA accepted' >&2; exit 1
fi
grep -Fq 'SHA256 mismatch' "$dir/badsha.log"
if bash "$bootstrap" --local-url http://localhost:9999 --version dev-ci-online --sha256 "$expected" --inbox "$dir/inbox" --verify-only >"$dir/badurl.log" 2>&1; then
  echo 'ERROR: noncanonical local URL accepted' >&2; exit 1
fi
if bash "$bootstrap" --version latest --sha256 "$expected" --inbox "$dir/inbox" --verify-only >"$dir/latest.log" 2>&1; then
  echo 'ERROR: ambiguous latest accepted' >&2; exit 1
fi
if bash "$bootstrap" --local-url http://127.0.0.1:55555 --version dev-ci-online --sha256 "$expected" --inbox "$dir/inbox" --verify-only >"$dir/down.log" 2>&1; then
  echo 'ERROR: unavailable download accepted' >&2; exit 1
fi
grep -Fq 'download failed' "$dir/down.log"
test -L "$dir/root/usr/local/bin/stl-spoofdiag"
test -f "$dir/inbox/spoofdiag-dev-ci-online_linux_amd64.tar.gz"
test "$(stat -c %a "$dir/inbox")" = 700
test ! -e "$dir/inbox/.spoofdiag-online"  # no fixed leftover temp directory

# New version-agnostic public-entrypoint logic exercised using a local
# test-owned HTTP fixture; this is NOT a live HTTPS/publisher-signature test.
latest="$here/scripts/install-latest.sh"
bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/channel-inbox" --verify-only >"$dir/channel-verify.log"
test ! -e "$dir/channel-root/opt/stl-spoofdiag"
bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/channel-inbox" --accept >"$dir/channel-install.log"
"$dir/channel-root/usr/local/bin/stl-spoofdiag" version | grep -Fq 'dev-ci-online'
test -f "$dir/channel-inbox/spoofdiag-dev-ci-online_linux_amd64.tar.gz"
# The approved channel is also idempotent.
bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/channel-inbox" --accept >"$dir/channel-reinstall.log"

cp "$dir/pkg/release-channel.txt" "$dir/good-channel.txt"
printf '%s\n' 'status=unpublished' >"$dir/pkg/release-channel.txt"
if bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/channel-inbox" --accept >"$dir/no-release.log" 2>&1; then
  echo 'ERROR: unpublished channel performed installation' >&2; exit 1
fi
grep -Fq NO_PUBLIC_SPOOFDIAG_RELEASE "$dir/no-release.log"
cp "$dir/good-channel.txt" "$dir/pkg/release-channel.txt"
sed -i 's/^version=dev-ci-online$/version=v0.1.7/' "$dir/pkg/release-channel.txt"
if bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/channel-inbox" --accept >"$dir/stl-tag.log" 2>&1; then
  echo 'ERROR: STL tag was accepted in tool channel' >&2; exit 1
fi
cp "$dir/good-channel.txt" "$dir/pkg/release-channel.txt"
sed -i 's/^bootstrap_sha256=/bootstrap_sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff #/' "$dir/pkg/release-channel.txt"
if bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/channel-inbox" --accept >"$dir/bad-bootstrap.log" 2>&1; then
  echo 'ERROR: corrupt channel bootstrap digest was accepted' >&2; exit 1
fi
cp "$dir/good-channel.txt" "$dir/pkg/release-channel.txt"
sed -i 's/^linux_amd64_sha256=/linux_amd64_sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff #/' "$dir/pkg/release-channel.txt"
if bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/channel-inbox" --accept >"$dir/bad-channel.log" 2>&1; then
  echo 'ERROR: malformed channel hash was accepted' >&2; exit 1
fi
cp "$dir/good-channel.txt" "$dir/pkg/release-channel.txt"
# Explicit wrong-but-wellformed selected archive digest must fail *before*
# any tool installation mutation.
sed -i 's/^linux_amd64_sha256=.*/linux_amd64_sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/' "$dir/pkg/release-channel.txt"
if bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/channel-inbox" --accept >"$dir/wrong-channel-sha.log" 2>&1; then
  echo 'ERROR: valid-format wrong archive checksum was accepted' >&2; exit 1
fi
grep -Fq 'SHA256 mismatch' "$dir/wrong-channel-sha.log"
cp "$dir/good-channel.txt" "$dir/pkg/release-channel.txt"

# Path confusion and symlink inbox must be rejected before any download.
ln -s "$dir/channel-inbox" "$dir/alias-inbox"
if bash "$latest" --local-url "http://127.0.0.1:$port" --destdir "$dir/channel-root" --inbox "$dir/alias-inbox" --accept >"$dir/inbox-symlink.log" 2>&1; then
  echo 'ERROR: symlinked private download inbox was accepted' >&2; exit 1
fi
printf 'LOCAL_ONLINE_BOOTSTRAP_AND_GENERIC_CHANNEL_POSITIVE_NEGATIVE=PASS\n'
