package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/version"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	publisherTrustDir          = "/usr/local/lib/simple-tun-link"
	publisherTrustFile         = "mirror-publisher.json"
	publisherTrustLockFile     = ".mirror-publisher.lock"
	mirrorReleasePurpose       = "stl-static-mirror-release/v1"
	mirrorReleaseMetadataBytes = 32768 // Signed control-plane object only, not a release artifact cap.
)

type mirrorSignedRelease struct {
	Purpose         string `json:"purpose"`
	Sequence        uint64 `json:"sequence"`
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	BootstrapSHA256 string `json:"bootstrap_sha256"`
	KeyFingerprint  string `json:"key_fingerprint"`
}

type mirrorPublisherTrust struct {
	SchemaVersion int    `json:"schema_version"`
	PublicKey     string `json:"public_key"`
	Fingerprint   string `json:"fingerprint"`
	Sequence      uint64 `json:"sequence"`
	LastVersion   string `json:"last_version,omitempty"`
}

var mirrorCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func publisherKeyFingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func validatedPublisherTrust(state mirrorPublisherTrust) (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.Strict().DecodeString(state.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || state.SchemaVersion != 1 ||
		!updateDigestPattern.MatchString(state.Fingerprint) ||
		subtle.ConstantTimeCompare([]byte(publisherKeyFingerprint(ed25519.PublicKey(pub))), []byte(state.Fingerprint)) != 1 ||
		state.LastVersion != "" && !menuStableVersion.MatchString(state.LastVersion) {
		return nil, errors.New("publisher trust record invalid or unverified")
	}
	return ed25519.PublicKey(pub), nil
}

// The independently enrolled key is a root-only, no-follow record. A symlink,
// foreign owner or hardlink never becomes authority for root code execution.
func readPublisherTrust(dir string, uid uint32) (mirrorPublisherTrust, error) {
	var state mirrorPublisherTrust
	if err := verifiedUpdateDirectory(dir, uid, true); err != nil {
		return state, err
	}
	path := filepath.Join(dir, publisherTrustFile)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return state, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Size() <= 0 || info.Size() > 2048 {
		return state, errors.New("publisher trust record identity invalid")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Nlink != 1 {
		return state, errors.New("publisher trust record owner/hardlinks untrusted")
	}
	raw, err := io.ReadAll(f)
	if err != nil || json.Unmarshal(raw, &state) != nil {
		return mirrorPublisherTrust{}, errors.New("publisher trust record cannot be parsed")
	}
	if _, err := validatedPublisherTrust(state); err != nil {
		return mirrorPublisherTrust{}, err
	}
	return state, nil
}

func lockPublisherTrust(dir string, uid uint32) (*os.File, error) {
	if err := verifiedUpdateDirectory(dir, uid, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, publisherTrustLockFile)
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("publisher lock unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("publisher lock untrusted")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("publisher lock ownership untrusted")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, errors.New("cannot acquire publisher update lock")
	}
	return f, nil
}

func writePublisherTrust(dir string, uid uint32, state mirrorPublisherTrust) error {
	if _, err := validatedPublisherTrust(state); err != nil {
		return err
	}
	if err := verifiedUpdateDirectory(dir, uid, true); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return errors.New("publisher record encoding failed")
	}
	tmp, err := os.CreateTemp(dir, ".publisher-trust-")
	if err != nil {
		return errors.New("publisher record staging unavailable")
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, publisherTrustFile)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func readEnrolledPublisherPublicKey(path string, uid uint32, wantFingerprint string) (ed25519.PublicKey, error) {
	if !updateDigestPattern.MatchString(wantFingerprint) ||
		path != filepath.Join("/root/stl", filepath.Base(path)) {
		return nil, errors.New("publisher enrollment requires an independent fingerprint and /root/stl public key file")
	}
	if err := verifiedUpdateDirectory("/root/stl", uid, true); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("publisher key file could not be opened safely")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 40 || info.Size() > 4096 ||
		(info.Mode().Perm() != 0600 && info.Mode().Perm() != 0644) {
		return nil, errors.New("publisher public key file is not a supported regular file")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Nlink != 1 {
		return nil, errors.New("publisher key owner/hardlink untrusted")
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, errors.New("publisher public key unreadable")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("publisher public key must be a PEM Ed25519 PUBLIC KEY")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize ||
		subtle.ConstantTimeCompare([]byte(publisherKeyFingerprint(key)), []byte(wantFingerprint)) != 1 {
		return nil, errors.New("publisher Ed25519 identity differs from independently supplied fingerprint")
	}
	return key, nil
}

func verifyMirrorSignedRelease(raw, signature []byte, public ed25519.PublicKey,
	trust mirrorPublisherTrust, currentVersion string) (mirrorSignedRelease, error) {
	var meta mirrorSignedRelease
	if len(raw) == 0 || len(raw) > mirrorReleaseMetadataBytes ||
		len(signature) != ed25519.SignatureSize || len(public) != ed25519.PublicKeySize ||
		subtle.ConstantTimeCompare([]byte(publisherKeyFingerprint(public)), []byte(trust.Fingerprint)) != 1 ||
		!ed25519.Verify(public, raw, signature) {
		return meta, errors.New("mirror release publisher signature invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return mirrorSignedRelease{}, errors.New("signed metadata is invalid")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return mirrorSignedRelease{}, errors.New("signed metadata has trailing bytes")
	}
	if meta.Purpose != mirrorReleasePurpose || meta.Sequence == 0 || meta.Sequence <= trust.Sequence ||
		!menuStableVersion.MatchString(meta.Version) || !mirrorCommitPattern.MatchString(meta.Commit) ||
		!updateDigestPattern.MatchString(meta.BootstrapSHA256) ||
		subtle.ConstantTimeCompare([]byte(meta.KeyFingerprint), []byte(trust.Fingerprint)) != 1 ||
		(meta.Version != currentVersion && !menuStablePatchUpgrade(currentVersion, meta.Version)) ||
		(trust.LastVersion != "" && meta.Version != trust.LastVersion && !menuStablePatchUpgrade(trust.LastVersion, meta.Version)) {
		return mirrorSignedRelease{}, errors.New("signed mirror metadata is incompatible, replayed or not a verified forward update")
	}
	return meta, nil
}

func fetchSignedMirrorObject(ctx context.Context, client *http.Client, endpoint string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("invalid signed mirror HTTPS request")
	}
	req.Header.Set("User-Agent", "simple-tun-link-signed-mirror")
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("signed mirror HTTPS request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ContentLength > max {
		return nil, errors.New("signed mirror metadata HTTP status or object size rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > max {
		return nil, errors.New("signed mirror metadata object could not be read fully")
	}
	return raw, nil
}

func fetchVerifiedSignedMirror(ctx context.Context, client *http.Client, bootstrapURL string,
	pub ed25519.PublicKey, trust mirrorPublisherTrust, current string) (mirrorSignedRelease, error) {
	if err := verifyUpdateMirrorURL(bootstrapURL); err != nil {
		return mirrorSignedRelease{}, err
	}
	root := strings.TrimSuffix(bootstrapURL, "/install.sh")
	raw, err := fetchSignedMirrorObject(ctx, client, root+"/release.json", mirrorReleaseMetadataBytes)
	if err != nil {
		return mirrorSignedRelease{}, err
	}
	encoded, err := fetchSignedMirrorObject(ctx, client, root+"/release.sig", 256)
	if err != nil {
		return mirrorSignedRelease{}, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return mirrorSignedRelease{}, errors.New("signed mirror signature encoding invalid")
	}
	return verifyMirrorSignedRelease(raw, signature, pub, trust, current)
}

// New publication trust is never inferred from the mirror. The operator
// brings a PEM public key and its independently verified SHA256 fingerprint
// into a protected local terminal, with an explicit second confirmation.
func mirrorPublisherEnrollmentCommand(args []string, out, errOut io.Writer) int {
	if (len(args) != 5 && len(args) != 6) || args[0] != "enroll" || args[1] != "--file" ||
		args[3] != "--fingerprint" || len(args) == 6 && args[5] != "--rotate" {
		fmt.Fprintln(errOut, "usage: stl mirror-key enroll --file /root/stl/publisher.pem --fingerprint INDEPENDENT_SHA256 [--rotate]")
		return 2
	}
	if os.Geteuid() != 0 || !terminalIsInteractive(os.Stdin) || !terminalIsInteractive(os.Stdout) {
		fmt.Fprintln(errOut, "publisher trust enrollment requires an installed root interactive terminal")
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		return 1
	}
	canonical, err := filepath.EvalSymlinks(exe)
	if err != nil || canonical != "/usr/local/bin/stl" {
		fmt.Fprintln(errOut, "publisher trust enrollment requires the canonical installed STL")
		return 1
	}
	key, err := readEnrolledPublisherPublicKey(args[2], 0, args[4])
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	rotate := len(args) == 6
	lock, err := lockPublisherTrust(publisherTrustDir, 0)
	if err != nil {
		fmt.Fprintln(errOut, "publisher trust storage unavailable")
		return 1
	}
	defer lock.Close()
	state, err := readPublisherTrust(publisherTrustDir, 0)
	if rotate {
		if err != nil {
			fmt.Fprintln(errOut, "no verified publisher trust record exists for rotation")
			return 1
		}
		if state.Fingerprint == publisherKeyFingerprint(key) {
			fmt.Fprintln(errOut, "new publisher key is already trusted")
			return 1
		}
	} else if err == nil || !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(errOut, "publisher trust exists or is ambiguous; explicit verified --rotate is required")
		return 1
	}
	token := "ENROLL"
	if rotate {
		token = "ROTATE"
	}
	fmt.Fprintf(out, "Publisher Ed25519 SHA256: %s\n%s requires independently checking this fingerprint, not trusting mirror content. Type %s: ",
		publisherKeyFingerprint(key), token, token)
	reader := bufio.NewReader(os.Stdin)
	if err := clearQueuedMenuConfirmation(os.Stdin, reader); err != nil {
		fmt.Fprintln(errOut, "cannot obtain fresh terminal enrollment consent; trust unchanged")
		return 1
	}
	line, readErr := reader.ReadString('\n')
	if readErr != nil || strings.TrimSpace(line) != token {
		fmt.Fprintln(errOut, "publisher trust enrollment cancelled")
		return 1
	}
	state.SchemaVersion = 1
	state.PublicKey = base64.StdEncoding.EncodeToString(key)
	state.Fingerprint = publisherKeyFingerprint(key)
	if err := writePublisherTrust(publisherTrustDir, 0, state); err != nil {
		fmt.Fprintln(errOut, "publisher trust could not be stored durably")
		return 1
	}
	fmt.Fprintln(out, "[OK] Publisher key enrolled locally; no update was started.")
	return 0
}

func signedMirrorUpdateCommand(args []string, out, errOut io.Writer) int {
	if len(args) != 2 || args[0] != "--signed-mirror" || verifyUpdateMirrorURL(args[1]) != nil {
		fmt.Fprintln(errOut, "usage: stl update --signed-mirror https://TRUSTED-MIRROR/install.sh")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(errOut, "signed mirror update requires root")
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		return 1
	}
	canonical, err := filepath.EvalSymlinks(exe)
	if err != nil || canonical != "/usr/local/bin/stl" {
		fmt.Fprintln(errOut, "signed mirror update requires /usr/local/bin/stl")
		return 1
	}
	lock, err := lockPublisherTrust(publisherTrustDir, 0)
	if err != nil {
		fmt.Fprintln(errOut, "publisher trust lock unavailable")
		return 1
	}
	defer lock.Close()
	state, err := readPublisherTrust(publisherTrustDir, 0)
	if err != nil {
		fmt.Fprintln(errOut, "no verified enrolled publisher key; enroll from an independent trusted source first")
		return 1
	}
	pub, err := validatedPublisherTrust(state)
	if err != nil {
		fmt.Fprintln(errOut, "publisher trust identity changed")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	meta, err := fetchVerifiedSignedMirror(ctx, verifiedUpdateHTTPClient(), args[1], pub, state, version.Version)
	if err != nil {
		fmt.Fprintln(errOut, "signed mirror authorization failed: "+err.Error())
		return 1
	}
	if meta.Version == version.Version {
		// Crash recovery: a canonical update can succeed then terminate before
		// its independently signed anti-rollback receipt is durably committed.
		// Only the EXACT matching signed source commit may advance the receipt
		// without running any installer, package command or network side effect.
		if meta.Commit != version.Commit {
			fmt.Fprintln(errOut, "installed version shares a tag but not the signed publisher commit; no trust advanced")
			return 1
		}
		state.Sequence, state.LastVersion = meta.Sequence, meta.Version
		if err := writePublisherTrust(publisherTrustDir, 0, state); err != nil {
			fmt.Fprintln(errOut, "publisher receipt could not be recovered; no update started")
			return 1
		}
		fmt.Fprintf(out, "[OK] Already installed verified signed %s; publisher sequence %d reconciled without running an installer.\n", meta.Version, meta.Sequence)
		return 0
	}
	fmt.Fprintf(out, "[INFO] Verified publisher signature, increasing sequence %d, target %s. Running exact authenticated bootstrap.\n", meta.Sequence, meta.Version)
	if code := verifiedUpdateCommandExpected([]string{"--mirror", args[1], "--sha256", meta.BootstrapSHA256}, out, errOut, meta.Version, meta.Commit); code != 0 {
		return code
	}
	raw, err := exec.Command("/usr/local/bin/stl", "version", "--json").Output()
	if err != nil || len(raw) > 4096 {
		fmt.Fprintln(errOut, "installed version cannot be checked after signed update")
		return 1
	}
	var installed struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if json.Unmarshal(raw, &installed) != nil || installed.Version != meta.Version || installed.Commit != meta.Commit {
		fmt.Fprintln(errOut, "signed update installed identity differs from authorized metadata; reconcile before retry")
		return 1
	}
	state.Sequence = meta.Sequence
	state.LastVersion = meta.Version
	if err := writePublisherTrust(publisherTrustDir, 0, state); err != nil {
		fmt.Fprintln(errOut, "installed release verified but publisher anti-rollback record could not be committed; manual reconciliation required")
		return 1
	}
	fmt.Fprintf(out, "[OK] Signed mirror update %s verified; publisher sequence %d committed.\n", installed.Version, meta.Sequence)
	return 0
}
