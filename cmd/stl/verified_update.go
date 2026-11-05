package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	verifiedLocalMaxBytes  int64 = 134250000
	verifiedMirrorMaxBytes int64 = 131072
)

var (
	updateDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	updateFilePattern   = regexp.MustCompile(`^stl_v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)_linux_(amd64|arm64)_local-install\.sh$`)
	updateHostPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)
)

type verifiedUpdateRequest struct {
	kind, source, digest string
}

func parseVerifiedUpdate(args []string) (verifiedUpdateRequest, error) {
	usage := errors.New("usage: stl update (--local /root/stl/official-local-install.sh | --mirror https://trusted.example/install.sh) --sha256 INDEPENDENT_64_HEX")
	if len(args) != 4 || args[2] != "--sha256" || !updateDigestPattern.MatchString(args[3]) {
		return verifiedUpdateRequest{}, usage
	}
	switch args[0] {
	case "--local":
		if args[1] != filepath.Join("/root/stl", filepath.Base(args[1])) || !updateFilePattern.MatchString(filepath.Base(args[1])) ||
			!strings.HasSuffix(args[1], "_linux_"+runtime.GOARCH+"_local-install.sh") {
			return verifiedUpdateRequest{}, errors.New("local update needs one exact published Stable filename for this CPU in /root/stl; no update started")
		}
		return verifiedUpdateRequest{kind: "local", source: args[1], digest: args[3]}, nil
	case "--mirror":
		if err := verifyUpdateMirrorURL(args[1]); err != nil {
			return verifiedUpdateRequest{}, err
		}
		return verifiedUpdateRequest{kind: "mirror", source: args[1], digest: args[3]}, nil
	default:
		return verifiedUpdateRequest{}, usage
	}
}

func verifyUpdateMirrorURL(raw string) error {
	reject := errors.New("mirror update requires exactly https://HOST[:PORT]/install.sh (no credentials, query, fragment or redirect); no update started")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
		u.Path != "/install.sh" || u.RawPath != "" || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Hostname() == "" ||
		!updateHostPattern.MatchString(u.Hostname()) || strings.Contains(u.Hostname(), "..") {
		return reject
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return reject
		}
	}
	return nil
}

// Only protected /root and /root/stl are admitted. An unchecked path,
// symlink, hardlink or shared writer must never supply privileged shell bytes.
func verifiedUpdateDirectory(path string, uid uint32, private bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("directory absent or not a real directory")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || info.Mode().Perm()&0022 != 0 ||
		(private && info.Mode().Perm() != 0700) {
		return errors.New("directory owner or permissions untrusted")
	}
	return nil
}

func verifiedUpdateSnapshot(source, root, transfer string, uid uint32, expectedSHA string) (string, string, error) {
	if err := verifiedUpdateDirectory(root, uid, false); err != nil {
		return "", "", fmt.Errorf("private source parent: %w", err)
	}
	if err := verifiedUpdateDirectory(transfer, uid, true); err != nil {
		return "", "", fmt.Errorf("private transfer directory: %w", err)
	}
	if source != filepath.Join(transfer, filepath.Base(source)) || !updateFilePattern.MatchString(filepath.Base(source)) {
		return "", "", errors.New("source filename or location is not a published Stable local installer")
	}
	fd, err := syscall.Open(source, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", "", errors.New("cannot open regular transferred installer without following links")
	}
	input := os.NewFile(uintptr(fd), source)
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 && info.Mode().Perm() != 0644 ||
		info.Size() <= 0 || info.Size() > verifiedLocalMaxBytes {
		return "", "", errors.New("installer must be a regular 0600/0644 file with bounded size")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Nlink != 1 {
		return "", "", errors.New("installer owner or hardlink count untrusted")
	}
	dir, err := os.MkdirTemp(root, ".stl-preflight.")
	if err != nil {
		return "", "", errors.New("cannot create private preflight directory")
	}
	// Keep the official basename. The authenticated build-bound launcher
	// uses this protected path to locate selected, separately pinned helpers
	// in /root/stl, never from an unverified private temporary copy.
	target := filepath.Join(dir, filepath.Base(source))
	if err := writeVerifiedUpdateCopy(target, input, verifiedLocalMaxBytes, info.Size(), expectedSHA); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	return dir, target, nil
}

func writeVerifiedUpdateCopy(target string, source io.Reader, maximum, exactSize int64, digest string) error {
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create private snapshot")
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, h), io.LimitReader(source, maximum+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n <= 0 || n > maximum ||
		(exactSize >= 0 && n != exactSize) {
		return errors.New("incomplete, changing or oversized snapshot; no code executed")
	}
	if !matchUpdateDigest(h, digest) {
		return errors.New("independent SHA256 mismatch; no code executed")
	}
	return nil
}

func matchUpdateDigest(h hash.Hash, trusted string) bool {
	expected, err := hex.DecodeString(trusted)
	return err == nil && subtle.ConstantTimeCompare(h.Sum(nil), expected) == 1
}

func verifiedMirrorSnapshot(ctx context.Context, raw, digest, root string, uid uint32, client *http.Client) (string, string, error) {
	if err := verifyUpdateMirrorURL(raw); err != nil {
		return "", "", err
	}
	if err := verifiedUpdateDirectory(root, uid, false); err != nil {
		return "", "", errors.New("private root staging unavailable")
	}
	dir, err := os.MkdirTemp(root, ".stl-mirror-preflight.")
	if err != nil {
		return "", "", errors.New("cannot create private mirror staging")
	}
	fail := func(message string) (string, string, error) {
		_ = os.RemoveAll(dir)
		return "", "", errors.New(message)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return fail("invalid HTTPS mirror request")
	}
	req.Header.Set("User-Agent", "simple-tun-link-verified-update")
	res, err := client.Do(req)
	if err != nil {
		return fail("trusted HTTPS mirror download failed; check TLS, reachability and timeouts")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ContentLength > verifiedMirrorMaxBytes {
		return fail("mirror returned an unexpected status or oversized bootstrap")
	}
	path := filepath.Join(dir, "install.sh")
	if err := writeVerifiedUpdateCopy(path, res.Body, verifiedMirrorMaxBytes, -1, digest); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	return dir, path, nil
}

func verifiedUpdateHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect forbidden")
		},
	}
}

// This is a trusted *first-hop* only. The preverified release launcher and
// the one canonical installer retain all version, APT, State and rollback
// authority. Caller-provided digest is a REQUIRED independent trust input;
// source URLs and downloaded manifests cannot supply it themselves.
func verifiedUpdateCommand(args []string, out, errOut io.Writer) int {
	req, err := parseVerifiedUpdate(args)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(errOut, "stl update requires root; use sudo with independently verified SHA256")
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(errOut, "installed executable identity unavailable; no update started")
		return 1
	}
	canonical, err := filepath.EvalSymlinks(executable)
	if err != nil || canonical != "/usr/local/bin/stl" {
		fmt.Fprintln(errOut, "run the installed /usr/local/bin/stl; no update started")
		return 1
	}
	var dir, path string
	if req.kind == "local" {
		dir, path, err = verifiedUpdateSnapshot(req.source, "/root", "/root/stl", 0, req.digest)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		dir, path, err = verifiedMirrorSnapshot(ctx, req.source, req.digest, "/root", 0, verifiedUpdateHTTPClient())
	}
	if err != nil {
		fmt.Fprintln(errOut, "stl verified update: "+err.Error())
		return 1
	}
	defer os.RemoveAll(dir)
	fmt.Fprintln(out, "[INFO] Verified private snapshot against independently provided SHA256. Running canonical Update; do not interrupt APT/package transactions.")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cli := exec.CommandContext(ctx, "/bin/bash", path, "--update")
	if req.kind == "mirror" {
		cli.Args = []string{"/bin/bash", path, "update"}
	}
	cli.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	cli.Stdin = os.Stdin
	var captured menuInstallerOutput
	cli.Stdout, cli.Stderr = captured.streams()
	if err := cli.Run(); err != nil {
		fmt.Fprintln(errOut, "[WARNING] Verified updater failed or was interrupted; host/package effects may be partial.")
		captured.failure(errOut, "update", err, ctx)
		return 1
	}
	versionOutput, err := exec.Command("/usr/local/bin/stl", "version", "--json").Output()
	if err != nil || len(versionOutput) > 4096 {
		fmt.Fprintln(errOut, "[WARNING] Installer exited but installed version identity is unverified. Inspect install-record and recovery before retrying.")
		return 1
	}
	var identity struct {
		SchemaVersion int    `json:"schema_version"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
	}
	if json.Unmarshal(versionOutput, &identity) != nil || identity.SchemaVersion != jsonSchemaVersion ||
		!menuReleaseTag.MatchString(identity.Version) || len(identity.Commit) != 40 ||
		!regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(identity.Commit) {
		fmt.Fprintln(errOut, "[WARNING] Installed binary version/commit identity unverified. Inspect recovery; do not retry blindly.")
		return 1
	}
	fmt.Fprintf(out, "[OK] Canonical Update reported success: %s (%s). Open sudo stl menu; verify Links separately.\n", identity.Version, identity.Commit)
	return 0
}
