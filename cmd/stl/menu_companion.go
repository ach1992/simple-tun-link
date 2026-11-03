package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Optional companions are acquired only after selecting their backend and
// confirming INSTALL. Their exact trusted release assets and SHA-256 digests
// are immutable inputs, not values discovered from a mutable remote tag.
type menuCompanionKind string

const (
	menuCompanionWSS  menuCompanionKind = "wss"
	menuCompanionQUIC menuCompanionKind = "quic"
)

type menuCompanionSpec struct {
	label, version, asset, url, digest, action, argument, binary, record string
}

func menuPinnedCompanion(kind menuCompanionKind, arch string) (menuCompanionSpec, bool) {
	switch kind {
	case menuCompanionWSS:
		spec := menuCompanionSpec{
			label: "WSS / wstunnel", version: "11.0.0",
			action: "companion-wss", argument: "--archive",
			binary: "/usr/local/libexec/stl/wstunnel",
			record: "/usr/local/lib/simple-tun-link/wss-companion-record",
		}
		switch arch {
		case "amd64":
			spec.digest = "9708a99717b5a951453c2ff7c14c25d3418d02ca7fcb96fdb382a8f2083bab5e"
		case "arm64":
			spec.digest = "b86abf73e340ed0c3ff9a77a5458aa27213784920ec65513132b36def45edc94"
		default:
			return menuCompanionSpec{}, false
		}
		spec.asset = "wstunnel_11.0.0_linux_" + arch + ".tar.gz"
		spec.url = "https://github.com/erebe/wstunnel/releases/download/v11.0.0/" + spec.asset
		return spec, true
	case menuCompanionQUIC:
		spec := menuCompanionSpec{
			label: "QUIC / Hysteria", version: "2.13.0",
			action: "companion-quic", argument: "--binary",
			binary: "/usr/local/libexec/stl/hysteria",
			record: "/usr/local/lib/simple-tun-link/quic-companion-record",
		}
		switch arch {
		case "amd64":
			spec.digest = "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
		case "arm64":
			spec.digest = "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7"
		default:
			return menuCompanionSpec{}, false
		}
		spec.asset = "hysteria-linux-" + arch
		spec.url = "https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/" + spec.asset
		return spec, true
	}
	return menuCompanionSpec{}, false
}

func (s menuCompanionSpec) localPath() string {
	return filepath.Join("/root/stl", s.asset)
}

// A corrupted, foreign or partially installed helper is NOT "missing" and
// cannot be adopted or overwritten by a download. The canonical installer
// performs its own authoritative ownership check under its exclusive lock.
func menuCompanionAbsent(s menuCompanionSpec) bool {
	for _, path := range []string{s.binary, s.record} {
		_, err := os.Lstat(path)
		if !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

type menuCompanionOps struct {
	inspect    func() error
	canInstall func(io.Reader, io.Writer) bool
	download   func(context.Context, menuCompanionSpec, string) error
	install    func(context.Context, io.Writer, io.Writer, ...string) error
	// Production always stages under root-controlled /root. Isolated tests
	// use a private test directory, never the real helper or install record.
	stageParent string
	localFile   string
	copyLocal   func(menuCompanionSpec, string, string) error
}

func productionMenuCompanionOps(inspect func() error, spec menuCompanionSpec) menuCompanionOps {
	return menuCompanionOps{
		inspect:    func() error { return menuInspectInstalledCompanion(spec, inspect) },
		canInstall: menuCanUpdateNow,
		download:   menuDownloadPinnedCompanion, install: runEmbeddedInstaller,
		stageParent: "/root", localFile: spec.localPath(),
		copyLocal: menuCopyLocalCompanion,
	}
}

const menuCompanionMaxBytes int64 = 100000000

type menuCompanionError string

func (e menuCompanionError) Error() string { return string(e) }

// Never surface raw HTTP/installer errors or remote bodies in interactive
// output. Keep a stable diagnostic reason and one accurate operator sentence.
func menuCompanionFailure(err error) (code, explanation string) {
	var known menuCompanionError
	if !errors.As(err, &known) {
		return "companion_acquisition_unverified", "The selected asset could not be inspected or verified; no installer was started."
	}
	switch known {
	case menuCompanionNetworkError:
		explanation = "Cannot reach the official HTTPS asset; check DNS, network, proxy or provider reachability. A timeout is also possible."
	case menuCompanionSourceError:
		explanation = "The official download returned an unacceptable response or redirected outside the trusted HTTPS hosts."
	case menuCompanionSizeError:
		explanation = "The asset size is outside STL's approved download limits."
	case menuCompanionHashError:
		explanation = "Downloaded file SHA-256 does not match the pinned official release; the file was rejected."
	case menuCompanionLocalError:
		explanation = "The local asset is missing, altered or has unsafe path, ownership or permissions."
	case menuCompanionStagingError:
		explanation = "Protected temporary storage could not be created or written; inspect space and permissions."
	default:
		explanation = "The selected asset could not be verified."
	}
	return string(known), explanation
}

const (
	menuCompanionNetworkError menuCompanionError = "official_download_unreachable"
	menuCompanionSourceError  menuCompanionError = "official_download_rejected"
	menuCompanionSizeError    menuCompanionError = "companion_size_unverified"
	menuCompanionHashError    menuCompanionError = "companion_sha256_mismatch"
	menuCompanionReadError    menuCompanionError = "companion_source_read_incomplete"
	menuCompanionLocalError   menuCompanionError = "local_source_unavailable_or_unsafe"
	menuCompanionStagingError menuCompanionError = "private_staging_unavailable"
)

func menuCompanionClient() *http.Client {
	return &http.Client{
		Timeout: 90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 || req.URL.Scheme != "https" {
				return menuCompanionSourceError
			}
			switch req.URL.Host {
			case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
				return nil
			default:
				return menuCompanionSourceError
			}
		},
	}
}

// Track destination errors independently of a body-reader failure: neither
// a disconnected transfer nor a full staging filesystem is an HTTP rejection.
type menuCompanionStageWriter struct {
	io.Writer
	failed bool
}

func (w *menuCompanionStageWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err != nil || n != len(p) {
		w.failed = true
	}
	return n, err
}

func menuCopyPinnedPayload(src io.Reader, dst io.Writer, digest string) error {
	sum := sha256.New()
	stage := &menuCompanionStageWriter{Writer: dst}
	n, err := io.Copy(io.MultiWriter(stage, sum), io.LimitReader(src, menuCompanionMaxBytes+1))
	if err != nil {
		if stage.failed {
			return menuCompanionStagingError
		}
		return menuCompanionReadError
	}
	if n <= 1024 || n >= menuCompanionMaxBytes {
		return menuCompanionSizeError
	}
	if hex.EncodeToString(sum.Sum(nil)) != digest {
		return menuCompanionHashError
	}
	return nil
}

func menuCopyPinnedAsset(src io.Reader, target, digest string) error {
	// The caller creates a private, never-before-existing staging directory.
	// O_EXCL and a bounded stream reject arbitrary overwrite or huge assets.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return menuCompanionStagingError
	}
	defer f.Close()
	if err := menuCopyPinnedPayload(src, f, digest); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return menuCompanionStagingError
	}
	return nil
}

func menuDownloadPinnedCompanion(ctx context.Context, spec menuCompanionSpec, target string) error {
	return menuDownloadPinnedCompanionWithClient(ctx, spec, target, menuCompanionClient())
}

func menuDownloadPinnedCompanionWithClient(ctx context.Context, spec menuCompanionSpec, target string, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.url, nil)
	if err != nil || req.URL.Scheme != "https" || req.URL.Host != "github.com" || req.URL.User != nil || req.URL.Fragment != "" {
		return menuCompanionSourceError
	}
	req.Header.Set("User-Agent", "simple-tun-link-companion")
	res, err := client.Do(req)
	if err != nil {
		if errors.Is(err, menuCompanionSourceError) {
			return menuCompanionSourceError
		}
		return menuCompanionNetworkError
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return menuCompanionSourceError
	}
	if res.ContentLength >= menuCompanionMaxBytes {
		return menuCompanionSizeError
	}
	if err := menuCopyPinnedAsset(res.Body, target, spec.digest); err != nil {
		if errors.Is(err, menuCompanionReadError) {
			return menuCompanionNetworkError
		}
		return err
	}
	return nil
}

// The local path is fixed, not an arbitrary root-executable path supplied
// by the terminal. Reject unsafe input ownership and parent traversal before
// copying into the same protected stage as an online asset.
func menuCopyLocalCompanion(spec menuCompanionSpec, source, target string) error {
	// A production menu can only read the exact root-owned /root/stl asset.
	return menuCopyLocalCompanionFromDir(spec, source, target, "/root/stl", 0)
}

func menuCopyLocalCompanionFromDir(spec menuCompanionSpec, source, target, directory string, uid uint32) error {
	if source != filepath.Join(directory, spec.asset) {
		return menuCompanionLocalError
	}
	dir, err := os.Lstat(directory)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 || !menuOwnedBy(dir, uid) {
		return menuCompanionLocalError
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || !menuOwnedBy(info, uid) ||
		!menuOneLink(info) ||
		(info.Mode().Perm() != 0600 && info.Mode().Perm() != 0644) {
		return menuCompanionLocalError
	}
	in, err := os.Open(source)
	if err != nil {
		return menuCompanionLocalError
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return menuCompanionLocalError
	}
	if err := menuCopyPinnedAsset(in, target, spec.digest); err != nil {
		if errors.Is(err, menuCompanionReadError) {
			return menuCompanionLocalError
		}
		return err
	}
	return nil
}

func menuOwnedBy(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}

func menuOneLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

// Shared first-use WSS/QUIC operator flow. It does NOT prepare all optional
// Carriers, does not initialize the Engine, and never modifies a Link.
func menuEnsureCompanion(input io.Reader, reader *bufio.Reader, out io.Writer,
	spec menuCompanionSpec, ops menuCompanionOps) bool {
	if ops.inspect == nil || ops.canInstall == nil || ops.download == nil ||
		ops.install == nil || ops.copyLocal == nil || ops.stageParent == "" {
		menuNotice(out, "FAILED", "Companion preparation is unavailable; no changes made.")
		return false
	}
	if ops.inspect() == nil {
		return true
	}
	if !menuCompanionAbsent(spec) {
		menuNotice(out, "WARNING", "Companion identity or absence is unverified; STL will not overwrite or adopt an existing or unreadable helper.")
		menuField(out, "Next", "Inspect STL-owned companion and its install record before a new attempt.")
		return false
	}
	menuSection(out, "Selected companion / setup")
	menuField(out, "Required", spec.label+" v"+spec.version)
	menuField(out, "Status", "Not installed")
	menuField(out, "Official asset", spec.url)
	menuCopyLine(out, "Local asset", ops.localFile)
	if !ops.canInstall(input, out) {
		menuNotice(out, "WARNING", "Automatic installation requires the official installed STL binary in a root interactive terminal.")
		menuField(out, "Next", "Use sudo stl menu. Offline: transfer the verified local asset to the path above.")
		return false
	}
	for {
		menuOption(out, "1", "Install online", "Download approved official asset, verify SHA-256, install")
		menuOption(out, "2", "Install local", "Use the already transferred verified asset")
		menuOption(out, "0", "Back", "No installation")
		fmt.Fprint(out, "Companion setup [1]: ")
		choice, err := readMenuAnswer(reader)
		if err != nil || choice == "0" || strings.EqualFold(choice, "q") {
			menuNotice(out, "INFO", "Companion installation cancelled. No new Link created.")
			return false
		}
		if choice == "" {
			choice = "1"
		}
		if choice != "1" && choice != "2" {
			menuNotice(out, "WARNING", "Select 1, 2 or 0.")
			continue
		}
		menuScreen(out, "Review / selected companion INSTALL")
		menuField(out, "Component", spec.label+" v"+spec.version)
		menuField(out, "Method", map[string]string{"1": "Online official release", "2": "Local verified file"}[choice])
		menuField(out, "Asset", spec.asset)
		menuCopyLine(out, "SHA-256 (exact)", spec.digest)
		menuField(out, "Install target", spec.binary)
		if choice == "1" {
			menuField(out, "Official source", spec.url)
			menuProse(out, "Requires access to the official GitHub release. A failed download does not authorize unverified mirrors.")
		} else {
			menuField(out, "Official source", spec.url)
			menuCopyLine(out, "Local source", ops.localFile)
			menuProse(out, "Transfer the exact official file from an Internet-connected device, unchanged, to root-owned /root/stl (0700); file mode 0600/0644.")
		}
		menuNotice(out, "WARNING", "INSTALL changes only the selected optional helper and its ownership record. It creates no Link. The existing canonical installer refuses foreign ownership.")
		if err := clearQueuedMenuConfirmation(input, reader); err != nil {
			menuNotice(out, "WARNING", "Fresh confirmation unavailable; nothing installed.")
			return false
		}
		fmt.Fprintf(out, "Type %s to install this companion (Enter=back): ", menuActionToken(out, "INSTALL"))
		answer, err := readMenuAnswer(reader)
		if err != nil || answer != "INSTALL" {
			menuNotice(out, "INFO", "Installation cancelled before download or host changes.")
			return false
		}
		// Reobserve immediately after consent; never turn a newly appeared
		// foreign executable or record into an installer overwrite attempt.
		if ops.inspect() == nil {
			menuNotice(out, "OK", "The selected companion is already verified; continuing Create.")
			return true
		}
		if !menuCompanionAbsent(spec) {
			menuNotice(out, "FAILED", "Companion ownership changed during review. No download or installation attempted.")
			return false
		}
		stage, err := os.MkdirTemp(ops.stageParent, ".stl-companion-")
		if err != nil {
			menuNotice(out, "FAILED", "Cannot create protected temporary staging; nothing installed.")
			return false
		}
		attemptedInstall := false
		result := func() bool {
			defer os.RemoveAll(stage)
			destination := filepath.Join(stage, spec.asset)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
			defer cancel()
			var acquisitionErr error
			if choice == "1" {
				menuNotice(out, "INFO", "Downloading only the selected official companion; verifying the pinned SHA-256 before installation.")
				acquisitionErr = ops.download(ctx, spec, destination)
			} else {
				menuNotice(out, "INFO", "Verifying the exact local asset before installation.")
				acquisitionErr = ops.copyLocal(spec, ops.localFile, destination)
			}
			if acquisitionErr != nil {
				reason, explanation := menuCompanionFailure(acquisitionErr)
				menuNotice(out, "FAILED", "Selected companion could not be verified. No installer was started.")
				menuField(out, "Why", explanation)
				menuField(out, "Reason code", reason)
				if choice == "1" {
					menuField(out, "Next", "The official source may be unreachable, blocked or unavailable; check HTTPS/DNS. For offline setup, transfer the exact official file and choose Install local.")
				} else {
					menuField(out, "Next", "Transfer the unmodified official file to "+ops.localFile+" and check root ownership, mode and architecture.")
				}
				return false
			}
			var child menuInstallerOutput
			stdout, stderr := child.streams()
			menuNotice(out, "INFO", "Verified download/source; canonical installer checking exact ownership and publishing companion.")
			attemptedInstall = true
			installCtx, stop := context.WithTimeout(context.Background(), 50*time.Second)
			defer stop()
			if err := ops.install(installCtx, stdout, stderr, spec.action, spec.argument, destination); err != nil {
				child.failure(out, "companion install", err, installCtx)
				menuNotice(out, "FAILED", "Companion installation denied or incomplete. Retained installer identity must be reconciled before a new attempt.")
				return false
			}
			if err := ops.inspect(); err != nil {
				menuNotice(out, "FAILED", "Installer returned success, but the pinned companion identity is not verified. Do not create this Link.")
				return false
			}
			menuNotice(out, "OK", "Approved companion installed and verified. Continuing the same Create wizard.")
			return true
		}()
		if result {
			return true
		}
		// If only acquisition failed, another explicit selection can use
		// the already transferred local asset without restarting the menu.
		if attemptedInstall || !menuCompanionAbsent(spec) {
			return false // an attempted installer requires fresh reconciliation, never blind retry
		}
		menuScreen(out, "Companion not installed / choose recovery")
		menuCopyLine(out, "Offline file", ops.localFile)
	}
}
