//go:build linux

package main

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestPackagePreviewMixedTTYNeverStreamsSensitiveAPTDiagnostics(t *testing.T) {
	_, stdout := openMenuPTY(t)
	stderrFile, err := os.CreateTemp(t.TempDir(), "redirected-apt-stderr-")
	if err != nil {
		t.Fatal(err)
	}
	defer stderrFile.Close()
	const secret = "APT_PRIVATE_SOURCE_URL_MUST_NOT_REACH_REDIRECTED_STDERR"
	runner := func(_ context.Context, _, stderr io.Writer, _ ...string) error {
		_, _ = io.WriteString(stderr, "Host private APT URL: "+secret+"\n")
		_, _ = io.WriteString(stderr, "stl installer [FAILED]: APT plan would remove packages; no changes allowed\n")
		return errors.New("installer failed: " + secret)
	}
	preview := selectedPackagePreviewForStreams(stdout, stderrFile, runner)
	selected := tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}
	_, err = preview(context.Background(), selected)
	reason, next := packageInventoryGuidance(err)
	if reason != "apt_dependency_plan_unverified" || strings.Contains(reason+next, secret) {
		t.Fatalf("read-only classified reason unavailable or leaked: %q %q", reason, next)
	}
	raw, err := os.ReadFile(stderrFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 || strings.Contains(string(raw), secret) {
		t.Fatalf("redirected stderr received unconsented private diagnostics: %q", raw)
	}
}

func TestPackagePreviewBothTTYStreamsCompleteHumanDiagnostics(t *testing.T) {
	_, stdout := openMenuPTY(t)
	master, stderr := openMenuPTY(t)
	const full = "APT_HUMAN_TERMINAL_ONLY_FULL_DIAGNOSTIC"
	runner := func(_ context.Context, _, diagnostics io.Writer, _ ...string) error {
		_, err := io.WriteString(diagnostics, full+"\n")
		return err
	}
	preview := selectedPackagePreviewForStreams(stdout, stderr, runner)
	_, err := preview(context.Background(), tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative})
	if err == nil {
		t.Fatal("incomplete canonical inventory was unexpectedly accepted")
	}
	content := readMenuPTYUntil(t, master, full)
	if !strings.Contains(content, full) {
		t.Fatalf("actual human diagnostic destination lost full APT message: %q", content)
	}
}

func TestPackagePreviewRedirectedStdoutNeverStreamsToInteractiveStderr(t *testing.T) {
	var stdout strings.Builder
	master, stderr := openMenuPTY(t)
	const secret = "APT_DIAGNOSTIC_MUST_STAY_PRIVATE"
	runner := func(_ context.Context, _, diagnostics io.Writer, _ ...string) error {
		_, _ = io.WriteString(diagnostics, secret+"\n")
		return errors.New("read-only check was interrupted")
	}
	preview := selectedPackagePreviewForStreams(&stdout, stderr, runner)
	_, _ = preview(context.Background(), tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative})
	// The terminal is nonblocking only for this assertion; no private child
	// output may be emitted merely because stderr alone is interactive.
	if err := unix.SetNonblock(int(master.Fd()), true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, readErr := unix.Read(int(master.Fd()), buf)
	if n > 0 || (readErr != nil && !errors.Is(readErr, unix.EAGAIN)) {
		t.Fatalf("stderr TTY received raw APT despite redirected stdout: %q err=%v", buf[:n], readErr)
	}
}
