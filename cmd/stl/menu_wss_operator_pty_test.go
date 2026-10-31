package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"golang.org/x/sys/unix"
)

// The operator must see the next question after the informational WSS banner;
// a genuine PTY, not merely a prebuffered string, drives and cancels the path.
func TestWSSGuidedPTYShowsNextPromptAndCancelsWithoutState(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	workspace := t.TempDir()
	root := filepath.Join(workspace, "absent-state")
	binary := filepath.Join(workspace, "pinned-helper")
	payload := []byte("isolated pinned helper identity; never executed")
	if err := os.WriteFile(binary, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	companion := wss.Host{Binary: binary, SHA256: hex.EncodeToString(sum[:])}
	master, slave := openMenuPTY(t)
	done := make(chan int, 1)
	go func() {
		done <- menuCreateWSSWithHost(slave, bufio.NewReader(slave), slave, slave,
			&runtimeOptions{stateRoot: root}, companion)
	}()
	seen := readMenuPTYUntil(t, master, "WireGuard UDP is scoped to loopback",
		"Other server's reachable IPv4 address")
	if strings.Contains(seen, "Approved wstunnel") {
		t.Fatal("correct pinned companion was refused")
	}
	if _, err := io.WriteString(master, "q\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("WSS PTY cancellation returned %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WSS PTY failed to return from the first prompt")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("canceled WSS created State: %v", err)
	}
}

func TestWSSGuidedMissingCompanionGivesBoundedActionableMessage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent-state")
	companion := wss.Host{Binary: filepath.Join(t.TempDir(), "missing-helper"),
		SHA256: strings.Repeat("0", 64)}
	in := strings.NewReader("q\n")
	var out, errOut bytes.Buffer
	code := menuCreateWSSWithHost(in, bufio.NewReader(in), &out, &errOut,
		&runtimeOptions{stateRoot: root}, companion)
	if code != 4 || errOut.Len() != 0 ||
		!strings.Contains(out.String(), "Approved wstunnel v11.0.0 companion is missing or untrusted") ||
		!strings.Contains(out.String(), "official one-file STL installer") ||
		strings.Contains(out.String(), "missing-helper") {
		t.Fatalf("missing WSS helper guidance incorrect: code=%d out=%q stderr=%q",
			code, out.String(), errOut.String())
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("WSS missing companion created State: %v", err)
	}
}

// Exercise the actual WSS wizard from role choice through review on a narrow
// terminal. Cancel before YES: no credential or host-resource mutation is allowed.
func TestWSSGuidedRealPTYDirectionPortRetryReviewAndCancel(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	workspace := t.TempDir()
	root := filepath.Join(workspace, "absent-state")
	binary := filepath.Join(workspace, "pinned-helper")
	payload := []byte("isolated pinned WSS helper identity; never executed")
	if err := os.WriteFile(binary, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	companion := wss.Host{Binary: binary, SHA256: hex.EncodeToString(sum[:])}
	master, slave := openMenuPTY(t)
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 24, Col: 38}); err != nil {
		t.Fatal(err)
	}
	opts := guidedTestOptions(root, &guidedTestRunner{},
		&guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()})
	done := make(chan int, 1)
	go func() {
		done <- menuCreateWSSWithHost(slave, bufio.NewReader(slave), slave, slave, opts, companion)
	}()
	steps := []struct {
		prompt, answer string
	}{
		{"Other server's reachable IPv4 address", "192.0.2.20\n"},
		{"Tunnel IP on THIS server", "\n"},
		{"Direction [Enter=suggested; 1=listen; 2=dial]: ", "2\n"},
		{"Public WSS/TLS TCP port [443]: ", "0\n"},
	}
	for _, step := range steps {
		readMenuPTYUntil(t, master, step.prompt)
		if _, err := io.WriteString(master, step.answer); err != nil {
			t.Fatal(err)
		}
	}
	retry := readMenuPTYUntil(t, master, "Use a port number between 1 and 65535.", "Public WSS/TLS TCP port [443]: ")
	if strings.Contains(retry, "Use a UDP port number") {
		t.Fatalf("WSS TCP was reported as UDP: %q", retry)
	}
	if _, err := io.WriteString(master, "8443\n"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		prompt, answer string
	}{
		{"Kernel WG UDP port on THIS server", "\n"},
		{"Kernel WG UDP port on OTHER server", "\n"},
		{"THIS server's private loopback forwarding UDP port", "\n"},
		{"TLS certificate SAN", "\n"},
	} {
		readMenuPTYUntil(t, master, step.prompt)
		if _, err := io.WriteString(master, step.answer); err != nil {
			t.Fatal(err)
		}
	}
	review := readMenuPTYUntil(t, master, "Create WSS Link and private receiver handoff? Type YES")
	for _, marker := range []string{
		"192.0.2.10 (dial)", "192.0.2.20 (listen)", "192.0.2.20:8443/TCP",
		"manual override", "Public reachability is unverified",
	} {
		if !strings.Contains(review, marker) {
			t.Fatalf("narrow WSS review missing %q: %q", marker, review)
		}
	}
	if strings.Contains(review, "\x1b") {
		t.Fatalf("NO_COLOR WSS review contained ANSI: %q", review)
	}
	if _, err := io.WriteString(master, "\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("WSS preview cancellation returned %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WSS preview cancellation did not finish")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("WSS review cancellation wrote State or credentials: %v", err)
	}
}
