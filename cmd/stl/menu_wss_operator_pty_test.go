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
