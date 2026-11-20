//go:build linux

package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Assert the actual guided Create path, not only a helper predicate. Both
// backends must reach Review after invalid SAN retries without credentials,
// host operations or saved State.
func TestQUICGuidedPTYRetriesTLSAndWarnsOnNonOnLinkBeforeCancel(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "xterm")
	root := filepath.Join(t.TempDir(), "absent-state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, &guidedTestRunner{}, fake)
	master, slave := openMenuPTY(t)
	helperPath := filepath.Join(t.TempDir(), "unused-helper")
	done := make(chan int, 1)
	go func() {
		// Only the non-mutating helper-readiness preflight is mocked.
		// The canonical production entrypoint always verifies pinned identity.
		done <- menuCreateQUICWithInspection(slave, bufio.NewReader(slave), slave, slave,
			opts, helperPath, func() error { return nil })
	}()
	for _, step := range []struct{ prompt, answer string }{
		{"Other server's IPv4 address (peer may be offline", "192.0.2.20\n"},
		{"Tunnel IP on THIS server", "10.87.2.10/32\n"},
		{"Tunnel IP on OTHER server", "10.87.3.11/32\n"},
		{"Direction [Enter=suggested; 1=listen; 2=dial]: ", "2\n"},
		{"QUIC mode [1]: ", "3\n"},
		{"Public QUIC/TLS UDP port [443]: ", "\n"},
		{"Kernel WG UDP port on THIS server", "\n"},
		{"Kernel WG UDP port on OTHER server", "\n"},
		{"THIS server's private loopback forwarding UDP port", "\n"},
	} {
		readMenuPTYUntil(t, master, step.prompt)
		if _, err := io.WriteString(master, step.answer); err != nil {
			t.Fatal(err)
		}
	}
	var transcript strings.Builder
	for _, bad := range []string{"bad@name", "bad:name", "BAD.EXAMPLE", "192.0.2.33", "singlelabel"} {
		transcript.WriteString(readMenuPTYUntil(t, master, "TLS certificate SAN"))
		if _, err := io.WriteString(master, bad+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	transcript.WriteString(readMenuPTYUntil(t, master, "TLS certificate SAN"))
	if !strings.Contains(transcript.String(), "IP SAN must match") ||
		!strings.Contains(transcript.String(), "QUIC requires") {
		t.Fatalf("QUIC invalid SAN did not retry at its own field: %q", transcript.String())
	}
	// Enter selects the actual physical listening peer IP.
	if _, err := io.WriteString(master, "\n"); err != nil {
		t.Fatal(err)
	}
	readMenuPTYUntil(t, master, "Customize kernel WireGuard keepalive")
	if _, err := io.WriteString(master, "n\n"); err != nil {
		t.Fatal(err)
	}
	review := readMenuPTYUntil(t, master, "Create QUIC Link and private receiver handoff? Type YES")
	normalized := strings.Join(strings.Fields(review), " ")
	for _, marker := range []string{
		"QUIC", "10.87.2.10/32", "10.87.3.11/32",
		"These custom CIDRs do not provide reciprocal on-link routing",
		"STL does not add an extra host route",
		"saving a Link is not evidence of peer connectivity",
	} {
		if !strings.Contains(normalized, marker) {
			t.Fatalf("guided QUIC review missing %q: %q", marker, review)
		}
	}
	if _, err := io.WriteString(master, "\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("QUIC cancellation failed: code=%d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("QUIC review cancellation did not finish")
	}
	if len(fake.applies) != 0 {
		t.Fatalf("QUIC canceled Create applied %d host operations", len(fake.applies))
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("QUIC canceled Create persisted State or protected credentials: %v", err)
	}
}

func TestWireGuardGuidedPTYNonOnLinkRouteWarningBeforeCancel(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "xterm")
	root := filepath.Join(t.TempDir(), "absent-state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, &guidedTestRunner{}, fake)
	master, slave := openMenuPTY(t)
	done := make(chan int, 1)
	go func() {
		done <- menuCreateWireGuard(slave, bufio.NewReader(slave), slave, slave, opts)
	}()
	for _, step := range []struct{ prompt, answer string }{
		{"Other server's IPv4 address (peer may be offline", "192.0.2.20\n"},
		{"Tunnel IP on THIS server", "10.87.2.10/32\n"},
		{"Tunnel IP on OTHER server", "10.87.3.11/32\n"},
		{"UDP port on THIS server", "\n"},
		{"UDP port on OTHER server", "\n"},
		{"Change advanced keepalive or local MTU settings", "n\n"},
	} {
		readMenuPTYUntil(t, master, step.prompt)
		if _, err := io.WriteString(master, step.answer); err != nil {
			t.Fatal(err)
		}
	}
	review := readMenuPTYUntil(t, master, "Create the encrypted tunnel and private handoff file? Type YES")
	normalized := strings.Join(strings.Fields(review), " ")
	for _, marker := range []string{
		"10.87.2.10/32", "10.87.3.11/32",
		"These custom CIDRs do not provide reciprocal on-link routing",
		"STL does not add an extra host route",
		"saving a Link is not evidence of peer connectivity",
	} {
		if !strings.Contains(normalized, marker) {
			t.Fatalf("guided WG review missing %q: %q", marker, review)
		}
	}
	if _, err := io.WriteString(master, "\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("WireGuard cancel returned %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WireGuard review cancellation did not finish")
	}
	if len(fake.applies) != 0 {
		t.Fatalf("WireGuard cancel applied %d host operations", len(fake.applies))
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("WireGuard canceled Create persisted State or protected credentials: %v", err)
	}
}
