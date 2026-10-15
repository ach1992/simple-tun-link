package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func runMenuTest(t *testing.T, root, input string) (int, string, string) {
	t.Helper()
	var output, errorsOut bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(input),
		&output, &errorsOut, &runtimeOptions{stateRoot: root})
	return code, output.String(), errorsOut.String()
}

func TestMenuTasksAndNavigationDoNotCreateState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, output, errOut := runMenuTest(t, root, "1\n0\n3\n\n4\n5\n6\n\n7\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("menu failed: code=%d err=%q", code, errOut)
	}
	for _, item := range []string{
		"SIMPLE TUN LINK", "Host", "IPv4 candidate", "Tunnels           0 saved",
		"Create tunnel", "Import setup link", "My tunnels",
		"Test connectivity", "Settings", "Update", "Uninstall", "Exit",
		"GRE / Native", "CREATE TUNNEL",
		"Update cancelled", "pre-uninstall",
	} {
		if !strings.Contains(output, item) {
			t.Fatalf("menu omitted %q", item)
		}
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only menu unexpectedly created state root: %v", err)
	}
}

func TestMenuConfiguredLinksAreProjectedNotRawState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link, _ := makeLifecycleDesired(t, "a", "10.70.90.0/31")
	link.DisplayName = "do-not-echo-my-token"
	err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	code, output, errOut := runMenuTest(t, root, "3\n\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("read-only listing failed: code=%d error=%q", code, errOut)
	}
	if !strings.Contains(output, "Tunnels           1 saved") ||
		!strings.Contains(output, link.Addresses.Local.Addr().String()) ||
		strings.Contains(output, link.DisplayName) {
		t.Fatal("menu failed Link summary projection or disclosed arbitrary display name")
	}
}

func TestMenuRejectsOversizedOrInvalidInputsWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, output, errOut := runMenuTest(t, root, strings.Repeat("VERY_PRIVATE", 20)+"\n8\n")
	if code != 0 || !strings.Contains(output, "short number") || strings.Contains(output+errOut, "VERY_PRIVATE") {
		t.Fatalf("unbounded or leaked interactive input: code=%d out=%q err=%q", code, output, errOut)
	}
	code, output, errOut = runMenuTest(t, root, "4\n8\n")
	if code != 0 || !strings.Contains(output, "No saved tunnels") {
		t.Fatalf("invalid diagnostic ID executed unexpectedly: code=%d out=%q err=%q", code, output, errOut)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected input created state root: %v", err)
	}
}

func TestMenuEOFAndCommandArgumentBoundaries(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, _, errOut := runMenuTest(t, root, "")
	if code != 0 || errOut != "" {
		t.Fatalf("EOF exit failed: code=%d err=%q", code, errOut)
	}
	var out, errBuffer bytes.Buffer
	code = runWithRuntimeInput([]string{"menu", "--json"}, strings.NewReader("8\n"),
		&out, &errBuffer, &runtimeOptions{stateRoot: root})
	if code != 2 || out.Len() != 0 || !strings.Contains(errBuffer.String(), "usage: stl menu") {
		t.Fatalf("menu must not accept an automation JSON variant")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if terminalIsInteractive(r) || terminalIsInteractive(w) {
		t.Fatal("pipe must not be treated as a terminal")
	}
}

func TestMenuHeaderSanitizesUntrustedTerminalText(t *testing.T) {
	if got := safeMenuText(strings.Repeat("😀", 25)); len(got) > 96 {
		t.Fatalf("UTF-8 header exceeded 96-byte bound: %d", len(got))
	}
	got := safeMenuText("host\x1b[31m\nnow\u202eRTL\u2069\u200d")
	if strings.Contains(got, "\x1b") || strings.Contains(got, "\n") || strings.Contains(got, "\u202e") ||
		strings.Contains(got, "\u2069") || strings.Contains(got, "\u200d") ||
		!strings.Contains(got, "host") {
		t.Fatalf("unsafe console label: %q", got)
	}
}

func TestMenuAllLinkHealthIsReadOnlyAndReturnsToTasksOnBlockedBackend(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	gre := fixtureReadLink("lnk_11111111111111111111111111111111", "10.80.70.0/31", "10.80.70.1/31", domain.BackendGRE)
	ipsec := fixtureReadLink("lnk_22222222222222222222222222222222", "10.80.80.0/31", "10.80.80.1/31", domain.BackendIPsec)
	ipsec.Encapsulation = domain.EncapESP
	storeReadLinks(t, root, gre, ipsec)
	code, output, stderr := runMenuTest(t, root, "4\na\n8\n")
	if code != 0 || stderr != "" {
		t.Fatalf("blocked diagnosis should return to operator task menu: %d %q %q", code, output, stderr)
	}
	for _, want := range []string{
		"Check all tunnels", "Links in snapshot: 2",
		"ipsec_runtime_not_registered", "diagnostic_capability_unavailable",
		"Some checks are unknown, blocked",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing operator health result %q in %q", want, output)
		}
	}
	if strings.Contains(output, "DO_NOT_EXPOSE_OR_LOG") ||
		strings.Contains(output, "private_key=") {
		t.Fatalf("unsafe saved Link display name leaked through menu: %q", output)
	}
}
