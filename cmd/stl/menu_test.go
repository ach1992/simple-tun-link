package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	code, output, errOut := runMenuTest(t, root, "1\n2\n3\n\n4\n\n5\n6\n7\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("menu failed: code=%d err=%q", code, errOut)
	}
	for _, item := range []string{
		"simple-tun-link", "Host:", "OS:", "Kernel:",
		"Local address candidate:", "Configured Links: 0",
		"Create Tunnel", "Import Setup Link", "Manage Links",
		"Tests & Diagnostics", "Settings", "Update", "Uninstall", "Exit",
		"stl link preview --stdin", "stl link ensure --stdin",
		"Not implemented", "0 configured link(s)", "bounded probes",
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
	if !strings.Contains(output, "Configured Links: 1") ||
		!strings.Contains(output, string(link.ID)) ||
		strings.Contains(output, link.DisplayName) {
		t.Fatal("menu failed Link summary projection or disclosed arbitrary display name")
	}
}

func TestMenuRejectsOversizedOrInvalidInputsWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, output, errOut := runMenuTest(t, root, strings.Repeat("VERY_PRIVATE", 20)+"\n8\n")
	if code != 2 || !strings.Contains(errOut, "too long") || strings.Contains(output+errOut, "VERY_PRIVATE") {
		t.Fatalf("unbounded or leaked interactive input: code=%d out=%q err=%q", code, output, errOut)
	}
	code, output, errOut = runMenuTest(t, root, "4\ninvalid-id\n")
	if code != 2 || !strings.Contains(errOut, "invalid Link ID") || !strings.Contains(output, "no host configuration") {
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
	got := safeMenuText("host\x1b[31m\nnow")
	if strings.Contains(got, "\x1b") || strings.Contains(got, "\n") ||
		!strings.Contains(got, "host") {
		t.Fatalf("unsafe console label: %q", got)
	}
}
