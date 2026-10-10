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

func TestMenuUpdateGuidancePinsExactReleaseWithoutExecutingAnything(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, out, errOut := runMenuTest(t, root, "6\nv0.1.0\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("guided update failed: code=%d stderr=%q", code, errOut)
	}
	for _, want := range []string{
		"releases/tag/v0.1.0",
		"/v0.1.0/scripts/install.sh",
		"sudo bash /path/to/verified/install.sh update --version v0.1.0",
		"No remote lookup, update, service restart or host change",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing guided update safeguard %q: %q", want, out)
		}
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("guided update mutated local state: %v", err)
	}
}

func TestMenuUpdateRejectsInjectionAndDoesNotEchoInput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	payload := "v0.1.0; touch /tmp/private-menu-injection"
	code, out, errOut := runMenuTest(t, root, "6\n"+payload+"\n")
	if code != 2 || !strings.Contains(errOut, "Invalid release tag") ||
		strings.Contains(out+errOut, payload) || strings.Contains(out, "sudo bash") {
		t.Fatalf("untrusted tag accepted or echoed: code=%d out=%q err=%q", code, out, errOut)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid update created state: %v", err)
	}
}

func TestMenuUninstallOnlyGuidesExistingLinkRemoval(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link, _ := makeLifecycleDesired(t, "a", "10.70.91.0/31")
	link.DisplayName = "private-do-not-print"
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "state.json")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runMenuTest(t, root, "7\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("uninstall guidance failed: code=%d err=%q", code, errOut)
	}
	if !strings.Contains(out, "BLOCKED: 1 configured Link") ||
		!strings.Contains(out, "stl link remove "+string(link.ID)+" --confirm "+string(link.ID)) ||
		strings.Contains(out, "sudo bash /path/to/verified/install.sh uninstall") ||
		strings.Contains(out, link.DisplayName) {
		t.Fatalf("uninstall was not safely blocked or leaked saved data: %q", out)
	}
	after, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("uninstall menu modified persisted Link state: %v", err)
	}
}

func TestMenuUninstallZeroLinksIsNotProofOfSafety(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, out, errOut := runMenuTest(t, root, "7\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("zero-Link handoff failed: code=%d err=%q", code, errOut)
	}
	for _, want := range []string{
		"NOT proof uninstall is safe",
		"sudo stl maintenance pre-uninstall --json",
		"sudo bash /path/to/verified/install.sh uninstall",
		"No uninstall or host change was performed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("zero-Link case silently bypassed canonical proof: %q", out)
		}
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("zero-Link guidance created state: %v", err)
	}
}

func TestMenuUninstallFailsClosedOnCorruptState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runMenuTest(t, root, "7\n8\n")
	if code != 1 || !strings.Contains(errOut, "Uninstall blocked") ||
		strings.Contains(out, "sudo bash /path/to/verified/install.sh uninstall") {
		t.Fatalf("corrupt state was treated as safe: code=%d out=%q err=%q", code, out, errOut)
	}
	original, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil || string(original) != "{corrupt" {
		t.Fatalf("uninstall guidance altered damaged state: %v", err)
	}
}
