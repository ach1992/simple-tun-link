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

func TestMenuUpdateGuidancePinsExactReleaseWithoutExecutingAnything(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, out, errOut := runMenuTest(t, root, "6\nv0.1.0\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("guided update failed: code=%d stderr=%q", code, errOut)
	}
	for _, want := range []string{
		"releases/tag/v0.1.0",
		"Do not pipe a mutable-tag download",
		"Manually entered tag was NOT verified",
		"LATEST COMPLETE PUBLIC RELEASES",
		"docs/INSTALL.md",
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
	if code != 0 || !strings.Contains(errOut, "Invalid release tag") ||
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
	if !strings.Contains(out, "Uninstall blocked: 1 saved tunnel") ||
		!strings.Contains(out, "My tunnels -> select tunnel -> Remove this tunnel") ||
		strings.Contains(out, string(link.ID)) ||
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
		"Zero saved Links",
		"installed_root_terminal_required",
		"sudo stl menu",
		"no external installer download is needed",
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
	if code != 0 || !strings.Contains(errOut, "Uninstall blocked") ||
		strings.Contains(out, "sudo bash /path/to/verified/install.sh uninstall") {
		t.Fatalf("corrupt state was treated as safe: code=%d out=%q err=%q", code, out, errOut)
	}
	original, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil || string(original) != "{corrupt" {
		t.Fatalf("uninstall guidance altered damaged state: %v", err)
	}
}

// Removing the Link first would lose the committed identity required by the
// sensitive receiver-handoff DELETE gate. Pure GRE/IPIP must not suggest it.
func TestMenuUninstallProtectedReceiverDecisionPrecedesRemoval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend domain.Backend
		encap   domain.Encapsulation
	}{
		{"WireGuard", domain.BackendWireGuard, domain.EncapUDP},
		{"IPsec", domain.BackendIPsec, domain.EncapESP},
		{"GRE", domain.BackendGRE, domain.EncapNative},
		{"IPIP", domain.BackendIPIP, domain.EncapNative},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			link, _ := makeLifecycleDesired(t, "a", "10.70.91.0/31")
			link.Backend, link.Encapsulation = tc.backend, tc.encap
			link.DisplayName = "confidential-do-not-print"
			if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
				s.Upsert(state.LinkRecord{Desired: link})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			code, out, errOut := runMenuTest(t, root, "7\n8\n")
			if code != 0 || errOut != "" {
				t.Fatalf("code=%d stderr=%q", code, errOut)
			}
			if strings.Contains(out, link.DisplayName) || strings.Contains(out, string(link.ID)) ||
				strings.Contains(out, "sudo bash /path/to/verified/install.sh uninstall") {
				t.Fatalf("uninstall leaked identity or bypassed preflight: %q", out)
			}
			protected := tc.backend == domain.BackendWireGuard || tc.backend == domain.BackendIPsec
			deletePos := strings.Index(out, "Delete receiver link -> type DELETE")
			removePos := strings.Index(out, "Remove this tunnel")
			if removePos < 0 {
				t.Fatalf("missing tunnel removal instruction: %q", out)
			}
			if protected {
				for _, want := range []string{"BEFORE removing", "KEEP or DELETE", "type DELETE",
					"survives tunnel removal and STL uninstall", "fresh confirmation"} {
					if !strings.Contains(out, want) {
						t.Fatalf("missing protected-retention choice %q: %q", want, out)
					}
				}
				if deletePos < 0 || deletePos >= removePos {
					t.Fatalf("private handoff deletion not before Link removal: %q", out)
				}
			} else if deletePos >= 0 || strings.Contains(out, "KEEP or DELETE") {
				t.Fatalf("private-handling instructions on plaintext backend: %q", out)
			}
			after, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil || !bytes.Equal(original, after) {
				t.Fatalf("read-only uninstall guidance altered State: %v", err)
			}
		})
	}
}
