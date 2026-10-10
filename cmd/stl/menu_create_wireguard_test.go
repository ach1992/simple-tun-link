package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
)

func TestGuidedWireGuardCreatesConfirmedProtectedHandoff(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "state")
	parent := filepath.Join(base, "handoff")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(parent, "receiver.stl")
	host := &guidedTestRunner{}
	fake := &wireGuardCreatorFake{newLifecycleFake()}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}, probeRunner: host,
		createLinkID: func() (domain.LinkID, error) { return createTestID, nil }}
	stdin := "9\n192.0.2.20\n\nn\n51871\n51872\n25\n\n" + file + "\n" + string(createTestID) + "\n8\n"
	var out, stderr bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(stdin), &out, &stderr, opts)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("guided WG failed: %d %s %s", code, out.String(), stderr.String())
	}
	if !strings.Contains(out.String(), "PREVIEW ONLY") || !strings.Contains(out.String(), "WireGuard Link") ||
		!strings.Contains(out.String(), "SENSITIVE") || strings.Contains(out.String(), "stl://") || len(fake.applies) != 1 {
		t.Fatalf("guided create bypassed safe public preview/Engine: %s applies=%v", out.String(), fake.applies)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := pairing.DecodeSetupLink(strings.TrimSpace(string(content)))
	if err != nil || !offer.IsSensitive() || offer.Link().ID != createTestID {
		t.Fatalf("guided handoff not bound/sensitive: %v", err)
	}
}

func TestGuidedWireGuardCancelDoesNotGeneratePrivateFileOrState(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "handoff")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "state")
	file := filepath.Join(parent, "must-not-exist.stl")
	host := &guidedTestRunner{}
	fake := &wireGuardCreatorFake{newLifecycleFake()}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}, probeRunner: host,
		createLinkID: func() (domain.LinkID, error) { return createTestID, nil }}
	stdin := "9\n192.0.2.20\n\nn\n51871\n51872\n\n\n" + file + "\nNO\n8\n"
	var out, stderr bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(stdin), &out, &stderr, opts)
	if code != 0 || stderr.Len() != 0 || len(fake.applies) != 0 {
		t.Fatalf("cancel applied or failed: %d %s %s", code, out.String(), stderr.String())
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancel wrote sensitive file")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancel provisioned secret state")
	}
}
