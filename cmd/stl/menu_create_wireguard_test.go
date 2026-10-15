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
	file, err := protectedMenuHandoffPath(&runtimeOptions{stateRoot: root}, createTestID)
	if err != nil {
		t.Fatal(err)
	}
	host := &guidedTestRunner{}
	fake := &wireGuardCreatorFake{newLifecycleFake()}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}, probeRunner: host,
		mtuManager:   guidedMTUFake{},
		createLinkID: func() (domain.LinkID, error) { return createTestID, nil }}
	stdin := "1\n2\n192.0.2.20\n\n51871\n51872\nn\nYES\n8\n"
	var out, stderr bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(stdin), &out, &stderr, opts)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("guided WG failed: %d %s %s", code, out.String(), stderr.String())
	}
	if !strings.Contains(out.String(), "REVIEW / CONFIRM WIREGUARD") || !strings.Contains(out.String(), "WireGuard Link") ||
		!strings.Contains(out.String(), "SENSITIVE") || strings.Contains(out.String(), "stl://") || len(fake.applies) != 1 {
		t.Fatalf("guided create bypassed safe public preview/Engine: %s applies=%v", out.String(), fake.applies)
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("guided private handoff not mode 0600", err)
	}
	parentInfo, err := os.Lstat(filepath.Dir(file))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o700 {
		t.Fatal("guided protected handoff directory must be 0700", err)
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
	root := filepath.Join(base, "state")
	file, err := protectedMenuHandoffPath(&runtimeOptions{stateRoot: root}, createTestID)
	if err != nil {
		t.Fatal(err)
	}
	host := &guidedTestRunner{}
	fake := &wireGuardCreatorFake{newLifecycleFake()}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}, probeRunner: host,
		mtuManager:   guidedMTUFake{},
		createLinkID: func() (domain.LinkID, error) { return createTestID, nil }}
	stdin := "1\n2\n192.0.2.20\n\n51871\n51872\nn\nNO\n8\n"
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
