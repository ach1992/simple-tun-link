package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type fakeUninstallUnit struct {
	installed bool
	err       error
}

func (f fakeUninstallUnit) IsRestoreInstalled(context.Context) (bool, error) {
	return f.installed, f.err
}

func TestUninstallPreflightCanonicalStateAndUnit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	root := filepath.Join(dir, "engine-state")
	// The trust-path injection allows an isolated user-owned fixture without
	// weakening production's root ownership gate.
	testTrust := func(string) error { return nil }
	unitAbsent := fakeUninstallUnit{}

	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err != nil {
		t.Fatalf("never-used missing root should be safe: %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err == nil ||
		!strings.Contains(err.Error(), "no committed state") {
		t.Fatalf("existing root with missing state must fail closed, got %v", err)
	}
	store := state.NewFileStore(root)
	if err := store.Update(ctx, func(s *state.Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err != nil {
		t.Fatalf("durable empty snapshot should be safe without unit: %v", err)
	}
	if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{installed: true}, testTrust); err == nil {
		t.Fatal("canonical restore unit present must block uninstall")
	}
	if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{err: errors.New("enabled unit without file")}, testTrust); err == nil {
		t.Fatal("ambiguous enabled systemd identity must block uninstall")
	}

	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	link := domain.Link{
		ID: id, Backend: domain.BackendGRE, Encapsulation: domain.EncapNative,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.10"),
			Peer:  netip.MustParseAddr("198.51.100.20"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.80.20.0/31"),
			Peer:  netip.MustParsePrefix("10.80.20.1/31"),
		},
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err == nil {
		t.Fatal("configured Link must block uninstall")
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Delete(id)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "state.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err == nil {
		t.Fatal("symlinked state snapshot must block uninstall")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err == nil {
		t.Fatal("corrupt state snapshot must block uninstall")
	}
}

func TestPreUninstallStateRootSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "state")
	if err := os.Symlink(t.TempDir(), root); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(context.Background(), root, fakeUninstallUnit{},
		func(string) error { return nil }); err == nil {
		t.Fatal("symlinked state root must block uninstall")
	}
}
