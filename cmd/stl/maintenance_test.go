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
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err != nil {
		t.Fatalf("verified empty root should be safe: %v", err)
	}
	locks := filepath.Join(root, "locks")
	if err := os.Mkdir(locks, 0o700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(locks, strings.Repeat("a", 64)+".lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err != nil {
		t.Fatalf("STL-generated lock-only root must not strand Uninstall: %v", err)
	}
	if err := os.WriteFile(filepath.Join(locks, "other"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err == nil {
		t.Fatal("unknown file inside orphan locks was accepted")
	}
	if err := os.Remove(filepath.Join(locks, "other")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "foreign"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, unitAbsent, testTrust); err == nil {
		t.Fatal("unknown state-root entry was accepted")
	}
	if err := os.Remove(filepath.Join(root, "foreign")); err != nil {
		t.Fatal(err)
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

// Exercise the *same* canonical pre-Uninstall path used by the installed
// menu and by the installer under FD9. The FileStore decoder would otherwise
// let a later duplicate/case-aliased field overwrite earlier retained data.
type countingUninstallUnit struct {
	inspections int
	removals    int
}

func (u *countingUninstallUnit) IsRestoreInstalled(context.Context) (bool, error) {
	u.inspections++
	return false, nil
}
func (u *countingUninstallUnit) RemoveRestore(context.Context) error {
	u.removals++
	return nil
}

func TestPreUninstallRejectsAmbiguousOriginalStateBeforeAnyEffects(t *testing.T) {
	cases := []struct {
		name, raw string
		valid     bool
	}{
		{"canonical empty v4", `{"schema_version":4,"links":[]}`, true},
		{"canonical empty v3", `{"schema_version":3,"links":[]}`, true},
		{"supported optional empty operation array", `{"schema_version":4,"links":[],"wss_crash_operations":[]}`, true},
		{"retained Links overwritten by duplicate empty field", `{"schema_version":4,"links":[{"desired":{"id":"retained"}}],"links":[]}`, false},
		{"duplicate Links empty then retained", `{"schema_version":4,"links":[],"links":[{"desired":{"id":"retained"}}]}`, false},
		{"case-variant duplicate Links", `{"schema_version":4,"Links":[{"desired":{"id":"retained"}}],"links":[]}`, false},
		{"case-variant single Links alias", `{"schema_version":4,"Links":[]}`, false},
		{"escaped duplicate Links", `{"schema_version":4,"links":[{"desired":{"id":"retained"}}],"lin\u006bs":[]}`, false},
		{"duplicate schema version", `{"schema_version":3,"schema_version":4,"links":[]}`, false},
		{"duplicate pending operation keys", `{"schema_version":4,"links":[],"wss_crash_operations":[{"private":"retained"}],"wss_crash_operations":[]}`, false},
		{"aliased pending operation keys", `{"schema_version":4,"links":[],"Quic_Crash_Operations":[{"private":"retained"}],"quic_crash_operations":[]}`, false},
		{"duplicate removal receipt keys", `{"schema_version":4,"links":[],"removal_receipts":[{"id":"retained"}],"removal_receipts":[]}`, false},
		{"unknown field", `{"schema_version":4,"links":[],"unrecognized":[]}`, false},
		{"missing links field", `{"schema_version":4}`, false},
		{"null links field", `{"schema_version":4,"links":null}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "state")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "state.json")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			binary, record := filepath.Join(dir, "installed-stl"), filepath.Join(dir, "owner-record")
			for _, artifact := range []string{binary, record} {
				if err := os.WriteFile(artifact, []byte("original-installed-owner"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			unit := &countingUninstallUnit{}
			trust := func(string) error { return nil }
			err := inspectUninstallReady(context.Background(), root, unit, trust)
			if (err == nil) != tc.valid {
				t.Fatalf("unsafe Uninstall gate decision: valid=%t err=%v", tc.valid, err)
			}
			if !tc.valid {
				if unit.inspections != 0 {
					t.Fatalf("ambiguous State reached systemd: %d inspections", unit.inspections)
				}
				// Also prove the separately confirmed orphan-cleanup entry
				// cannot retire systemd on the same malformed State.
				if err := retireOrphanRestoreUnit(context.Background(), root, unit, trust); err == nil {
					t.Fatal("ambiguous State authorized orphan retirement")
				}
				if unit.removals != 0 || unit.inspections != 0 {
					t.Fatal("ambiguous State reached systemd retirement")
				}
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil || string(raw) != tc.raw {
				t.Fatalf("maintenance modified ambiguous State: %v", readErr)
			}
			for _, artifact := range []string{binary, record} {
				data, readErr := os.ReadFile(artifact)
				if readErr != nil || string(data) != "original-installed-owner" {
					t.Fatalf("maintenance changed original installed artifact %q: %v", artifact, readErr)
				}
			}
		})
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
