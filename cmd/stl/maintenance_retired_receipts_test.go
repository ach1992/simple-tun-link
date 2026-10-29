package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestRetiredWSSReceiptAllowsCoreUninstallButNeverDownlevelState(t *testing.T) {
	opts, sender, _, _, _ := savedExternalWSSFixture(t)
	root := opts.stateRoot
	store := state.NewFileStore(root)
	ctx := context.Background()
	original, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record, exists := original.Find(sender.ID)
	if !exists {
		t.Fatal("missing saved WSS original")
	}
	receipt := state.RemovalReceipt{
		LinkID: sender.ID, Backend: domain.BackendWireGuardWSS,
		LocalPublicKey: sender.WireGuard.LocalPublicKey,
		WSSLink:        sender, WSSFiles: record.WSSFiles,
		WSSOriginalTermination: state.WSSOriginalExactIfIndexDeleted,
		Retired:                true,
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		if !s.Delete(sender.ID) {
			t.Fatal("original was not present")
		}
		s.RemovalReceipts = append(s.RemovalReceipts, receipt)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	untrustedRoot := func(string) error { return nil } // private test-only fake path
	if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{}, untrustedRoot); err != nil {
		t.Fatalf("retired WSS receipt stranded core Uninstall: %v", err)
	}
	if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{installed: true}, untrustedRoot); err == nil {
		t.Fatal("owned restore unit was ignored in presence of retired receipt")
	}
	if err := inspectDowngradeReady(ctx, root, fakeUninstallUnit{}, untrustedRoot); err == nil ||
		!strings.Contains(err.Error(), "downgrade requires a canonical empty State") {
		t.Fatalf("historical identity was silently discarded by downgrade: %v", err)
	}
	code, display, errs := runMenuTest(t, root, "7\n8\n")
	if code != 0 || errs != "" ||
		!strings.Contains(display, "Retired receipts") ||
		!strings.Contains(display, "installed_root_terminal_required") ||
		strings.Contains(display, string(sender.ID)) ||
		(sender.DisplayName != "" && strings.Contains(display, sender.DisplayName)) ||
		strings.Contains(display, "saved_or_pending_links") {
		t.Fatalf("menu did not preserve a safe receipt-aware Uninstall preview: code=%d display=%q errors=%q", code, display, errs)
	}
	after, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatalf("read-only Uninstall and downgrade checks changed State: %v", err)
	}
	for _, malformed := range []struct {
		name, duplicate string
	}{
		{"duplicate retired flag", `"retired":false,"retired":true`},
		{"case-aliased retired flag", `"Retired":false,"retired":true`},
		{"escaped retired flag", `"retir\u0065d":false,"retired":true`},
	} {
		t.Run(malformed.name, func(t *testing.T) {
			unsafe := regexp.MustCompile(`"retired"\s*:\s*true`).ReplaceAll(raw, []byte(malformed.duplicate))
			if bytes.Equal(unsafe, raw) {
				t.Fatal("receipt test input did not include retired field")
			}
			if err := os.WriteFile(statePath, unsafe, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{}, untrustedRoot); err == nil {
				t.Fatal("duplicate nested receipt authorization admitted")
			}
			if err := os.WriteFile(statePath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.RemovalReceipts[0].Retired = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{}, untrustedRoot); err == nil ||
		!strings.Contains(err.Error(), "protected credential retirement remains") {
		t.Fatalf("unretired WSS receipt authorized Uninstall: %v", err)
	}
	code, display, errs = runMenuTest(t, root, "7\n8\n")
	if code != 0 || errs != "" || !strings.Contains(display, "credential_retirement_pending") ||
		strings.Contains(display, string(sender.ID)) {
		t.Fatalf("unretired WSS receipt menu diagnostics incorrect: %d %q %q", code, display, errs)
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.RemovalReceipts[0].Retired = true
		s.RemovalReceipts[0].WSSOriginalTermination = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{}, untrustedRoot); err == nil {
		t.Fatal("legacy WSS receipt without original termination proof authorized Uninstall")
	}
}

func TestRetiredNativeAndIPsecReceiptsPreservedButIncompleteRetirementBlocksUninstall(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "state")
	nativeID := domain.LinkID("lnk_" + strings.Repeat("b", 32))
	ipsecID := domain.LinkID("lnk_" + strings.Repeat("c", 32))
	store := state.NewFileStore(root)
	native := state.RemovalReceipt{LinkID: nativeID, Backend: domain.BackendWireGuard,
		LocalPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), Retired: true}
	ipsec := state.IPsecRemovalReceipt{LinkID: ipsecID, PSKSHA256: strings.Repeat("d", 64), Retired: true}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.RemovalReceipts = append(s.RemovalReceipts, native)
		s.IPsecRemovalReceipts = append(s.IPsecRemovalReceipts, ipsec)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	trust := func(string) error { return nil } // test-only
	if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{}, trust); err != nil {
		t.Fatalf("fully retired native and IPsec receipt prevented uninstall: %v", err)
	}
	if err := inspectDowngradeReady(ctx, root, fakeUninstallUnit{}, trust); err == nil {
		t.Fatal("downlevel binary admitted retained retired receipt history")
	}
	for _, target := range []struct {
		name string
		edit func(*state.Snapshot)
	}{
		{"native", func(s *state.Snapshot) { s.RemovalReceipts[0].Retired = false }},
		{"ipsec", func(s *state.Snapshot) { s.IPsecRemovalReceipts[0].Retired = false }},
	} {
		t.Run(target.name, func(t *testing.T) {
			if err := store.Update(ctx, func(s *state.Snapshot) error {
				target.edit(s)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := inspectUninstallReady(ctx, root, fakeUninstallUnit{}, trust); err == nil {
				t.Fatal("pending retirement was admitted")
			}
			if err := store.Update(ctx, func(s *state.Snapshot) error {
				s.RemovalReceipts[0].Retired = true
				s.IPsecRemovalReceipts[0].Retired = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDowngradePreflightStillRequiresCanonicalEmptySnapshot(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "state.json")
	trust := func(string) error { return nil }
	for _, tc := range []struct {
		content string
		want    bool
	}{
		{`{"schema_version":4,"links":[]}`, true},
		{`{"schema_version":4,"links":[],"removal_receipts":[]}`, false},
		{`{"schema_version":4,"links":[],"wss_crash_operations":[]}`, false},
		{`{"schema_version":4,"links":[],"links":[{"desired":{"id":"retained"}}]}`, false},
	} {
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		got := inspectDowngradeReady(ctx, root, fakeUninstallUnit{}, trust) == nil
		if got != tc.want {
			t.Fatalf("downgrade gate mismatch: permitted=%t want=%t", got, tc.want)
		}
		if raw, err := os.ReadFile(path); err != nil || string(raw) != tc.content {
			t.Fatal("downgrade preflight modified original State", err)
		}
	}
}
