package quic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestQUICJournalGenerationOwnsExactlyCreatedFilesBothRoles(t *testing.T) {
	for _, role := range []Role{Dial, Listen} {
		t.Run(string(role), func(t *testing.T) {
			plan, port := helperConfigPlan(domainTestLinkID(), role)
			root := privateStateRoot(t)
			server, client, err := GeneratePair(plan.LinkID, plan.TLSName)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Clear()
			defer client.Clear()
			bundle := server
			if role == Dial {
				bundle = client
			}
			want, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath,
				bundle, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			const nonce = "1234567890abcdef1234567890abcdef"
			if _, err := os.Lstat(filepath.Join(root, "credentials")); !os.IsNotExist(err) {
				t.Fatal("preflight wrote credentials")
			}
			got, err := stageJournalGeneration(context.Background(), root, plan, port,
				fixtureHysteriaPath, nonce, bundle, want, fixtureHysteriaAdmission)
			if err != nil || got != want {
				t.Fatalf("fresh exact journal generation rejected: %v", err)
			}
			if err := InspectGenerationReceipt(root, plan, nonce, want); err != nil {
				t.Fatalf("durable create-time receipt invalid: %v", err)
			}
			dir := filepath.Join(root, "credentials", "quic", string(plan.LinkID))
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 6 {
				t.Fatalf("expected five private files and receipt, got %v, %v", entries, err)
			}
			inodes := make(map[string]os.FileInfo, 6)
			for _, entry := range entries {
				info, err := os.Lstat(filepath.Join(dir, entry.Name()))
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
					t.Fatalf("unsafe generation artifact %q: %v", entry.Name(), err)
				}
				inodes[entry.Name()] = info
			}
			retry, err := stageJournalGeneration(context.Background(), root, plan, port,
				fixtureHysteriaPath, nonce, bundle, want, fixtureHysteriaAdmission)
			if err != nil || retry != want {
				t.Fatalf("verified same-generation retry failed: %v", err)
			}
			for name, old := range inodes {
				now, err := os.Lstat(filepath.Join(dir, name))
				if err != nil || !os.SameFile(old, now) {
					t.Fatalf("retry replaced generation inode %q: %v", name, err)
				}
			}
			if err := InspectGenerationReceipt(root, plan,
				"abcdef1234567890abcdef1234567890", want); err == nil {
				t.Fatal("foreign journal nonce adopted protected generation")
			}
			if err := os.WriteFile(filepath.Join(dir, "foreign"), []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := InspectGenerationReceipt(root, plan, nonce, want); err == nil {
				t.Fatal("new unknown artifact accepted by durable receipt")
			}
		})
	}
}

func TestQUICJournalGenerationNeverAdoptsLegacyOrInterruptedIdenticalFiles(t *testing.T) {
	plan, port := helperConfigPlan(domainTestLinkID(), Listen)
	server, _, err := GeneratePair(plan.LinkID, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	const nonce = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name  string
		stage func(string, HelperConfigIdentity) error
	}{
		{"complete legacy five files without receipt", func(root string, expected HelperConfigIdentity) error {
			_, e := stageExpectedMaterials(context.Background(), root, plan, port,
				fixtureHysteriaPath, server, expected, fixtureHysteriaAdmission)
			return e
		}},
		{"interrupted credentials only", func(root string, _ HelperConfigIdentity) error {
			_, e := StageCredentials(root, plan, server)
			return e
		}},
		{"orphan private generation directory", func(root string, _ HelperConfigIdentity) error {
			return os.MkdirAll(filepath.Join(root, "credentials", "quic", string(plan.LinkID)), 0o700)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := privateStateRoot(t)
			want, err := previewHelperConfig(root, plan, port,
				fixtureHysteriaPath, server, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.stage(root, want); err != nil {
				t.Fatal(err)
			}
			_, err = stageJournalGeneration(context.Background(), root, plan, port,
				fixtureHysteriaPath, nonce, server, want, fixtureHysteriaAdmission)
			if err == nil || !strings.Contains(err.Error(), "lacks proven creation ownership") {
				t.Fatalf("existing private materials were post-hoc adopted: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "credentials", "quic",
				string(plan.LinkID), generationReceiptName)); !os.IsNotExist(err) {
				t.Fatalf("failed adoption forged a generation receipt: %v", err)
			}
		})
	}
}

func TestQUICJournalGenerationDetectsInodeReplacementDespiteIdenticalBytes(t *testing.T) {
	plan, port := helperConfigPlan(domainTestLinkID(), Dial)
	root := privateStateRoot(t)
	_, dial, err := GeneratePair(plan.LinkID, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Clear()
	want, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath,
		dial, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "1234567890abcdef1234567890abcdef"
	if _, err := stageJournalGeneration(context.Background(), root, plan, port,
		fixtureHysteriaPath, nonce, dial, want, fixtureHysteriaAdmission); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "credentials", "quic", string(plan.LinkID))
	target := filepath.Join(dir, "helper.json")
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(original) })
	// Create a different inode while the original still exists, then swap.
	// An unlink/recreate test could accidentally reuse the same inode.
	replacement := filepath.Join(dir, ".replacement")
	if err := os.WriteFile(replacement, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, target); err != nil {
		t.Fatal(err)
	}
	if err := InspectGenerationReceipt(root, plan, nonce, want); err == nil {
		t.Fatal("identical replacement inode bypassed create-time receipt")
	}
	if _, err := stageJournalGeneration(context.Background(), root, plan, port,
		fixtureHysteriaPath, nonce, dial, want, fixtureHysteriaAdmission); err == nil {
		t.Fatal("generation retry silently adopted a replaced private inode")
	}
}

func TestQUICJournalGenerationRejectsInvalidOrCancelledIntentWithoutFiles(t *testing.T) {
	plan, port := helperConfigPlan(domain.LinkID("lnk_88888888888888888888888888888888"), Listen)
	server, _, err := GeneratePair(plan.LinkID, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	for _, nonce := range []string{"", "abc", strings.Repeat("G", 32), strings.Repeat("1", 34)} {
		root := privateStateRoot(t)
		want, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, server, fixtureHysteriaAdmission)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stageJournalGeneration(context.Background(), root, plan, port,
			fixtureHysteriaPath, nonce, server, want, fixtureHysteriaAdmission); err == nil {
			t.Fatal("unsafe journal nonce admitted")
		}
		if _, err := os.Lstat(filepath.Join(root, "credentials")); !os.IsNotExist(err) {
			t.Fatal("invalid journal created credentials")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := privateStateRoot(t)
	want, _ := previewHelperConfig(root, plan, port, fixtureHysteriaPath, server, fixtureHysteriaAdmission)
	if _, err := stageJournalGeneration(ctx, root, plan, port, fixtureHysteriaPath,
		"1234567890abcdef1234567890abcdef", server, want, fixtureHysteriaAdmission); err == nil {
		t.Fatal("cancelled generation wrote credentials")
	}
	if _, err := os.Lstat(filepath.Join(root, "credentials")); !os.IsNotExist(err) {
		t.Fatal("canceled operation published protected files")
	}
}
