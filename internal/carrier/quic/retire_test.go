package quic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedQUICRetirementResumesOriginalPartialDeletionBothRoles(t *testing.T) {
	for _, role := range []Role{Listen, Dial} {
		t.Run(string(role), func(t *testing.T) {
			root, plan, port, expected, nonce, dir := stageInspectionFixture(t, role)
			pin, err := openPinnedGeneration(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, expected, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			identity := pin.Identity()
			pin.Close()
			names, _ := roleFiles(role)
			if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
				t.Fatal(err)
			}
			if err := RetireOwnedGeneration(context.Background(), root, plan, nonce, expected, identity); err != nil {
				t.Fatal(err)
			}
			if absent, err := GenerationAbsent(root, plan.LinkID); err != nil || !absent {
				t.Fatal("original generation still present", err)
			}
			if err := RetireOwnedGeneration(context.Background(), root, plan, nonce, expected, identity); err != nil {
				t.Fatal("original missing generation retry failed:", err)
			}
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "foreign"), []byte("retained"), 0o600); err != nil {
				t.Fatal(err)
			}
			if absent, err := GenerationAbsent(root, plan.LinkID); err != nil || absent {
				t.Fatal("read-only consumed receipt missed reappeared material")
			}
			if _, err := os.Stat(filepath.Join(dir, "foreign")); err != nil {
				t.Fatal("read-only absence check modified replacement")
			}
		})
	}
}

func TestManagedQUICRetirementRejectsReplacementBeforeDeletingAnyFile(t *testing.T) {
	for _, change := range []string{"same-bytes-new-inode", "foreign-entry", "receipt-missing", "different-origin", "cancel"} {
		t.Run(change, func(t *testing.T) {
			root, plan, port, expected, nonce, dir := stageInspectionFixture(t, Listen)
			pin, err := openPinnedGeneration(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, expected, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			identity := pin.Identity()
			pin.Close()
			ctx := context.Background()
			switch change {
			case "same-bytes-new-inode":
				path := filepath.Join(dir, "server-key.pem")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(raw)
				if err := os.Rename(path, filepath.Join(root, "original-key")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			case "foreign-entry":
				if err := os.WriteFile(filepath.Join(dir, "foreign"), []byte("private"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "receipt-missing":
				if err := os.Remove(filepath.Join(dir, generationReceiptName)); err != nil {
					t.Fatal(err)
				}
			case "different-origin":
				nonce = "abcdefabcdefabcdefabcdefabcdefab"
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := RetireOwnedGeneration(ctx, root, plan, nonce, expected, identity); err == nil {
				t.Fatal("foreign or unverified material retired")
			}
			for _, name := range []string{"helper.json", "server-cert.pem", "authorization-token"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Fatalf("earlier original %s removed before full verification", name)
				}
			}
		})
	}
}

func TestManagedQUICRetirementOnlyRemovesExactEmptyDirectoryAfterReceiptUnlink(t *testing.T) {
	root, plan, port, expected, nonce, dir := stageInspectionFixture(t, Dial)
	pin, err := openPinnedGeneration(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, expected, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	identity := pin.Identity()
	pin.Close()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := RetireOwnedGeneration(context.Background(), root, plan, nonce, expected, identity); err != nil {
		t.Fatal(err)
	}
	if absent, err := GenerationAbsent(root, plan.LinkID); err != nil || !absent {
		t.Fatal("empty originating directory retained", err)
	}
}
