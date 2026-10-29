package quic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func stageInspectionFixture(t *testing.T, role Role) (string, Plan, uint16, HelperConfigIdentity, string, string) {
	t.Helper()
	root := privateStateRoot(t)
	plan, port := helperConfigPlan(domainTestLinkID(), role)
	listen, dial, err := GeneratePair(plan.LinkID, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listen.Clear(); dial.Clear() })
	bundle := listen
	if role == Dial {
		bundle = dial
	}
	expected, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, bundle, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "0123456789abcdef0123456789abcdef"
	if got, err := stageJournalGeneration(context.Background(), root, plan, port,
		fixtureHysteriaPath, nonce, bundle, expected, fixtureHysteriaAdmission); err != nil || got != expected {
		t.Fatalf("could not stage original owned generation: %v", err)
	}
	dir := filepath.Join(root, "credentials", "quic", string(plan.LinkID))
	return root, plan, port, expected, nonce, dir
}

// Copies only matching PRIVATE bytes, not the create-time receipt. An
// identical material digest never gives this foreign directory ownership.
func copyForeignQUICGeneration(t *testing.T, dir string, role Role) string {
	t.Helper()
	foreign := dir + "-foreign"
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	names, err := generationFiles(role)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(filepath.Join(foreign, name), raw, 0o600)
		clear(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	return foreign
}

// This executes the same production reader, with deterministic hooks
// injected only at the read-only receipt/semantic boundaries. The public
// reader has no hooks and always verifies the official Hysteria executable.
func TestQUICJournalInspectionRejectsDirectoryGenerationSwap(t *testing.T) {
	for _, role := range []Role{Dial, Listen} {
		for _, boundary := range []string{"before-receipt", "after-receipt", "after-semantic"} {
			t.Run(string(role)+"/"+boundary, func(t *testing.T) {
				root, plan, port, expected, nonce, dir := stageInspectionFixture(t, role)
				foreign := copyForeignQUICGeneration(t, dir, role)
				swapped := false
				swap := func() error {
					if err := os.Rename(dir, dir+"-original"); err != nil {
						return err
					}
					if err := os.Rename(foreign, dir); err != nil {
						return err
					}
					swapped = true
					return nil
				}
				hooks := &generationInspectHooks{}
				switch boundary {
				case "before-receipt":
					hooks.beforeReceipt = swap
				case "after-receipt":
					hooks.afterReceipt = swap
				case "after-semantic":
					hooks.afterSemantic = swap
				}
				got, err := inspectJournalGeneration(root, plan, port, fixtureHysteriaPath,
					nonce, expected, fixtureHysteriaAdmission, hooks)
				if err == nil || got != (HelperConfigIdentity{}) || !swapped {
					t.Fatalf("mixed original receipt with foreign generation: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(dir, generationReceiptName)); !os.IsNotExist(err) {
					t.Fatalf("foreign same-byte material gained a receipt: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(dir+"-original", generationReceiptName)); err != nil {
					t.Fatalf("original verified generation was modified or erased: %v", err)
				}
				if err := InspectGenerationReceipt(root, plan, nonce, expected); err == nil {
					t.Fatal("public receipt reader adopted foreign canonical directory")
				}
				if got, err := inspectJournalGeneration(root, plan, port, fixtureHysteriaPath,
					nonce, expected, fixtureHysteriaAdmission, nil); err == nil || got != (HelperConfigIdentity{}) {
					t.Fatal("public generation reader adopted foreign canonical directory")
				}
			})
		}
	}
}

func TestQUICJournalInspectionRejectsSameBytesNewInode(t *testing.T) {
	for _, boundary := range []string{"after-receipt", "after-semantic"} {
		t.Run(boundary, func(t *testing.T) {
			root, plan, port, expected, nonce, dir := stageInspectionFixture(t, Dial)
			replaced := false
			swap := func() error {
				target := filepath.Join(dir, "helper.json")
				raw, err := os.ReadFile(target)
				if err != nil {
					return err
				}
				defer clear(raw)
				replacement := filepath.Join(dir, ".independent-helper")
				if err := os.WriteFile(replacement, raw, 0o600); err != nil {
					return err
				}
				if err := os.Rename(replacement, target); err != nil {
					return err
				}
				replaced = true
				return nil
			}
			hooks := &generationInspectHooks{}
			if boundary == "after-receipt" {
				hooks.afterReceipt = swap
			} else {
				hooks.afterSemantic = swap
			}
			got, err := inspectJournalGeneration(root, plan, port, fixtureHysteriaPath,
				nonce, expected, fixtureHysteriaAdmission, hooks)
			if err == nil || got != (HelperConfigIdentity{}) || !replaced {
				t.Fatalf("same-byte new inode gained ownership: %v", err)
			}
			if err := InspectGenerationReceipt(root, plan, nonce, expected); err == nil {
				t.Fatal("replaced helper inode passed original receipt")
			}
		})
	}
}

func TestQUICJournalInspectionRejectsReplacedCanonicalParent(t *testing.T) {
	for _, ancestor := range []string{"quic", "credentials"} {
		t.Run(ancestor, func(t *testing.T) {
			root, plan, port, expected, nonce, dir := stageInspectionFixture(t, Listen)
			var parent string
			if ancestor == "quic" {
				parent = filepath.Dir(dir)
			} else {
				parent = filepath.Dir(filepath.Dir(dir))
			}
			got, err := inspectJournalGeneration(root, plan, port, fixtureHysteriaPath,
				nonce, expected, fixtureHysteriaAdmission, &generationInspectHooks{
					afterSemantic: func() error {
						if err := os.Rename(parent, parent+"-original"); err != nil {
							return err
						}
						return os.Mkdir(parent, 0o700)
					},
				})
			if err == nil || got != (HelperConfigIdentity{}) {
				t.Fatalf("canonical parent substitution passed generation inspection: %v", err)
			}
			original := filepath.Join(parent+"-original", string(plan.LinkID), generationReceiptName)
			if ancestor == "credentials" {
				original = filepath.Join(parent+"-original", "quic", string(plan.LinkID), generationReceiptName)
			}
			if _, err := os.Stat(original); err != nil {
				t.Fatalf("original owned receipt was removed during foreign ancestor substitution: %v", err)
			}
		})
	}
}

func TestQUICJournalInspectionPreservesValidDialListenAndStageRetry(t *testing.T) {
	for _, role := range []Role{Dial, Listen} {
		t.Run(string(role), func(t *testing.T) {
			root, plan, port, expected, nonce, _ := stageInspectionFixture(t, role)
			got, err := inspectJournalGeneration(root, plan, port, fixtureHysteriaPath,
				nonce, expected, fixtureHysteriaAdmission, nil)
			if err != nil || got != expected {
				t.Fatalf("unchanged original generation was rejected: %v", err)
			}
			if err := InspectGenerationReceipt(root, plan, nonce, expected); err != nil {
				t.Fatal(err)
			}
			// Stage retry is already covered with its original inode witnesses
			// in generation_receipt_test.go and generation_interleaving_test.go.
		})
	}
}
