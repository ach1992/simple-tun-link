package quic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestQUICGenerationExclusiveFirstCreationInterleavings(t *testing.T) {
	const nonce = "1234567890abcdef1234567890abcdef"
	for _, test := range []struct {
		name string
		hook func(t *testing.T, dir string, bundle CredentialBundle) *generationStageHooks
	}{
		{"identical foreign file after mkdir", func(t *testing.T, dir string, bundle CredentialBundle) *generationStageHooks {
			return &generationStageHooks{afterMkdir: func() error {
				files := bundle.ProtectedFiles()
				defer clearRoleFiles(files)
				return os.WriteFile(filepath.Join(dir, "server-cert.pem"), files["server-cert.pem"], 0o600)
			}}
		}},
		{"directory replaced after mkdir", func(t *testing.T, dir string, _ CredentialBundle) *generationStageHooks {
			return &generationStageHooks{afterMkdir: func() error {
				if err := os.Rename(dir, dir+"-original"); err != nil {
					return err
				}
				return os.Mkdir(dir, 0o700)
			}}
		}},
		{"one identical inode replacement after creation", func(t *testing.T, dir string, _ CredentialBundle) *generationStageHooks {
			return &generationStageHooks{afterFile: func(name string) error {
				if name != "authorization-token" {
					return nil
				}
				path := filepath.Join(dir, name)
				raw, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				defer clear(raw)
				replacement := filepath.Join(dir, ".independent-inode")
				if err := os.WriteFile(replacement, raw, 0o600); err != nil {
					return err
				}
				return os.Rename(replacement, path)
			}}
		}},
		{"foreign helper config inserted before create", func(t *testing.T, dir string, _ CredentialBundle) *generationStageHooks {
			return &generationStageHooks{beforeFile: func(name string) error {
				if name != "helper.json" {
					return nil
				}
				return os.WriteFile(filepath.Join(dir, name), []byte("identical-content-not-required-to-refuse"), 0o600)
			}}
		}},
		{"interrupt after all files but before receipt", func(t *testing.T, dir string, _ CredentialBundle) *generationStageHooks {
			return &generationStageHooks{beforeReceipt: func() error {
				return errors.New("injected interruption")
			}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, port := helperConfigPlan(domainTestLinkID(), Listen)
			root := privateStateRoot(t)
			server, client, err := GeneratePair(plan.LinkID, plan.TLSName)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Clear()
			defer client.Clear()
			expected, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, server, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "credentials", "quic", string(plan.LinkID))
			_, err = stageJournalGenerationWithHooks(context.Background(), root, plan, port,
				fixtureHysteriaPath, nonce, server, expected, fixtureHysteriaAdmission, test.hook(t, dir, server))
			if err == nil {
				t.Fatal("unverified foreign/interrupted generation received a successful receipt")
			}
			for _, path := range []string{dir, dir + "-original"} {
				if _, err := os.Stat(path); err == nil {
					if _, e := os.Lstat(filepath.Join(path, generationReceiptName)); !os.IsNotExist(e) {
						t.Fatalf("unverified generation minted an ownership receipt: %s (%v)", path, e)
					}
				}
			}
			if err := InspectGenerationReceipt(root, plan, nonce, expected); err == nil {
				t.Fatal("foreign/interrupted generation was adopted by read-only inspector")
			}
			_, err = stageJournalGeneration(context.Background(), root, plan, port,
				fixtureHysteriaPath, nonce, server, expected, fixtureHysteriaAdmission)
			if err == nil || !strings.Contains(err.Error(), "lacks proven creation ownership") {
				t.Fatalf("uncertain existing generation re-adopted on retry: %v", err)
			}
			if _, e := os.Lstat(filepath.Join(dir, generationReceiptName)); !os.IsNotExist(e) {
				t.Fatalf("retry created a receipt for an uncertain generation: %v", e)
			}
		})
	}
}

// A new creation and an exact, durable idempotent retry are separate paths.
// The second path must not use the first path's exclusive-file writer.
func TestQUICGenerationConfirmedRetryRetainsEveryCreatedInode(t *testing.T) {
	plan, port := helperConfigPlan(domain.LinkID("lnk_88888888888888888888888888888888"), Dial)
	root := privateStateRoot(t)
	server, client, err := GeneratePair(plan.LinkID, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	defer client.Clear()
	want, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, client, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "0123456789abcdef0123456789abcdef"
	_, err = stageJournalGeneration(context.Background(), root, plan, port, fixtureHysteriaPath,
		nonce, client, want, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "credentials", "quic", string(plan.LinkID))
	before := make(map[string]os.FileInfo)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 6 {
		t.Fatalf("unexpected generation inventory: %v, %v", entries, err)
	}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		before[entry.Name()] = info
	}
	_, err = stageJournalGeneration(context.Background(), root, plan, port, fixtureHysteriaPath,
		nonce, client, want, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatalf("positive matching generation cannot retry: %v", err)
	}
	for name, info := range before {
		current, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !os.SameFile(info, current) {
			t.Fatalf("retry unexpectedly rewrote originally created inode %s: %v", name, err)
		}
	}
}
