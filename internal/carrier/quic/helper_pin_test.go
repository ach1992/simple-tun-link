package quic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedJournalGenerationRetainsExactMaterialAcrossEffect(t *testing.T) {
	for _, change := range []string{"none", "same-byte-config", "same-byte-receipt", "content-drift"} {
		t.Run(change, func(t *testing.T) {
			plan, port := helperConfigPlan(domainTestLinkID(), Listen)
			root := privateStateRoot(t)
			server, client, err := GeneratePair(plan.LinkID, plan.TLSName)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Clear()
			defer client.Clear()
			const nonce = "0123456789abcdef0123456789abcdef"
			want, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, server, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stageJournalGeneration(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, server, want, fixtureHysteriaAdmission); err != nil {
				t.Fatal(err)
			}
			calls := 0
			err = withPinnedJournalGeneration(context.Background(), root, plan, port, fixtureHysteriaPath, nonce, want, func() error {
				calls++
				if change == "none" {
					return nil
				}
				name := "helper.json"
				if change == "same-byte-receipt" {
					name = generationReceiptName
				}
				path := filepath.Join(root, "credentials", "quic", string(plan.LinkID), name)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(raw)
				if change != "content-drift" {
					if err := os.Rename(path, filepath.Join(root, "retained-"+name)); err != nil {
						t.Fatal(err)
					}
				} else {
					raw[0] ^= 1
				}
				return os.WriteFile(path, raw, 0o600)
			}, fixtureHysteriaAdmission)
			if calls != 1 {
				t.Fatal("material callback was not bounded to one effect")
			}
			if change == "none" && err != nil {
				t.Fatal(err)
			}
			if change != "none" && err == nil {
				t.Fatal("original held material replacement passed")
			}
		})
	}
}
