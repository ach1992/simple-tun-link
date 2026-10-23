package state

import (
	"context"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/hostidentity"
)

func TestWSSCommittedBootGenerationProvenanceSchemaAndLegacyReadability(t *testing.T) {
	link, _ := crashJournalStateFixture(t)
	files := WSSFileIdentity{Certificate: strings.Repeat("a", 64), TLSKey: strings.Repeat("a", 64), TrustCA: strings.Repeat("a", 64), Authorization: strings.Repeat("a", 64), Restrictions: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name, boot, source string
		accepted           bool
	}{
		{"legacy-untrusted", "", "", true},
		{"trusted-birth", "11111111-1111-4111-8111-111111111111", hostidentity.VerifiedHostBootSourceV1, true},
		{"missing-source", "11111111-1111-4111-8111-111111111111", "", false},
		{"orphaned-source", "", hostidentity.VerifiedHostBootSourceV1, false},
		{"unknown-source", "11111111-1111-4111-8111-111111111111", "v2-unknown", false},
		{"invalid-boot", "boot-malformed", hostidentity.VerifiedHostBootSourceV1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewFileStore(t.TempDir())
			record := LinkRecord{Desired: link, WSSFiles: files, WSSOrigin: strings.Repeat("a", 32), WSSKernelBootID: tc.boot, WSSKernelBootSource: tc.source}
			err := store.Update(context.Background(), func(s *Snapshot) error { s.Links = append(s.Links, record); return nil })
			if (err == nil) != tc.accepted {
				t.Fatalf("provenance admitted=%t expected=%t: %v", err == nil, tc.accepted, err)
			}
			if !tc.accepted {
				return
			}
			restored, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			exact, ok := restored.Find(link.ID)
			if !ok || exact.WSSKernelBootID != tc.boot || exact.WSSKernelBootSource != tc.source {
				t.Fatal("legacy or trusted generation lost during Store readback")
			}
		})
	}
}

// The manual Restore authority is not a historical birth marker. It survives
// FileStore restart only with complete, versioned pre/post kernel evidence,
// can be spent only once and cannot coexist with a claimed original birth.
func TestWSSManualColdBootRestoreProofSchemaAndDurableSpending(t *testing.T) {
	link, _ := crashJournalStateFixture(t)
	digest := strings.Repeat("a", 64)
	files := WSSFileIdentity{Certificate: digest, TLSKey: digest, TrustCA: digest, Authorization: digest, Restrictions: digest}
	source := hostidentity.VerifiedHostBootSourceV1
	from, to := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	for _, tc := range []struct {
		name  string
		proof WSSColdBootRestore
		birth string
		valid bool
	}{
		{"legacy-no-proof", WSSColdBootRestore{}, "", true},
		{"verified-manual", WSSColdBootRestore{ArmedFrom: from, ReconciledAt: to, Source: source}, "", true},
		{"spent", WSSColdBootRestore{ArmedFrom: from, ReconciledAt: to, Source: source, Spent: true}, "", true},
		{"uuid-only", WSSColdBootRestore{ArmedFrom: from, ReconciledAt: to}, "", false},
		{"same-kernel", WSSColdBootRestore{ArmedFrom: from, ReconciledAt: from, Source: source}, "", false},
		{"invalid-from", WSSColdBootRestore{ArmedFrom: "invalid", ReconciledAt: to, Source: source}, "", false},
		{"invalid-to", WSSColdBootRestore{ArmedFrom: from, ReconciledAt: "invalid", Source: source}, "", false},
		{"unexpected-source", WSSColdBootRestore{ArmedFrom: from, ReconciledAt: to, Source: "unverified-v2"}, "", false},
		{"spent-without-proof", WSSColdBootRestore{Spent: true}, "", false},
		{"birth-and-manual", WSSColdBootRestore{ArmedFrom: from, ReconciledAt: to, Source: source}, from, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewFileStore(t.TempDir())
			rec := LinkRecord{Desired: link, WSSFiles: files, WSSOrigin: strings.Repeat("a", 32),
				WSSColdBootRestore: tc.proof, WSSKernelBootID: tc.birth}
			if tc.birth != "" {
				rec.WSSKernelBootSource = source
			}
			err := store.Update(context.Background(), func(s *Snapshot) error {
				s.Links = append(s.Links, rec)
				return nil
			})
			if (err == nil) != tc.valid {
				t.Fatalf("admission=%t expected=%t err=%v", err == nil, tc.valid, err)
			}
			if !tc.valid {
				return
			}
			saved, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			recovered, ok := saved.Find(link.ID)
			if !ok || recovered.WSSColdBootRestore != tc.proof ||
				recovered.WSSKernelBootSource != "" {
				t.Fatal("FileStore lost manual source proof or silently stamped birth")
			}
			if tc.name == "legacy-no-proof" && recovered.WSSColdBootRestore != (WSSColdBootRestore{}) {
				t.Fatal("old Link was promoted to new recovery authorization")
			}
			if tc.name == "verified-manual" {
				if !recovered.WSSColdBootRestore.AvailableOn(to) ||
					!recovered.WSSColdBootRestore.AvailableOn("33333333-3333-4333-8333-333333333333") ||
					recovered.WSSColdBootRestore.AvailableOn(from) ||
					recovered.WSSColdBootRestore.AvailableOn("") {
					t.Fatal("manual recovery proof accepted original/untrusted boot")
				}
				recovered.WSSColdBootRestore.Spent = true
				if err := store.Update(context.Background(), func(s *Snapshot) error { s.Upsert(recovered); return nil }); err != nil {
					t.Fatal(err)
				}
				later, err := store.Load(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				exact, _ := later.Find(link.ID)
				if exact.WSSColdBootRestore.AvailableOn(to) || !exact.WSSColdBootRestore.Spent {
					t.Fatal("spent authorization was replayed after FileStore reload")
				}
			}
		})
	}
}
