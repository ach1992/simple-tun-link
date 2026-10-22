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
