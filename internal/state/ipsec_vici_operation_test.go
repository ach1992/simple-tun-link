package state

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPsecVICIOperationDurablePreparedAndUncertainStates(t *testing.T) {
	ctx := context.Background()
	store := NewFileStore(filepath.Join(t.TempDir(), "private"))
	pending := pendingIPsecFixture()
	const nonce = "29b12628fa2ef1c20db6253af2f103b6"
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.PendingIPsec = append(s.PendingIPsec, pending)
		s.IPsecVICIOperations = append(s.IPsecVICIOperations, IPsecVICIOperation{
			Intent: pending, Nonce: nonce, Phase: IPsecVICIPrepared,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{IPsecVICIIssuingShared, IPsecVICISharedObserved,
		IPsecVICIIssuingConnection, IPsecVICIConnectionSeen} {
		if err := store.Update(ctx, func(s *Snapshot) error {
			s.IPsecVICIOperations[0].Phase = phase
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		reloaded, err := store.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := reloaded.FindIPsecVICIOperation(pending.Link.ID)
		if !ok || got.Phase != phase || got.Nonce != nonce ||
			got.Intent != pending || len(reloaded.PendingIPsec) != 1 || len(reloaded.Links) != 0 {
			t.Fatal("durable uncertain IPsec daemon phase lost or wrongly committed")
		}
	}
}

func TestIPsecVICIOperationRejectsOrphanCollisionAndCorruption(t *testing.T) {
	entry := pendingIPsecFixture()
	for name, mutate := range map[string]func(*Snapshot){
		"orphan": func(s *Snapshot) { s.PendingIPsec = nil },
		"wrong-link": func(s *Snapshot) {
			s.IPsecVICIOperations[0].Intent.Link.Underlay.Peer = s.IPsecVICIOperations[0].Intent.Link.Underlay.Local
		},
		"changed-handoff-digest": func(s *Snapshot) { s.IPsecVICIOperations[0].Intent.HandoffSHA256 = strings.Repeat("b", 64) },
		"changed-origin": func(s *Snapshot) {
			s.IPsecVICIOperations[0].Intent.Origin = "recipient"
			s.IPsecVICIOperations[0].Intent.HandoffSHA256 = ""
		},
		"missing-nonce":   func(s *Snapshot) { s.IPsecVICIOperations[0].Nonce = "" },
		"all-zero-nonce":  func(s *Snapshot) { s.IPsecVICIOperations[0].Nonce = strings.Repeat("0", 32) },
		"uppercase-nonce": func(s *Snapshot) { s.IPsecVICIOperations[0].Nonce = strings.Repeat("A", 32) },
		"malformed-nonce": func(s *Snapshot) { s.IPsecVICIOperations[0].Nonce = strings.Repeat("x", 32) },
		"unknown-phase":   func(s *Snapshot) { s.IPsecVICIOperations[0].Phase = "owned-and-safe-to-delete" },
		"duplicate":       func(s *Snapshot) { s.IPsecVICIOperations = append(s.IPsecVICIOperations, s.IPsecVICIOperations[0]) },
		"committed":       func(s *Snapshot) { s.Upsert(LinkRecord{Desired: entry.Link}) },
	} {
		t.Run(name, func(t *testing.T) {
			s := EmptySnapshot()
			s.PendingIPsec = append(s.PendingIPsec, entry)
			s.IPsecVICIOperations = append(s.IPsecVICIOperations, IPsecVICIOperation{
				Intent: entry, Nonce: "29b12628fa2ef1c20db6253af2f103b6", Phase: IPsecVICIPrepared,
			})
			mutate(&s)
			if err := validateSnapshot(s); err == nil {
				t.Fatal("unsafe/orphaned IPsec VICI journal accepted")
			}
		})
	}
}
