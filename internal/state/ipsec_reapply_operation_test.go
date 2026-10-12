package state

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func committedIPsecRecoveryFixture(t *testing.T) (Snapshot, domain.Link) {
	t.Helper()
	entry := pendingIPsecFixture()
	state := EmptySnapshot()
	state.Upsert(LinkRecord{Desired: entry.Link})
	return state, entry.Link
}

func TestIPsecCommittedReapplyJournalPersistsAdjacentPhases(t *testing.T) {
	ctx := context.Background()
	s, l := committedIPsecRecoveryFixture(t)
	store := NewFileStore(filepath.Join(t.TempDir(), "private"))
	nonce := "29b12628fa2ef1c20db6253af2f103b6"
	if err := store.Update(ctx, func(w *Snapshot) error {
		*w = s
		w.IPsecReapplyOperations = append(w.IPsecReapplyOperations, IPsecReapplyOperation{
			Intent: l, Nonce: nonce, Phase: IPsecVICIPrepared})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{IPsecVICIIssuingShared, IPsecVICISharedObserved,
		IPsecVICIIssuingConnection, IPsecVICIConnectionSeen} {
		err := store.Update(ctx, func(w *Snapshot) error {
			w.IPsecReapplyOperations[0].Phase = phase
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		restored, err := store.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := restored.FindIPsecReapplyOperation(l.ID)
		if !ok || got.Intent != l || got.Nonce != nonce || got.Phase != phase {
			t.Fatal("committed-Link VICI transaction identity not preserved")
		}
		if len(restored.PendingIPsec) != 0 || len(restored.IPsecVICIOperations) != 0 || len(restored.Links) != 1 {
			t.Fatal("committed reapply journal contaminated initial activation/state")
		}
	}
}

func TestIPsecReapplyJournalRejectsOrphanAndUnsafeIdentity(t *testing.T) {
	for label, change := range map[string]func(*Snapshot){
		"orphan":            func(s *Snapshot) { s.Links = nil },
		"mismatched-intent": func(s *Snapshot) { s.IPsecReapplyOperations[0].Intent.Encapsulation = "definitely_invalid" },
		"wrong-backend":     func(s *Snapshot) { s.IPsecReapplyOperations[0].Intent.Backend = domain.BackendGRE },
		"bad-nonce":         func(s *Snapshot) { s.IPsecReapplyOperations[0].Nonce = strings.Repeat("0", 32) },
		"unknown-phase":     func(s *Snapshot) { s.IPsecReapplyOperations[0].Phase = "safe-to-unload" },
		"duplicate": func(s *Snapshot) {
			s.IPsecReapplyOperations = append(s.IPsecReapplyOperations, s.IPsecReapplyOperations[0])
		},
		"pending-overlap": func(s *Snapshot) { s.PendingIPsec = append(s.PendingIPsec, pendingIPsecFixture()) },
	} {
		t.Run(label, func(t *testing.T) {
			s, l := committedIPsecRecoveryFixture(t)
			s.IPsecReapplyOperations = []IPsecReapplyOperation{{
				Intent: l, Nonce: "29b12628fa2ef1c20db6253af2f103b6", Phase: IPsecVICIPrepared,
			}}
			change(&s)
			if err := validateSnapshot(s); err == nil {
				t.Fatal("ambiguous committed IPsec recovery journal was accepted")
			}
		})
	}
}
