package state

import (
	"bytes"
	"context"
	"encoding/json"
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

// State v2 before this source-only journal remains readable. Once a
// journal-bearing v2 snapshot exists, an old strictly decoding v2 reader
// must *reject* it rather than silently dropping unknown safety metadata.
// This is a documented no-downgrade policy until explicit schema migration.
func TestIPsecVICIOperationV2ReaderCompatibilityMatrix(t *testing.T) {
	ctx := context.Background()
	store := NewFileStore(filepath.Join(t.TempDir(), "state"))
	entry := pendingIPsecFixture()
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.PendingIPsec = append(s.PendingIPsec, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	oldSnapshot, err := store.Load(ctx)
	if err != nil || len(oldSnapshot.PendingIPsec) != 1 ||
		len(oldSnapshot.IPsecVICIOperations) != 0 {
		t.Fatalf("old journal-free v2 state incompatible: %v", err)
	}
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.IPsecVICIOperations = append(s.IPsecVICIOperations, IPsecVICIOperation{
			Intent: entry, Nonce: "29b12628fa2ef1c20db6253af2f103b6", Phase: IPsecVICIPrepared,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fresh, err := store.Load(ctx)
	if err != nil || len(fresh.IPsecVICIOperations) != 1 || fresh.SchemaVersion != SchemaVersion {
		t.Fatalf("new v2 reader rejected explicit journal-bearing state: %v", err)
	}
	raw, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	type oldReaderV2 struct {
		SchemaVersion   int              `json:"schema_version"`
		Links           []LinkRecord     `json:"links"`
		PendingSenders  []PendingSender  `json:"pending_senders,omitempty"`
		PendingIPsec    []PendingIPsec   `json:"pending_ipsec,omitempty"`
		RemovalReceipts []RemovalReceipt `json:"removal_receipts,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var old oldReaderV2
	if err := d.Decode(&old); err == nil || !strings.Contains(err.Error(), "ipsec_vici_operations") {
		t.Fatalf("older strict v2 reader unexpectedly accepted/dropped journal: %v", err)
	}
}
