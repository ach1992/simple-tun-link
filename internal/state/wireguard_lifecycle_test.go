package state

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func validPublicForLifecycleTest(t *testing.T, seed byte) string {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}
func validPendingForLifecycleTest(t *testing.T) PendingSender {
	t.Helper()
	return PendingSender{
		Link: domain.Link{
			ID:            "lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			Backend:       domain.BackendWireGuard,
			Encapsulation: domain.EncapUDP,
			Underlay:      domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("192.0.2.11")},
			Addresses:     domain.LinkAddresses{Local: netip.MustParsePrefix("10.80.70.0/31"), Peer: netip.MustParsePrefix("10.80.70.1/31")},
			WireGuard:     domain.WireGuardOptions{LocalPublicKey: validPublicForLifecycleTest(t, 1), PeerPublicKey: validPublicForLifecycleTest(t, 2), ListenPort: 51871, PeerPort: 51872},
		},
		HandoffSHA256: strings.Repeat("a", 64),
	}
}
func TestWireGuardPendingAndRemovalReceiptAreValidatedDurablePublicState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store := NewFileStore(root)
	ctx := context.Background()
	pending := validPendingForLifecycleTest(t)
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.PendingSenders = append(s.PendingSenders, pending)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, found := saved.FindPendingSender(pending.Link.ID)
	if !found || got != pending || len(saved.Links) != 0 {
		t.Fatal("durable pending public intent changed")
	}
	// A pending sender has no receiver private credential in state.json.
	raw, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "recipient_secret") || strings.Contains(string(raw), "private_key") {
		t.Fatal("secret-bearing field appeared in public lifecycle snapshot")
	}
	// Pending + committed for same ID is invalid even if the inner Link matches.
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.Upsert(LinkRecord{Desired: pending.Link})
		return nil
	}); err == nil {
		t.Fatal("pending+committed dual authority was accepted")
	}
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.DeletePendingSender(pending.Link.ID)
		s.Upsert(LinkRecord{Desired: pending.Link})
		return nil
	}); err != nil {
		t.Fatal("atomic pending->committed transition failed", err)
	}
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.Delete(pending.Link.ID)
		s.RemovalReceipts = append(s.RemovalReceipts, RemovalReceipt{LinkID: pending.Link.ID, Backend: domain.BackendWireGuard, LocalPublicKey: pending.Link.WireGuard.LocalPublicKey})
		return nil
	}); err != nil {
		t.Fatal("Link-specific public receipt state invalid", err)
	}
	proof, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receipt, found := proof.FindRemovalReceipt(pending.Link.ID)
	if !found || receipt.Retired || receipt.LocalPublicKey != pending.Link.WireGuard.LocalPublicKey || len(proof.Links) != 0 {
		t.Fatal("durable retirement proof incorrect")
	}
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.Upsert(LinkRecord{Desired: pending.Link})
		return nil
	}); err == nil {
		t.Fatal("retirement proof coexisted with new committed Link")
	}
}

func TestWireGuardLifecycleRejectsInvalidOrDuplicatedUntrustedRecords(t *testing.T) {
	base := validPendingForLifecycleTest(t)
	for name, alter := range map[string]func(*Snapshot){
		"invalid-hash":      func(s *Snapshot) { s.PendingSenders[0].HandoffSHA256 = strings.Repeat("G", 64) },
		"duplicate-pending": func(s *Snapshot) { s.PendingSenders = append(s.PendingSenders, s.PendingSenders[0]) },
		"missing-port":      func(s *Snapshot) { s.PendingSenders[0].Link.WireGuard.ListenPort = 0 },
		"incorrect-backend": func(s *Snapshot) { s.PendingSenders[0].Link.Backend = domain.BackendGRE },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := EmptySnapshot()
			snapshot.PendingSenders = []PendingSender{base}
			alter(&snapshot)
			if err := validateSnapshot(snapshot); err == nil {
				t.Fatal("invalid sender lifecycle data passed validation")
			}
		})
	}
	validReceipt := RemovalReceipt{LinkID: base.Link.ID, Backend: domain.BackendWireGuard, LocalPublicKey: base.Link.WireGuard.LocalPublicKey}
	for name, alter := range map[string]func(*Snapshot){
		"foreign-backend":      func(s *Snapshot) { s.RemovalReceipts[0].Backend = domain.BackendGRE },
		"invalid-key":          func(s *Snapshot) { s.RemovalReceipts[0].LocalPublicKey = "invalid" },
		"duplicate-receipt":    func(s *Snapshot) { s.RemovalReceipts = append(s.RemovalReceipts, s.RemovalReceipts[0]) },
		"pending-with-receipt": func(s *Snapshot) { s.PendingSenders = []PendingSender{base} },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := EmptySnapshot()
			snapshot.RemovalReceipts = []RemovalReceipt{validReceipt}
			alter(&snapshot)
			if err := validateSnapshot(snapshot); err == nil {
				t.Fatal("invalid retirement evidence passed validation")
			}
		})
	}
}
