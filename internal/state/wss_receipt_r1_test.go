package state

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestR1WSSRetirementReceiptPreservesExactPublicIdentityWithoutSecrets(t *testing.T) {
	link := validPendingForLifecycleTest(t).Link
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443, TLSServerName: "192.0.2.10"}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	issued := WSSFileIdentity{Certificate: digest, TLSKey: digest, TrustCA: digest,
		Authorization: digest, Restrictions: digest}
	receipt := RemovalReceipt{LinkID: link.ID, Backend: link.Backend,
		LocalPublicKey: link.WireGuard.LocalPublicKey, WSSLink: link, WSSFiles: issued,
		WSSOriginalTermination: WSSOriginalExactIfIndexDeleted}
	root := filepath.Join(t.TempDir(), "state")
	store := NewFileStore(root)
	ctx := context.Background()
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.RemovalReceipts = append(s.RemovalReceipts, receipt)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exact, ok := saved.FindRemovalReceipt(link.ID)
	if !ok || exact != receipt {
		t.Fatal("durable WSS retirement receipt lost exact nonsecret Link identity")
	}
	raw, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"authorization-token", "authorization-headers", "private_key", "recipient_secret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("secret field in WSS public receipt")
		}
	}
	var clean map[string]any
	if err := json.Unmarshal(raw, &clean); err != nil {
		t.Fatal(err)
	}
	legacy := receipt
	legacy.WSSOriginalTermination = ""
	legacySnapshot := EmptySnapshot()
	legacySnapshot.RemovalReceipts = []RemovalReceipt{legacy}
	if err := validateSnapshot(legacySnapshot); err != nil {
		t.Fatalf("legacy receipt must remain readable, but ineligible for Engine retirement: %v", err)
	}
	for label, alter := range map[string]func(*RemovalReceipt){
		"missing-original-link": func(r *RemovalReceipt) { r.WSSLink = domain.Link{} },
		"wrong-underlay":        func(r *RemovalReceipt) { r.WSSLink.Underlay.Local = domain.Underlay{}.Local },
		"wrong-public-key":      func(r *RemovalReceipt) { r.WSSLink.WireGuard.LocalPublicKey = r.WSSLink.WireGuard.PeerPublicKey },
		"wrong-receipt-owner":   func(r *RemovalReceipt) { r.LinkID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		"wrong-backend":         func(r *RemovalReceipt) { r.WSSLink.Backend = domain.BackendWireGuard },
		"unexpected-native-wss": func(r *RemovalReceipt) { r.Backend = domain.BackendWireGuard },
		"unknown-termination":   func(r *RemovalReceipt) { r.WSSOriginalTermination = "invalid-source" },
	} {
		t.Run(label, func(t *testing.T) {
			s := EmptySnapshot()
			copyReceipt := receipt
			alter(&copyReceipt)
			s.RemovalReceipts = []RemovalReceipt{copyReceipt}
			if err := validateSnapshot(s); err == nil {
				t.Fatal("accepted mismatched or unauthorized WSS retirement receipt")
			}
		})
	}
}
