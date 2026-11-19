package state

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func masqueStateTestLink() domain.Link {
	return domain.Link{
		ID:      "lnk_0123456789abcdef0123456789abcdef",
		Backend: domain.BackendMASQUE, Encapsulation: domain.EncapTLS,
		Underlay: domain.Underlay{
			Local: mustAddrMASQUE("2a10:ed40::1"), Peer: mustAddrMASQUE("2a01:4f8::2")},
		Addresses: domain.LinkAddresses{
			Local: mustPrefixMASQUE("10.252.99.2/32"), Peer: mustPrefixMASQUE("10.252.99.1/32")},
		MASQUE: domain.MASQUEOptions{
			Role: "dial", TCPPort: 443, TLSServerName: "masque-test.example",
			MaterialSHA256: strings.Repeat("a", 64),
		},
	}
}

func mustAddrMASQUE(s string) netip.Addr     { return netip.MustParseAddr(s) }
func mustPrefixMASQUE(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func masqueStateClaims(link domain.Link) []domain.ResourceClaim {
	return []domain.ResourceClaim{
		{Kind: domain.ResourceBackendID, Key: "masque/material/" + string(link.ID) + "/" + link.MASQUE.MaterialSHA256},
		{Kind: domain.ResourceBackendID, Key: "masque/unit/" + string(link.ID)},
		{Kind: domain.ResourceInterface, Key: "stlm" + string(link.ID)[4:15]},
		{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
		{Kind: domain.ResourceRoute, Key: "masque/peer/" + link.Addresses.Peer.String()},
	}
}
func TestMASQUEStateJournalAtomicCompletionAndRetirement(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s := NewFileStore(root)
	link := masqueStateTestLink()
	claims := masqueStateClaims(link)
	// Normalize claim order prior to operation, just as Engine does.
	sort.Slice(claims, func(i, j int) bool { return claims[i].Canonical() < claims[j].Canonical() })
	op := MASQUEOperation{Intent: link, Operation: "ensure", Nonce: strings.Repeat("b", 64), Resources: claims}
	if err := s.Update(ctx, func(doc *Snapshot) error { doc.MASQUEOperations = append(doc.MASQUEOperations, op); return nil }); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load(ctx)
	if err != nil || len(loaded.Links) != 0 || len(loaded.MASQUEOperations) != 1 {
		t.Fatalf("pending state missing %v", err)
	}
	if err := s.Update(ctx, func(doc *Snapshot) error { doc.DeleteMASQUEOperation(link.ID); return nil }); err == nil {
		t.Fatal("dropped pre-effect journal without exact committed Link")
	}
	if err := s.Update(ctx, func(doc *Snapshot) error {
		doc.Upsert(LinkRecord{Desired: link, OwnedResources: claims, MASQUELastEffectNonce: op.Nonce})
		doc.DeleteMASQUEOperation(link.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err = s.Load(ctx)
	if err != nil || len(loaded.MASQUEOperations) != 0 || len(loaded.Links) != 1 {
		t.Fatalf("expected committed Link %v", err)
	}
	op = MASQUEOperation{Intent: link, Operation: "remove", Nonce: strings.Repeat("c", 64), HadCommittedLink: true, Resources: claims}
	if err := s.Update(ctx, func(doc *Snapshot) error { doc.MASQUEOperations = append(doc.MASQUEOperations, op); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(doc *Snapshot) error {
		doc.Delete(link.ID)
		doc.MASQUERemovalReceipts = append(doc.MASQUERemovalReceipts, MASQUERemovalReceipt{Link: link, MaterialSHA256: link.MASQUE.MaterialSHA256, Purpose: "removed"})
		doc.DeleteMASQUEOperation(link.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err = s.Load(ctx)
	receipt, ok := loaded.FindMASQUERemovalReceipt(link.ID)
	if err != nil || len(loaded.Links) != 0 || len(loaded.MASQUEOperations) != 0 || !ok || receipt.Retired {
		t.Fatalf("removed Link lost original protected receipt: %v", err)
	}
	if err := s.Update(ctx, func(doc *Snapshot) error {
		for i := range doc.MASQUERemovalReceipts {
			doc.MASQUERemovalReceipts[i].Retired = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(doc *Snapshot) error { doc.DeleteMASQUERemovalReceipt(link.ID); return nil }); err == nil {
		t.Fatal("erased original material retirement receipt")
	}
}

func TestMASQUEStateRejectsLegacyGraftedCarrier(t *testing.T) {
	for _, version := range []int{1, 3, 4, 5, 6} {
		for _, graft := range []string{
			`"masque_operations":[]`,
			`"links":[{"desired":{"masque":{"role":"listen"}}}]`,
			`"masque_removal_receipts":null`,
		} {
			root := t.TempDir()
			raw := []byte(`{"schema_version":` + strconv.Itoa(version) + `,` + graft + `}`)
			if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileStore(root).Load(context.Background()); err == nil {
				t.Fatalf("legacy State %d accepted MASQUE graft %s", version, graft)
			}
		}
	}
}

func TestMASQUEStateRoundtripNoSecretAndStableOwners(t *testing.T) {
	link := masqueStateTestLink()
	s := EmptySnapshot()
	s.Upsert(LinkRecord{Desired: link, OwnedResources: masqueStateClaims(link), MASQUELastEffectNonce: strings.Repeat("c", 64)})
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "password") {
		t.Fatal("State should never include credential material")
	}
	var restored Snapshot
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Links, s.Links) {
		t.Fatal("MASQUE nonsecret Link model changed during State roundtrip")
	}
}
