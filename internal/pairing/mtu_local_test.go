package pairing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestQuickLinkNeverCopiesManagedLocalMTUOrAcceptsForgedPolicy(t *testing.T) {
	link := domain.Link{
		ID:        "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("192.0.2.20")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.80.66.0/31"), Peer: netip.MustParsePrefix("10.80.66.1/31")},
		Backend:   domain.BackendGRE, Encapsulation: domain.EncapNative,
		MTU: domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1350},
	}
	offer, err := NewQuickOffer(link, nil)
	if err != nil {
		t.Fatal(err)
	}
	if offer.Link().MTU != (domain.MTUPolicy{}) || offer.ReceiverLink().MTU != (domain.MTUPolicy{}) {
		t.Fatal("sender's endpoint-local MTU leaked to receiver")
	}
	encoded, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeSetupLink(encoded)
	if err != nil || restored.Link().MTU != (domain.MTUPolicy{}) {
		t.Fatalf("invalid portable pairing: %v", err)
	}
	// A correctly checksummed but schema-incompatible MTU cannot smuggle a
	// receiver-host policy through an existing v2 Quick Link.
	wire := wireOffer{SchemaVersion: SchemaVersion, Mode: ModeQuick, Link: link}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	forged := "stl://2." + base64.RawURLEncoding.EncodeToString(raw) + "." + hex.EncodeToString(sum[:])
	if _, err := DecodeSetupLink(forged); err == nil {
		t.Fatal("versioned pairing admitted endpoint-local MTU without protocol version decision")
	}
}
