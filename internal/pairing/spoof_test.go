package pairing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestSpoofSetupSingleConfidentialHandoff(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	var pub [32]byte
	pub[0] = 17
	s, err := NewSpoofSetup(id,
		netip.MustParseAddrPort("198.51.100.10:17001"),
		netip.MustParseAddrPort("203.0.113.20:17002"),
		netip.MustParseAddr("10.23.1.0"),
		netip.MustParseAddr("10.23.1.1"), pub)
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.EncodeSensitive()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSensitiveSpoofSetup(code)
	if err != nil || got.id != s.id || got.creator != s.creator ||
		got.recipient != s.recipient || got.secret != s.secret || got.creatorPublic != pub {
		t.Fatalf("offline import mismatch: %v", err)
	}
	other := code[:len(code)-1] + "x"
	if _, err := DecodeSensitiveSpoofSetup(other); err == nil {
		t.Fatal("tampered Setup Code accepted")
	}
	generic, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(generic, []byte("bootstrap_secret")) ||
		strings.Contains(fmt.Sprintf("%+v", s), fmt.Sprintf("%x", s.secret)) {
		t.Fatal("generic display leaked confidential bootstrap")
	}
	if _, err := DecodeSensitiveSpoofSetup("not a Setup Code"); err == nil {
		t.Fatal("invalid offer accepted")
	}
}

// The confidential offline Setup Code must pin the selected OUTER protocol.
// A recipient cannot silently accept ICMP on an allegedly UDP Link.
func TestSpoofSetupICMPProfilePinnedInSingleOfflineCode(t *testing.T) {
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	var pub [32]byte
	pub[0] = 42
	offer, err := NewSpoofSetup(id,
		netip.MustParseAddrPort("192.0.2.10:42101"),
		netip.MustParseAddrPort("198.51.100.20:42102"),
		netip.MustParseAddr("10.245.64.1"),
		netip.MustParseAddr("10.245.64.2"), pub)
	if err != nil {
		t.Fatal(err)
	}
	offer, err = offer.WithOuterProtocol("icmp")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := offer.EncodeSensitive()
	if err != nil {
		t.Fatal(err)
	}
	received, err := DecodeSensitiveSpoofSetup(raw)
	if err != nil || received.OuterProtocol() != "icmp" {
		t.Fatalf("recipient lost immutable profile: %v", err)
	}
	for _, profile := range []string{"auto", "tcp", "gre", "ipip", "proto58", "proto58-echo", "l2tpv3"} {
		candidate, e := offer.WithOuterProtocol(profile)
		if e != nil {
			t.Fatalf("STL raw profile %s rejected: %v", profile, e)
		}
		code, e := candidate.EncodeSensitive()
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := DecodeSensitiveSpoofSetup(code)
		if e != nil || decoded.OuterProtocol() != profile {
			t.Fatalf("STL profile %s not pinned in offline Code: %v", profile, e)
		}
	}
	if _, err = offer.WithOuterProtocol("not-a-profile"); err == nil {
		t.Fatal("unknown experimental outer profile accepted")
	}
}
