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
