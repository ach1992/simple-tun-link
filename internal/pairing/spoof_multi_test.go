package pairing

import (
	"net/netip"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestSpoofSingleCodeCarriesExactRealAlternateEndpoints(t *testing.T) {
	id, e := domain.NewLinkID()
	if e != nil {
		t.Fatal(e)
	}
	_, pub, e := spoof.GenerateIdentity()
	if e != nil {
		t.Fatal(e)
	}
	primaryA := netip.MustParseAddrPort("10.244.62.221:48001")
	primaryB := netip.MustParseAddrPort("10.244.62.222:48002")
	altA := netip.MustParseAddrPort("10.244.62.223:48011")
	altB := netip.MustParseAddrPort("10.244.62.224:48012")
	created, e := NewSpoofSetup(id, primaryA, primaryB, netip.MustParseAddr("10.245.100.1"), netip.MustParseAddr("10.245.100.2"), pub)
	if e != nil {
		t.Fatal(e)
	}
	created, e = created.WithOuterProtocol("auto")
	if e != nil {
		t.Fatal(e)
	}
	created, e = created.WithAlternates([]netip.AddrPort{altA}, []netip.AddrPort{altB})
	if e != nil {
		t.Fatal(e)
	}
	code, e := created.EncodeSensitive()
	if e != nil {
		t.Fatal(e)
	}
	imported, e := DecodeSensitiveSpoofSetup(code)
	if e != nil {
		t.Fatal(e)
	}
	if imported.CreatorEndpoint() != primaryA || imported.RecipientEndpoint() != primaryB || len(imported.CreatorAlternates()) != 1 || imported.CreatorAlternates()[0] != altA || len(imported.RecipientAlternates()) != 1 || imported.RecipientAlternates()[0] != altB {
		t.Fatal("original one-time Code lost the paired alternate endpoints")
	}
	if _, e = imported.WithAlternates([]netip.AddrPort{primaryA}, nil); e == nil {
		t.Fatal("accepted duplicate primary as an alternate")
	}
	if _, e = imported.WithAlternates([]netip.AddrPort{altA, altA}, nil); e == nil {
		t.Fatal("accepted duplicate alternates")
	}
}
