package domain

import (
	"net/netip"
	"testing"
)

func TestCanonicalSpoofRealAlternates(t *testing.T) {
	primary := netip.MustParseAddrPort("10.244.62.207:48001")
	good := []netip.AddrPort{netip.MustParseAddrPort("10.244.62.211:48011"), netip.MustParseAddrPort("10.244.62.207:48031")}
	encoded, err := CanonicalSpoofAlternates(good, primary)
	if err != nil {
		t.Fatal(err)
	}
	received, err := ParseSpoofAlternates(encoded, primary)
	if err != nil || len(received) != 2 || received[0] != good[0] || received[1] != good[1] {
		t.Fatalf("roundtrip failed: %v %v", received, err)
	}
	for _, v := range []string{"10.244.62.207:48001", "10.244.62.211:48011,10.244.62.211:48011", ",10.244.62.211:48011", "10.244.62.211:0", "not-an-IP:42", "255.255.255.255:123", "10.244.62.211:48011,", "10.244.62.211:048011"} {
		if _, err := ParseSpoofAlternates(v, primary); err == nil {
			t.Fatalf("bad destination accepted: %q", v)
		}
	}
}
