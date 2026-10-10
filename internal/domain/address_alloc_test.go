package domain

import (
	"net/netip"
	"testing"
)

func TestPrivate31CandidatesAreDistinctCanonicalRFC1918Networks(t *testing.T) {
	candidates, err := Private31Candidates()
	if err != nil || len(candidates) != 48 {
		t.Fatalf("unusable /31 candidates: %d %v", len(candidates), err)
	}
	seen := map[netip.Prefix]bool{}
	for _, candidate := range candidates {
		if err := ValidatePrivate31(candidate); err != nil || seen[candidate] {
			t.Fatalf("invalid/duplicate candidate %s: %v", candidate, err)
		}
		seen[candidate] = true
	}
}

func TestFreePrivate31UsesCanonicalOverlapAndFailsClosed(t *testing.T) {
	first := netip.MustParsePrefix("10.88.2.0/31")
	second := netip.MustParsePrefix("172.30.9.2/31")
	third := netip.MustParsePrefix("192.168.99.4/31")
	proposals := []netip.Prefix{first, second, third}
	occupied := []ResourceClaim{
		{Kind: ResourceLinkSubnet, Key: "10.88.0.0/16"},
		{Kind: ResourceLinkAddress, Key: "172.30.9.3"},
	}
	got, ok, err := FreePrivate31(proposals, occupied)
	if err != nil || !ok || got != third {
		t.Fatalf("candidate collision not rejected: %s %t %v", got, ok, err)
	}
	got, ok, err = FreePrivate31(proposals, append(occupied,
		ResourceClaim{Kind: ResourceLinkSubnet, Key: "192.168.99.0/24"}))
	if err != nil || ok || got.IsValid() {
		t.Fatalf("all-conflict proposal unexpectedly available: %s %t %v", got, ok, err)
	}
	_, _, err = FreePrivate31([]netip.Prefix{third}, []ResourceClaim{{Kind: ResourceLinkSubnet, Key: "not-canonical"}})
	if err == nil {
		t.Fatal("invalid reservations must fail closed")
	}
}

func TestPrivate31ManualValidation(t *testing.T) {
	for _, good := range []string{"10.253.0.0/31", "172.16.0.2/31", "192.168.255.254/31"} {
		if err := ValidatePrivate31(netip.MustParsePrefix(good)); err != nil {
			t.Fatalf("valid private /31 %s rejected: %v", good, err)
		}
	}
	for _, bad := range []string{"10.253.0.1/31", "10.253.0.0/30", "8.8.8.0/31", "127.0.0.0/31", "fc00::/31"} {
		if err := ValidatePrivate31(netip.MustParsePrefix(bad)); err == nil {
			t.Fatalf("invalid private /31 accepted: %s", bad)
		}
	}
}
