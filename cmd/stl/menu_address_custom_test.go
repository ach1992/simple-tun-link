package main

import (
	"github.com/ach1992/simple-tun-link/internal/domain"
	"net/netip"
	"testing"
)

func TestExplicitAdvancedCIDRHostAndBackendSemantics(t *testing.T) {
	positive := []struct{ local, peer string }{
		{"10.87.2.10/24", "10.87.2.11/25"},
		{"10.87.2.10/32", "10.87.3.11/32"},
		{"10.87.2.0/31", "10.87.2.1/31"},
		{"10.87.2.10/24", "10.87.2.11/24"},
	}
	for _, pair := range positive {
		addrs, err := manualCIDRLinkAddresses(pair.local, pair.peer)
		if err != nil || addrs.Local.String() != pair.local || addrs.Peer.String() != pair.peer {
			t.Fatalf("valid explicit CIDR rejected: %s %s: %v", pair.local, pair.peer, err)
		}
		for _, backend := range []domain.Backend{domain.BackendGRE, domain.BackendIPIP} {
			encap := domain.EncapNative
			link := domain.Link{ID: domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("198.51.100.20")},
				Addresses: addrs, Backend: backend, Encapsulation: encap}
			if err := link.Validate(); err != nil {
				t.Fatalf("backend=%s valid addresses rejected: %v", backend, err)
			}
		}
	}
	for _, pair := range []struct{ local, peer string }{
		{"10.87.2.0/24", "10.87.2.11/24"},   // network address
		{"10.87.2.255/24", "10.87.2.11/24"}, // broadcast
		{"10.87.2.10/0", "10.87.2.11/24"},   // no usable local host route
		{"10.87.2.10/24", "10.87.2.10/24"},  // duplicate host
		{"10.87.2.10/24", "192.0.2.20/33"},  // malformed prefix
		{"10.87.2.10", "10.87.2.11/24"},     // no CIDR
	} {
		if _, err := manualCIDRLinkAddresses(pair.local, pair.peer); err == nil {
			t.Fatalf("unusable explicit CIDR accepted: %+v", pair)
		}
	}
}
