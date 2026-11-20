package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// A valid CIDR pair is not necessarily routable through its connected
// prefix; warn before confirmation without disallowing custom routing.
func TestNonOnLinkPeerRouteGuidanceForSupportedCustomCIDRs(t *testing.T) {
	for _, tc := range []struct {
		name, local, peer string
		warn              bool
	}{
		{"on-link /31", "10.87.2.0/31", "10.87.2.1/31", false},
		{"on-link /30", "10.87.2.1/30", "10.87.2.2/30", false},
		{"different mutually on-link prefixes", "10.87.2.10/24", "10.87.2.11/25", false},
		{"disjoint /32", "10.87.2.10/32", "10.87.3.11/32", true},
		{"wider disjoint", "10.87.2.10/24", "10.87.3.11/24", true},
		{"asymmetric reachability", "10.87.2.10/32", "10.87.2.11/24", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addresses, err := manualCIDRLinkAddresses(tc.local, tc.peer)
			if err != nil {
				t.Fatalf("valid custom CIDRs were restricted: %v", err)
			}
			var out bytes.Buffer
			warnNonOnLinkPeerRoute(&out, addresses)
			warned := strings.Contains(out.String(), "STL does not add an extra host route")
			if warned != tc.warn {
				t.Fatalf("route guidance does not match CIDRs: wanted=%t got=%q", tc.warn, out.String())
			}
			if tc.warn && !strings.Contains(out.String(), "saving a Link is not evidence of peer connectivity") {
				t.Fatalf("missing honest post-create connectivity warning: %q", out.String())
			}
		})
	}
}

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
