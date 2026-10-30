package quic

import "testing"

func TestMaximumWireGuardMTUAccountsForBothRoleDestinations(t *testing.T) {
	for _, role := range []Role{Dial, Listen} {
		for _, port := range []uint16{1, 9999, 65535} {
			p, _ := helperConfigPlan(domainTestLinkID(), role)
			if role == Dial {
				p.PeerWGUDPPort = port
			} else {
				p.LocalWGUDPPort = port
			}
			got, err := MaximumWireGuardMTU(p)
			if err != nil || got != 4032 {
				t.Fatalf("role=%s port=%d MTU=%d err=%v", role, port, got, err)
			}
		}
	}
	p, _ := helperConfigPlan(domainTestLinkID(), Dial)
	p.PeerWGUDPPort = 0
	if _, err := MaximumWireGuardMTU(p); err == nil {
		t.Fatal("missing remote WireGuard destination accepted")
	}
	p, _ = helperConfigPlan(domainTestLinkID(), Listen)
	p.LocalWGUDPPort = p.Underlay.Port()
	if _, err := MaximumWireGuardMTU(p); err == nil {
		t.Fatal("conflicting physical and WireGuard ports accepted")
	}
}
