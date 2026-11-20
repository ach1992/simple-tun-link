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

// These boundaries are pinned-helper operational requirements, not the
// generic QUIC RFC minimum or an assumed measured remote path PMTU.
func TestPinnedHysteriaMinimumIPv4UnderlayMTU(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int
	}{
		{"", 1308},
		{"salamander", 1316},
	} {
		got, err := MinimumIPv4UnderlayMTU(tc.mode)
		if err != nil || got != tc.want {
			t.Fatalf("obfuscation=%q local required MTU=%d want=%d err=%v", tc.mode, got, tc.want, err)
		}
	}
	if _, err := MinimumIPv4UnderlayMTU("unknown"); err == nil {
		t.Fatal("unexpected unknown QUIC mode accepted")
	}
}
