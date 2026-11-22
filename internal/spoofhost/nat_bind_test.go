//go:build linux

package spoofhost

import (
	"net/netip"
	"strings"
	"testing"
)

func TestSpoofNATBindingsAreNotAdvertisedAndIngressDiffersFromEgress(t *testing.T) {
	link := ingressFixture(t, "udp")
	link.Underlay.Local = netip.MustParseAddr("198.51.100.11")
	link.Spoof.LocalAlternates = "198.51.100.12:48800"
	link.Spoof.BindIPv4 = netip.MustParseAddr("10.0.12.8")
	link.Spoof.BindPort = 49400
	link.Spoof.BindAlternates = "10.0.12.9:49401"
	link.Spoof.Interface = "out1"
	link.Spoof.IngressInterface = "in0"
	a := newAgent(t.TempDir(), link, Material{}, nil)
	want := netip.MustParseAddrPort("10.0.12.8:49400")
	if a.localEndpoint() != want || len(a.localEndpoints()) != 2 {
		t.Fatal("local listener not bound to post-DNAT destination")
	}
	if a.advertisedLocalEndpoints()[0] != netip.MustParseAddrPort("198.51.100.11:48001") ||
		a.advertisedLocalEndpoints()[1] != netip.MustParseAddrPort("198.51.100.12:48800") {
		t.Fatal("local receiver address leaked into pairing/advertised endpoints")
	}
	rules, err := ingressRules(link)
	if err != nil || len(rules) != 3 {
		t.Fatalf("expected two distinct inbound binds plus private TUN, got %v %v", rules, err)
	}
	args, _, err := rules[0].args(link)
	if err != nil || !strings.Contains(strings.Join(args, " "), "-i in0 -d 10.0.12.8/32 -p udp --dport 49400") {
		t.Fatalf("firewall targets advertised NAT IP or outbound interface: %v %v", args, err)
	}
	if strings.Contains(strings.Join(args, " "), "198.51.100") || strings.Contains(strings.Join(args, " "), "out1") {
		t.Fatal("incorrect ingress topology")
	}
}
