//go:build linux

package spoofhost

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func ingressFixture(t *testing.T, outer string) domain.Link {
	t.Helper()
	link := domain.Link{
		ID:      "lnk_1234567890abcdef1234567890abcdef",
		Backend: domain.BackendSpoof, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("10.244.62.221"), Peer: netip.MustParseAddr("10.244.62.222")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.245.42.1/32"), Peer: netip.MustParsePrefix("10.245.42.2/32")},
		Spoof: domain.SpoofOptions{
			OuterProtocol: outer, ListenPort: 48001, PeerPort: 48002,
			Interface: "out0", IngressInterface: "eth0",
			LocalAlternates: "10.244.62.223:48011", BindAlternates: "10.244.62.223:48011",
			ManageIngress: true,
		},
	}
	return link
}
func TestSpoofIngressRulesExactProtocolDestinationAndMarker(t *testing.T) {
	link := ingressFixture(t, "auto")
	rules, err := ingressRules(link)
	if err != nil || len(rules) != 15 {
		t.Fatalf("want 2 endpoints x7 outer protocols plus private TUN, got %d: %v", len(rules), err)
	}
	markers := map[string]bool{}
	for _, r := range rules {
		args, marker, err := r.args(link)
		if err != nil {
			t.Fatal(err)
		}
		if markers[marker] {
			t.Fatalf("duplicate Spoof rule marker: %s", marker)
		}
		markers[marker] = true
		joined := strings.Join(args, " ")
		if r.private {
			if !strings.Contains(joined, "-i stls1234567890") ||
				!strings.Contains(joined, "-s 10.245.42.2/32 -d 10.245.42.1/32") ||
				!strings.Contains(joined, "--comment "+marker) || !strings.HasSuffix(joined, "-j ACCEPT") ||
				strings.Contains(joined, " --dport ") || strings.Contains(joined, " -p ") {
				t.Fatalf("unexpected private TUN exception: %s", joined)
			}
			if readOwnedMarkerCount("-A INPUT "+joined+"\n", marker) != 1 {
				t.Fatal("private TUN owner marker not recognizable")
			}
			continue
		}
		if strings.Contains(joined, "-s ") || !strings.Contains(joined, "-d "+r.endpoint.Addr().String()+"/32") || !strings.Contains(joined, "-i eth0") ||
			!strings.Contains(joined, "--comment "+marker) || !strings.HasSuffix(joined, "-j ACCEPT") {
			t.Fatalf("unexpected broad or malformed owned rule: %s", joined)
		}
		if r.protocol == "icmp" && !strings.Contains(joined, "--icmp-type echo-reply") {
			t.Fatal("ICMP must be narrowed to unsolicited reply")
		}
		if (r.protocol == "tcp" || r.protocol == "udp") && !strings.Contains(joined, "--dport "+strconv.Itoa(int(r.endpoint.Port()))) {
			t.Fatal("UDP/TCP receive port missing")
		}
		if readOwnedMarkerCount("-A INPUT "+joined+"\n", marker) != 1 {
			t.Fatal("exact owner marker not recognizable")
		}
	}
	if readOwnedMarkerCount("-A INPUT --comment stl:unrelated -j DROP", "stl:spoof:"+string(link.ID)) != 0 {
		t.Fatal("foreign rule adopted")
	}
}
func TestSpoofIngressOptInAndRawProfileScoping(t *testing.T) {
	link := ingressFixture(t, "proto58-echo")
	rules, err := ingressRules(link)
	if err != nil || len(rules) != 3 {
		t.Fatalf("proto58 echo needs one IP protocol per endpoint plus private TUN, got %d: %v", len(rules), err)
	}
	for _, r := range rules {
		if r.private {
			continue
		}
		args, _, err := r.args(link)
		if err != nil || !strings.Contains(strings.Join(args, " "), " -p 58 ") {
			t.Fatalf("expected exact IPv4 protocol 58: %v %v", args, err)
		}
	}
	link.Spoof.ManageIngress = false
	rules, err = ingressRules(link)
	if err != nil || len(rules) != 0 {
		t.Fatal("default must never alter host firewall")
	}
	link.Spoof.ManageIngress = true
	link.Spoof.IngressInterface = ""
	if _, err = ingressRules(link); err == nil {
		t.Fatal("managed ingress without explicit interface accepted")
	}
}
