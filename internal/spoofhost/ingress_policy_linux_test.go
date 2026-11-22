//go:build linux

package spoofhost

import "testing"

func TestSpoofIngressPermissionOnlyWhenBlocked(t *testing.T) {
	link := ingressFixture(t, "auto")
	routes, err := ingressRules(link)
	if err != nil || len(routes) != 14 {
		t.Fatalf("unexpected routes %d %v", len(routes), err)
	}
	tests := []struct {
		name, chain string
	}{
		{name: "open default without special filter", chain: "-P INPUT ACCEPT\n"},
		{name: "existing explicit allow", chain: "-P INPUT DROP\n-A INPUT -i eth0 -d 10.244.62.221/32 -j ACCEPT\n"},
		{name: "blocked primary only", chain: "-P INPUT ACCEPT\n-A INPUT -d 10.244.62.221/32 -j DROP\n"},
		{name: "default drop", chain: "-P INPUT DROP\n"},
		{name: "default drop with tracked established only", chain: "-P INPUT DROP\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"},
		{name: "default drop with legacy state established only", chain: "-P INPUT DROP\n-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n"},
		{name: "unrelated destination drop", chain: "-P INPUT ACCEPT\n-A INPUT -d 203.0.113.98/32 -j DROP\n"},
		{name: "unrelated port drop", chain: "-P INPUT ACCEPT\n-A INPUT -i eth0 -p udp --dport 9000 -j DROP\n"},
		{name: "unknown jump on permissive policy", chain: "-P INPUT ACCEPT\n-A INPUT -j PREEXISTING_FILTER\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, r := range routes {
				got, e := needsIngressException(tt.chain, link, r)
				if e != nil {
					t.Fatalf("inspection error for %s: %v", r.protocol, e)
				}
				var want bool
				switch tt.name {
				case "default drop", "default drop with tracked established only", "default drop with legacy state established only":
					want = true
				case "blocked primary only":
					want = r.endpoint.Port() == 48001
				case "existing explicit allow":
					want = r.endpoint.Port() == 48011
				}
				if got != want {
					t.Fatalf("%s at %s, got exception=%v expected=%v", r.protocol, r.endpoint, got, want)
				}
			}
		})
	}
}
func TestSpoofIngressPortAware(t *testing.T) {
	link := ingressFixture(t, "auto")
	routes, _ := ingressRules(link)
	for _, r := range routes {
		if r.protocol == "udp" {
			got, err := needsIngressException("-P INPUT ACCEPT\n-A INPUT -i eth0 -p udp --dport 48001 -j DROP\n", link, r)
			if err != nil || got != (r.endpoint.Port() == 48001) {
				t.Fatalf("wrong UDP port-specific result %s got %t err=%v", r.endpoint, got, err)
			}
		}
	}
}
