//go:build linux

package spoofhost

import (
	"strings"
	"testing"
)

func TestSpoofPrivateTunIngressDecisionAndExactOwnership(t *testing.T) {
	link := ingressFixture(t, "auto")
	routes, err := ingressRules(link)
	if err != nil || len(routes) != 15 {
		t.Fatalf("unexpected outer + private ingress: %d %v", len(routes), err)
	}
	inner := routes[len(routes)-1]
	if !inner.private || inner.protocol != "private" {
		t.Fatalf("missing unique private TUN rule: %+v", inner)
	}
	args, marker, err := inner.args(link)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-i stls1234567890 -s 10.245.42.2/32 -d 10.245.42.1/32") ||
		!strings.Contains(joined, "--comment "+marker) ||
		!strings.HasSuffix(joined, "-j ACCEPT") {
		t.Fatalf("private INPUT rule must bind original TUN, peer and local /32: %s", joined)
	}
	firstArgs, firstMarker, err := routes[0].args(link)
	if err != nil || firstMarker == marker || strings.Join(firstArgs, " ") == joined {
		t.Fatal("private INPUT and raw receiver must not share ownership")
	}
	const tun = "stls1234567890"
	cases := []struct {
		name, chain string
		want        bool
	}{
		{"permissive empty", "-P INPUT ACCEPT\n", false},
		{"default drop", "-P INPUT DROP\n", true},
		{"stateful established only", "-P INPUT DROP\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", true},
		{"legacy state only", "-P INPUT DROP\n-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n", true},
		{"exact private allow under drop", "-P INPUT DROP\n-A INPUT -i " + tun + " -s 10.245.42.2/32 -d 10.245.42.1/32 -j ACCEPT\n", false},
		{"allow private interface under drop", "-P INPUT DROP\n-A INPUT -i " + tun + " -j ACCEPT\n", false},
		{"unrelated interface allow does not admit private", "-P INPUT DROP\n-A INPUT -i eth0 -j ACCEPT\n", true},
		{"only private ICMP allowed is insufficient", "-P INPUT DROP\n-A INPUT -i " + tun + " -p icmp -j ACCEPT\n", true},
		{"only private TCP port allowed is insufficient", "-P INPUT DROP\n-A INPUT -i " + tun + " -p tcp -m tcp --dport 443 -j ACCEPT\n", true},
		{"direct private interface drop under accept", "-P INPUT ACCEPT\n-A INPUT -i " + tun + " -j DROP\n", true},
		{"exact peer/private drop under accept", "-P INPUT ACCEPT\n-A INPUT -i " + tun + " -s 10.245.42.2/32 -d 10.245.42.1/32 -j DROP\n", true},
		{"private protocol-specific drop", "-P INPUT ACCEPT\n-A INPUT -i " + tun + " -p icmp --icmp-type echo-request -j DROP\n", true},
		{"private UDP port-specific drop", "-P INPUT ACCEPT\n-A INPUT -i " + tun + " -p udp -m udp --dport 5353 -j DROP\n", true},
		{"different peer cannot block configured peer", "-P INPUT ACCEPT\n-A INPUT -i " + tun + " -s 10.245.42.99/32 -d 10.245.42.1/32 -j DROP\n", false},
		{"wrong private destination", "-P INPUT ACCEPT\n-A INPUT -i " + tun + " -d 10.245.42.99/32 -j DROP\n", false},
		{"underlay drop cannot block private TUN", "-P INPUT ACCEPT\n-A INPUT -i eth0 -d 10.244.62.221/32 -j DROP\n", false},
		{"broad private peer subnet blocked", "-P INPUT ACCEPT\n-A INPUT -i " + tun + " -s 10.245.42.0/24 -j DROP\n", true},
		{"prior broad private allow overrides later drop", "-P INPUT DROP\n-A INPUT -i " + tun + " -j ACCEPT\n-A INPUT -i " + tun + " -j DROP\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := needsIngressException(c.chain, link, inner)
			if err != nil || got != c.want {
				t.Fatalf("private TUN INPUT exception=%v, want=%v; err=%v", got, c.want, err)
			}
		})
	}
}
