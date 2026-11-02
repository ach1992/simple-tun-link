package linux

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestFindOwnedInboundRecoversExactRuleWithoutRoute(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := InboundFirewallRule{
		Peer:           netip.MustParseAddr("10.77.94.0"),
		Local:          netip.MustParseAddr("10.77.94.1"),
		InputInterface: "stlxdeadbeef01", Protocol: 17, DestinationPort: 55561,
	}
	runner := newFirewallRunner()
	runner.seedRule("iptables", firewallRuleArgs(id, rule))
	f := IPTablesFirewall{Runner: runner}

	got, found, err := f.FindOwnedInbound(context.Background(), id, false)
	if err != nil || !found || got != rule {
		t.Fatalf("cannot recover exact rule despite missing original interface/route: found=%v got=%+v err=%v", found, got, err)
	}
	fields := append([]string{"-A", "INPUT"}, firewallRuleArgs(id, rule)...)
	for i, field := range fields {
		if field == "-p" {
			fields[i+1] = "udp" // iptables -S normalizes protocol 17 to udp.
			break
		}
	}
	if parsed, err := parseOwnedInboundRule(fields, id, false); err != nil || parsed != rule {
		t.Fatalf("kernel-normalized UDP listing rejected: parsed=%+v err=%v", parsed, err)
	}
	if got, found, err := f.FindOwnedInbound(context.Background(), domain.LinkID("lnk_ffffffffffffffffffffffffffffffff"), false); err != nil || found || got != (InboundFirewallRule{}) {
		t.Fatalf("foreign rule adopted: found=%v err=%v", found, err)
	}
}

func TestFindOwnedInboundFailsClosedOnAmbiguousAndAlteredRules(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := InboundFirewallRule{
		Peer:           netip.MustParseAddr("10.77.94.0"),
		Local:          netip.MustParseAddr("10.77.94.1"),
		InputInterface: "stlxdeadbeef01", Protocol: 17, DestinationPort: 55561,
	}
	args := firewallRuleArgs(id, rule)
	for _, tc := range []struct {
		name    string
		prepare func(*firewallRunner)
	}{
		{"duplicate-owned-rules", func(r *firewallRunner) { r.seedRule("iptables", args); r.seedRule("iptables", args) }},
		{"owned-marker-does-not-match-fields", func(r *firewallRunner) {
			altered := append([]string(nil), args...)
			for i, s := range altered {
				if s == "-i" {
					altered[i+1] = "other-device"
					break
				}
			}
			r.seedRule("iptables", altered)
		}},
		{"owned-marker-with-extra-condition", func(r *firewallRunner) {
			altered := append([]string(nil), args...)
			altered = append(altered, "-m", "limit")
			r.seedRule("iptables", altered)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := newFirewallRunner()
			tc.prepare(runner)
			f := IPTablesFirewall{Runner: runner}
			if _, found, err := f.FindOwnedInbound(context.Background(), id, false); err == nil || found {
				t.Fatalf("ambiguous or altered firewall rule was authorized: found=%v err=%v", found, err)
			}
			if runner.countCommandsContaining(" -D ") != 0 || runner.countCommandsContaining(" -A ") != 0 {
				t.Fatal("read-only ownership inspection mutated firewall")
			}
		})
	}
}

func TestParseOwnedInboundRejectsBroadOrNoncanonicalRule(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := InboundFirewallRule{
		Peer:           netip.MustParseAddr("10.77.94.0"),
		Local:          netip.MustParseAddr("10.77.94.1"),
		InputInterface: "stlxdeadbeef01", Protocol: 17, DestinationPort: 55561,
	}
	args := append([]string{"-A", "INPUT"}, firewallRuleArgs(id, rule)...)
	for _, tc := range []struct{ name, old, value string }{
		{"broad-source", "10.77.94.0/32", "10.77.94.0/24"},
		{"wrong-target", "ACCEPT", "DROP"},
		{"unknown-protocol", "17", "tcp"},
		{"forged-marker", firewallMarker(id, rule), "stl:" + string(id) + ":1234567890abcdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]string(nil), args...)
			for i := range bad {
				if bad[i] == tc.old {
					bad[i] = tc.value
					break
				}
			}
			if _, err := parseOwnedInboundRule(bad, id, false); err == nil {
				t.Fatalf("accepted noncanonical firewall rule: %s", strings.Join(bad, " "))
			}
		})
	}
}

// Native GRE, IPIP and L2TPv3 rules are IP protocols rather than UDP.
// iptables -S can normalize numeric protocols to names on readback.
func TestFindOwnedInboundRecoversCanonicalNativeProtocolRulesWithoutRoute(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	for _, tc := range []struct {
		protocol uint8
		name     string
	}{
		{47, "gre"}, {4, "ipencap"}, {115, "115"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := InboundFirewallRule{
				Peer: netip.MustParseAddr("198.51.100.20"), Local: netip.MustParseAddr("192.0.2.10"),
				InputInterface: "old-eth0", Protocol: tc.protocol,
			}
			runner := newFirewallRunner()
			runner.seedRule("iptables", firewallRuleArgs(id, rule))
			f := IPTablesFirewall{Runner: runner}
			got, present, err := RecoverOwnedInboundForRemoval(context.Background(), f, id, rule.Local, rule.Peer, tc.protocol, 0)
			if err != nil || !present || got != rule {
				t.Fatalf("native owned rule recovery failed: got=%+v present=%v err=%v", got, present, err)
			}
			raw := append([]string{"-A", "INPUT"}, firewallRuleArgs(id, rule)...)
			for i := range raw {
				if raw[i] == "-p" {
					raw[i+1] = tc.name
					break
				}
			}
			if parsed, err := parseOwnedInboundRule(raw, id, false); err != nil || parsed != rule {
				t.Fatalf("kernel protocol alias rejected: %+v %v", parsed, err)
			}
			if _, present, err := RecoverOwnedInboundForRemoval(context.Background(), f, id, rule.Local, rule.Peer, 17, 1234); err == nil || present {
				t.Fatal("owned rule adopted by unrelated transport")
			}
		})
	}
}

func TestNativeFirewallOwnedReadbackRejectsInexactOrForgedRules(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	rule := InboundFirewallRule{
		Peer: netip.MustParseAddr("198.51.100.20"), Local: netip.MustParseAddr("192.0.2.10"),
		InputInterface: "eth0", Protocol: 47,
	}
	base := append([]string{"-A", "INPUT"}, firewallRuleArgs(id, rule)...)
	for _, tc := range []struct {
		name string
		edit func([]string) []string
	}{
		{"extra-match", func(fields []string) []string { return append(fields, "-m", "limit") }},
		{"unexpected-port", func(fields []string) []string { return append(fields, "--dport", "1234") }},
		{"wrong-rule-interface", func(fields []string) []string {
			for i := range fields {
				if fields[i] == "-i" {
					fields[i+1] = "eth1"
				}
			}
			return fields
		}},
		{"wrong-comment", func(fields []string) []string {
			for i := range fields {
				if fields[i] == "--comment" {
					fields[i+1] = "stl:" + string(id) + ":deadbeefcafe1111"
				}
			}
			return fields
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := tc.edit(append([]string(nil), base...))
			if _, err := parseOwnedInboundRule(fields, id, false); err == nil {
				t.Fatalf("noncanonical native rule admitted: %v", fields)
			}
		})
	}
}
