package quic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// Fixture token is intentionally public/test-only, NOT an issued credential.
const fixtureToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func fixturePlan(role Role) Plan {
	return Plan{
		LinkID:   domain.LinkID("lnk_0123456789abcdef0123456789abcdef"),
		Role:     role,
		Underlay: netip.MustParseAddrPort("203.0.113.45:443"),
		TLSName:  "quic-probe.invalid",
	}
}
func unwrap(t *testing.T, c Command) map[string]json.RawMessage {
	t.Helper()
	b := c.ProtectedConfigBytes()
	defer clear(b)
	var x map[string]json.RawMessage
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	return x
}
func field(t *testing.T, x map[string]json.RawMessage, name string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(x[name], &s); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestBuildHysteriaPinnedQUICDialAndListenRestrictedConfigs(t *testing.T) {
	base := fixturePlan(Dial)
	base.LocalForwardUDPPort = 52211
	base.PeerWGUDPPort = 51821
	dial, err := Build(base, "/opt/stl/hysteria", "/var/lib/simple-tun-link", fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	root := "/var/lib/simple-tun-link/credentials/quic/lnk_0123456789abcdef0123456789abcdef"
	if dial.Binary != "/opt/stl/hysteria" || dial.ConfigPath != filepath.Join(root, "helper.json") {
		t.Fatalf("unexpected own executable/config identity: %+v", dial)
	}
	args := []string{"--disable-update-check", "--log-level", "info", "-c", dial.ConfigPath, "client"}
	if !reflect.DeepEqual(dial.Args, args) {
		t.Fatalf("unknown client command: %v", dial.Args)
	}
	if strings.Contains(strings.Join(dial.Args, " "), fixtureToken) ||
		strings.Contains(fmt.Sprintf("%+v / %#v", dial, dial), fixtureToken) ||
		!strings.Contains(fmt.Sprintf("%#v", dial), "REDACTED") {
		t.Fatal("process arguments/diagnostics leak per-Link password")
	}
	c := unwrap(t, dial)
	if len(c) != 4 {
		t.Fatalf("unapproved Hysteria client mode: %v", c)
	}
	if field(t, c, "server") != "203.0.113.45:443" || field(t, c, "auth") != fixtureToken {
		t.Fatal("client must dial exact physical endpoint with per-Link auth")
	}
	var tls struct {
		SNI               string `json:"sni"`
		Insecure          bool   `json:"insecure"`
		CA                string `json:"ca"`
		ClientCertificate string `json:"clientCertificate"`
		ClientKey         string `json:"clientKey"`
	}
	if err := json.Unmarshal(c["tls"], &tls); err != nil {
		t.Fatal(err)
	}
	if tls.SNI != "quic-probe.invalid" || tls.Insecure ||
		tls.CA != filepath.Join(root, "server-ca.pem") ||
		tls.ClientCertificate != filepath.Join(root, "client-cert.pem") ||
		tls.ClientKey != filepath.Join(root, "client-key.pem") {
		t.Fatalf("untrusted client TLS: %+v", tls)
	}
	var forwards []udpForward
	if err := json.Unmarshal(c["udpForwarding"], &forwards); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forwards, []udpForward{{
		Listen: "127.0.0.1:52211", Remote: "127.0.0.1:51821", Timeout: "20s",
	}}) {
		t.Fatalf("unapproved extra listener/forwarder: %+v", forwards)
	}
	for _, notAllowed := range []string{"socks5", "http", "tun", "tcpForwarding", "trafficStats", "insecure", "obfs", "portHopping"} {
		if _, ok := c[notAllowed]; ok {
			t.Errorf("unexpected Hysteria dial capability: %s", notAllowed)
		}
	}

	serverPlan := fixturePlan(Listen)
	serverPlan.Underlay = netip.MustParseAddrPort("198.51.100.21:443")
	serverPlan.LocalWGUDPPort = 51820
	listener, err := Build(serverPlan, "/opt/stl/hysteria", "/var/lib/simple-tun-link", fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(listener.Args, []string{"--disable-update-check", "--log-level", "info", "-c", listener.ConfigPath, "server"}) {
		t.Fatalf("unexpected server helper args %q", listener.Args)
	}
	s := unwrap(t, listener)
	if len(s) != 5 {
		t.Fatalf("unapproved Hysteria server capability: %v", s)
	}
	if field(t, s, "listen") != "198.51.100.21:443" {
		t.Fatal("wrong server physical bind")
	}
	var serverTLS tlsServer
	var auth serverAuth
	var acl serverACL
	if err := json.Unmarshal(s["tls"], &serverTLS); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(s["auth"], &auth); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(s["acl"], &acl); err != nil {
		t.Fatal(err)
	}
	if serverTLS.SNIGuard != "strict" ||
		serverTLS.Cert != filepath.Join(root, "server-cert.pem") ||
		serverTLS.Key != filepath.Join(root, "server-key.pem") ||
		serverTLS.ClientCA != filepath.Join(root, "client-ca.pem") ||
		auth.Type != "password" || auth.Password != fixtureToken ||
		!reflect.DeepEqual(acl.Inline, []string{"direct(127.0.0.1, udp/51820)", "reject(all)"}) {
		t.Fatal("server missing exact mTLS+token or deny-by-default single-WG-destination ACL")
	}
	var disabled bool
	if err := json.Unmarshal(s["disableUDP"], &disabled); err != nil {
		t.Fatal(err)
	}
	if disabled {
		t.Fatal("QUIC UDP forwarding explicitly disabled")
	}
	for _, notAllowed := range []string{"socks5", "http", "tun", "outbounds", "tcpForwarding", "trafficStats", "masquerade", "obfs"} {
		if _, ok := s[notAllowed]; ok {
			t.Errorf("unexpected Hysteria server capability: %s", notAllowed)
		}
	}
}

func TestHysteriaConfigReturnsIndependentProtectedBytesAndMasksFormatting(t *testing.T) {
	plan := fixturePlan(Dial)
	plan.LocalForwardUDPPort = 50010
	plan.PeerWGUDPPort = 50011
	c, err := Build(plan, "/opt/stl/hysteria", "/var/lib/simple-tun-link", fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	a, b := c.ProtectedConfigBytes(), c.ProtectedConfigBytes()
	if len(a) == 0 || len(b) == 0 || !bytes.Equal(a, b) {
		t.Fatal("missing private config or aliasing")
	}
	a[0] = '?'
	if bytes.Equal(a, c.ProtectedConfigBytes()) {
		t.Fatal("secret config caller mutated builder-owned bytes")
	}
	for _, rep := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(rep, fixtureToken) || strings.Contains(rep, "sensitiveConfig") {
			t.Fatalf("secret must be redacted in accidental formatting: %s", rep)
		}
	}
	// Clearing the original builder-owned secret must neither retain a
	// hidden second copy nor erase caller-owned protected staging bytes.
	c.Clear()
	if c.ProtectedConfigBytes() != nil || len(b) == 0 || !bytes.Contains(b, []byte(fixtureToken)) {
		t.Fatal("Command Clear did not release original secret independently of caller copies")
	}
	c.Clear() // idempotent retirement
	clear(a)
	clear(b)
}

func TestHysteriaRequiresExactRoleTopologyOwnerAndPrivateInputs(t *testing.T) {
	dial := fixturePlan(Dial)
	dial.LocalForwardUDPPort = 52211
	dial.PeerWGUDPPort = 51821
	listen := fixturePlan(Listen)
	listen.LocalWGUDPPort = 51820
	cases := []struct {
		name         string
		plan         Plan
		binary, root string
	}{
		{"invalid-link", func() Plan { p := dial; p.LinkID = "untrusted"; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"binary-relative", dial, "hysteria", "/var/lib/simple-tun-link"},
		{"binary-dirty", dial, "/opt/stl/../hysteria", "/var/lib/simple-tun-link"},
		{"root-relative", dial, "/opt/stl/hysteria", "."},
		{"root-is-rootfs", dial, "/opt/stl/hysteria", "/"},
		{"path-newline", dial, "/opt/stl/hysteria\n", "/var/lib/simple-tun-link"},
		{"unknown-role", func() Plan { p := dial; p.Role = "reverse"; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"invalid-underlay", func() Plan { p := dial; p.Underlay = netip.AddrPort{}; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"ipv6-underlay", func() Plan { p := dial; p.Underlay = netip.MustParseAddrPort("[2001:db8::1]:443"); return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"missing-port", func() Plan { p := dial; p.Underlay = netip.MustParseAddrPort("203.0.113.45:0"); return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"sni-unsafe", func() Plan { p := dial; p.TLSName = "evil.com:443"; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"sni-peer-IP-mismatch", func() Plan { p := dial; p.TLSName = "198.51.100.10"; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"unknown-dns", func() Plan { p := dial; p.TLSName = "this-should-not-have-dot"; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"dial-no-local", func() Plan { p := dial; p.LocalForwardUDPPort = 0; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"dial-no-remote", func() Plan { p := dial; p.PeerWGUDPPort = 0; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"dial-mixed-listen", func() Plan { p := dial; p.LocalWGUDPPort = 51820; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"listen-no-wg", func() Plan { p := listen; p.LocalWGUDPPort = 0; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"listen-mixed-dial", func() Plan { p := listen; p.LocalForwardUDPPort = 52000; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
		{"listen-mixed-remote", func() Plan { p := listen; p.PeerWGUDPPort = 53000; return p }(), "/opt/stl/hysteria", "/var/lib/simple-tun-link"},
	}
	for _, token := range []string{"1234", fixtureToken[:63] + "\n"} {
		if c, err := Build(dial, "/opt/stl/hysteria", "/var/lib/simple-tun-link", token); err == nil {
			t.Fatalf("untrusted token leaked through renderer: %+v", c)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if c, err := Build(tc.plan, tc.binary, tc.root, fixtureToken); err == nil {
				t.Fatalf("unsafe plan got helper config: %+v", c)
			} else if strings.Contains(err.Error(), fixtureToken) {
				t.Fatal("unsafe plan reflected secret")
			}
		})
	}
}

func TestPhysicalIPSANUsesExactPeerWithoutInventedDNSName(t *testing.T) {
	p := fixturePlan(Dial)
	p.LocalForwardUDPPort = 51222
	p.PeerWGUDPPort = 51820
	p.TLSName = p.Underlay.Addr().String()
	c, err := Build(p, "/opt/stl/hysteria", "/var/lib/simple-tun-link", fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	var tls tlsClient
	if err := json.Unmarshal(unwrap(t, c)["tls"], &tls); err != nil {
		t.Fatal(err)
	}
	if tls.Insecure || tls.SNI != p.TLSName {
		t.Fatal("IP SAN client did not pin the selected peer")
	}

	p.Role = Listen
	p.LocalForwardUDPPort = 0
	p.PeerWGUDPPort = 0
	p.LocalWGUDPPort = 51820
	c, err = Build(p, "/opt/stl/hysteria", "/var/lib/simple-tun-link", fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	var stls tlsServer
	if err := json.Unmarshal(unwrap(t, c)["tls"], &stls); err != nil {
		t.Fatal(err)
	}
	if stls.SNIGuard != "dns-san" {
		t.Fatal("IP SAN must not require a DNS-only SNI")
	}
}
