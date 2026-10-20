package wss

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func wssTestLink() domain.Link {
	local, peer := make([]byte, 32), make([]byte, 32)
	for i := range local {
		local[i], peer[i] = 1, 2
	}
	return domain.Link{
		ID:      domain.LinkID("lnk_0123456789abcdef0123456789abcdef"),
		Backend: domain.BackendWireGuard, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("198.51.100.21"), Peer: netip.MustParseAddr("203.0.113.34")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.99.1.1/30"), Peer: netip.MustParsePrefix("10.99.1.2/30")},
		WireGuard: domain.WireGuardOptions{
			LocalPublicKey: base64.StdEncoding.EncodeToString(local),
			PeerPublicKey:  base64.StdEncoding.EncodeToString(peer),
			ListenPort:     51820, PeerPort: 51821,
		},
	}
}

func TestRestrictedWSSCommandsAreExecutableArgumentArraysNotShells(t *testing.T) {
	l := wssTestLink()
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role  composition.Role
		local uint16
		tcp   uint16
	}{
		{composition.Dial, 51321, 443}, {composition.Listen, 0, 8443},
	} {
		c := composition.Carrier{Kind: composition.WSS, Role: tc.role,
			PublicTCPPort: tc.tcp, LocalForwardUDP: tc.local, CredentialOwner: l.ID}
		if tc.role == composition.Dial {
			c.TLSServerName = "server.example"
		}
		cmd, err := Build(l, c, "/opt/stl/wstunnel", "/var/lib/simple-tun-link")
		if err != nil {
			t.Fatal(err)
		}
		root := filepath.Join("/var/lib/simple-tun-link", "credentials", "wss", string(l.ID))
		if cmd.Binary != "/opt/stl/wstunnel" || len(cmd.Args) < 5 {
			t.Fatalf("missing explicit executable/arguments %+v", cmd)
		}
		if strings.Contains(strings.Join(cmd.Args, " "), " --tls-sni-disable") ||
			strings.Contains(strings.Join(cmd.Args, " "), " --insecure") {
			t.Fatalf("TLS verification bypass is forbidden: %+v", cmd.Args)
		}
		if tc.role == composition.Dial {
			want := []string{"client", "--tls-verify-certificate",
				"--tls-certificate", filepath.Join(root, "client-cert.pem"),
				"--tls-private-key", filepath.Join(root, "client-key.pem"),
				"--tls-sni-override", "server.example", "-L",
				"udp://127.0.0.1:51321:127.0.0.1:51821?timeout_sec=0",
				"wss://203.0.113.34:443",
			}
			if !reflect.DeepEqual(cmd.Args, want) {
				t.Fatalf("unexpected strict dial command\ngot=%q\nwant=%q", cmd.Args, want)
			}
			if len(cmd.ServerRestrictions) > 0 ||
				!reflect.DeepEqual(cmd.Env, []string{"SSL_CERT_FILE=" + filepath.Join(root, "server-ca.pem")}) {
				t.Fatalf("missing per-Link explicit server-trust store: %+v", cmd)
			}
		} else {
			want := []string{"server",
				"--tls-certificate", filepath.Join(root, "server-cert.pem"),
				"--tls-private-key", filepath.Join(root, "server-key.pem"),
				"--tls-client-ca-certs", filepath.Join(root, "client-ca.pem"),
				"--restrict-config", filepath.Join(root, "restrictions.yaml"),
				"wss://198.51.100.21:8443",
			}
			if !reflect.DeepEqual(cmd.Args, want) {
				t.Fatalf("unexpected strict listener command\ngot=%q\nwant=%q", cmd.Args, want)
			}
			policy := string(cmd.ServerRestrictions)
			for _, part := range []string{
				"^stl0123456789abcdef0123456789abcdef$",
				"!Tunnel", "          - Udp", "          - 51820",
				"host:", "127.0.0.1/32",
			} {
				if !strings.Contains(policy, part) {
					t.Fatalf("restriction misses exact %q: %s", part, policy)
				}
			}
			if strings.Contains(policy, "!ReverseTunnel") || strings.Contains(policy, "- Tcp") ||
				strings.Contains(policy, "0.0.0.0/0") || !strings.Contains(policy, "^127") {
				t.Fatalf("WSS server restriction grants extraneous connectivity: %s", policy)
			}
		}
	}
}

func TestWSSCommandBuilderRejectsNonWSSOrUntrustedResourceNames(t *testing.T) {
	l := wssTestLink()
	dial := composition.Carrier{Kind: composition.WSS, Role: composition.Dial,
		PublicTCPPort: 443, LocalForwardUDP: 51321, TLSServerName: "server.example",
		CredentialOwner: l.ID}
	tests := []struct {
		carrier      composition.Carrier
		binary, root string
	}{
		{composition.Carrier{}, "/opt/stl/wstunnel", "/var/lib/simple-tun-link"},
		{dial, "wstunnel", "/var/lib/simple-tun-link"},
		{dial, "/opt/stl/wstunnel", "."},
		{dial, "/opt/stl/wstunnel", "/"},
		{dial, "/opt/stl/wstunnel", "/tmp/../var/lib/simple-tun-link"},
	}
	for i, tc := range tests {
		if _, err := Build(l, tc.carrier, tc.binary, tc.root); err == nil {
			t.Fatalf("unsafe case %d accepted", i)
		}
	}
}

func TestWSSDialWithoutDNSOverrideRequiresPhysicalIPCertificateSAN(t *testing.T) {
	l := wssTestLink()
	carrier := composition.Carrier{Kind: composition.WSS, Role: composition.Dial,
		PublicTCPPort: 443, LocalForwardUDP: 51321, CredentialOwner: l.ID}
	p, err := composition.Build(l, carrier)
	if err != nil {
		t.Fatal(err)
	}
	if p.TLSName != l.Underlay.Peer.String() {
		t.Fatalf("default peer identity not public IP: %s", p.TLSName)
	}
	cmd, err := Build(l, carrier, "/opt/stl/wstunnel", "/var/lib/simple-tun-link")
	if err != nil {
		t.Fatal(err)
	}
	// An explicit certificate IP SAN equal to the dialed address
	// is also valid; it must not create an unsupported SNI override.
	carrier.TLSServerName = l.Underlay.Peer.String()
	if explicit, err := Build(l, carrier, "/opt/stl/wstunnel", "/var/lib/simple-tun-link"); err != nil || !reflect.DeepEqual(explicit.Args, cmd.Args) {
		t.Fatalf("explicit physical IP SAN not equivalent to omitted override: %v", err)
	}
	args := strings.Join(cmd.Args, " ")
	if strings.Contains(args, "--tls-sni-override") || !strings.Contains(args, "--tls-verify-certificate") {
		t.Fatalf("IP SAN path must verify physical endpoint with no unverified SNI override: %s", args)
	}
}

// TestPinnedV11RestrictionFixture makes the actual v11 executable parser
// acceptance use byte-for-byte output of Build, not a hand-edited
// permissive policy. The fixture is also consumed by the opt-in disposable
// network-namespace test in scripts/e2e/wss-v11-compat.sh.
func TestPinnedV11RestrictionFixture(t *testing.T) {
	link := wssTestLink()
	link.WireGuard.ListenPort = 53000
	c := composition.Carrier{Kind: composition.WSS, Role: composition.Listen, PublicTCPPort: 59443, CredentialOwner: link.ID}
	actual, err := Build(link, c, "/opt/stl/wstunnel", "/var/lib/simple-tun-link")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("testdata/restrictions-v11.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual.ServerRestrictions, expected) {
		t.Fatalf("wstunnel v11 executable test policy drifted from the canonical WSS renderer")
	}
}
