package quic

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestManagedQUICDialPlanDefersPeerConnectionWithoutChangingSourcePolicy(t *testing.T) {
	link := domain.Link{ID: domainTestLinkID(), Backend: domain.BackendWireGuardQUIC, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("203.0.113.44"), Peer: netip.MustParseAddr("203.0.113.45")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.81.10.0/31"), Peer: netip.MustParsePrefix("10.81.10.1/31")},
		WireGuard: domain.WireGuardOptions{LocalPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), PeerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), ListenPort: 51820, PeerPort: 51821},
		QUIC:      domain.QUICOptions{Role: "dial", UDPPort: 443, ForwardUDPPort: 52211, TLSServerName: "quic-probe.invalid"}}
	plan, err := PlanFromLink(link)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := Build(plan, "/usr/local/libexec/stl/hysteria", "/var/lib/simple-tun-link", fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Clear()
	if !strings.Contains(strings.Join(managed.Args, " "), "--log-format json") {
		t.Fatal("managed renderer and runtime logger format differ")
	}
	fields := unwrap(t, managed)
	var lazy bool
	if json.Unmarshal(fields["lazy"], &lazy) != nil || !lazy {
		t.Fatal("Dial-first managed provisioning would require an already available peer")
	}
	if len(fields) != 5 {
		t.Fatal("managed connection policy enabled an unexpected client capability")
	}
	source := plan
	source.managed = false
	original, err := Build(source, "/usr/local/libexec/stl/hysteria", "/var/lib/simple-tun-link", fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Clear()
	originalFields := unwrap(t, original)
	if _, exists := originalFields["lazy"]; exists || len(originalFields) != 4 {
		t.Fatal("legacy source-only helper configuration was silently changed")
	}
	if projected, err := plan.HostPlan(link.WireGuard.ListenPort); err != nil || projected.Local.LocalHelperUDPPort != 52211 || projected.Local.RemoteWGUDPPort != 51821 {
		t.Fatal("managed policy changed public host reservations", err)
	}
}
