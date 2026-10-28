package composition

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestWireGuardProviderClaimsPreserveNativeResources(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	wg := domain.WireGuardOptions{
		LocalPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x91}, 32)),
		PeerPublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x18}, 32)),
		ListenPort:     51820,
	}
	got, err := WireGuardProviderClaims(id, netip.MustParsePrefix("10.56.30.1/31"), wg)
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: "stlwg0123456789"},
		{Kind: domain.ResourceLinkAddress, Key: "10.56.30.1"},
		{Kind: domain.ResourceLinkSubnet, Key: "10.56.30.0/31"},
		{Kind: domain.ResourceUDPListenPort, Key: "51820"},
		{Kind: domain.ResourceBackendID, Key: "wireguard/local-public/" + wg.LocalPublicKey},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("provider reservation changed: %v != %v", got, want)
	}
	wg.ListenPort = 0
	if _, err := WireGuardProviderClaims(id, netip.MustParsePrefix("10.56.30.1/31"), wg); err == nil {
		t.Fatal("zero local WG port accepted")
	}
}
