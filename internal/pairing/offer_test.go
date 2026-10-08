package pairing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const idOne = "lnk_00112233445566778899aabbccddeeff"
const idTwo = "lnk_ffeeddccbbaa99887766554433221100"

func testLink(id string, backend domain.Backend, encap domain.Encapsulation) domain.Link {
	return domain.Link{
		ID: domain.LinkID(id), DisplayName: "Production Link / Test",
		Backend: backend, Encapsulation: encap,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("192.0.2.20")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.90.20.0/31"), Peer: netip.MustParsePrefix("10.90.20.1/31")},
	}
}
func wgTestKey() []byte {
	return []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa6}, 32)))
}
func ipsecTestPSK() []byte { return []byte("random-test-psk-aaaaaaaaaaaaaaaa") }

func TestPairingRoundTripAndReceiverInversion(t *testing.T) {
	tests := []struct {
		name       string
		backend    domain.Backend
		encap      domain.Encapsulation
		credential []byte
	}{
		{"GRE Native", domain.BackendGRE, domain.EncapNative, nil},
		{"GRE FOU", domain.BackendGRE, domain.EncapFOU, nil},
		{"GRE GUE", domain.BackendGRE, domain.EncapGUE, nil},
		{"IPIP Native", domain.BackendIPIP, domain.EncapNative, nil},
		{"IPIP FOU", domain.BackendIPIP, domain.EncapFOU, nil},
		{"IPIP GUE", domain.BackendIPIP, domain.EncapGUE, nil},
		{"WireGuard", domain.BackendWireGuard, domain.EncapUDP, wgTestKey()},
		{"IPsec ESP", domain.BackendIPsec, domain.EncapESP, ipsecTestPSK()},
		{"IPsec NAT-T", domain.BackendIPsec, domain.EncapNATT, ipsecTestPSK()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := testLink(idOne, tt.backend, tt.encap)
			offer, err := NewQuickOffer(link, tt.credential)
			if err != nil {
				t.Fatal(err)
			}
			serialized, err := offer.EncodeSetupLink()
			if err != nil || !strings.HasPrefix(serialized, setupPrefix) {
				t.Fatalf("encode failed: %v", err)
			}
			if len(serialized) > MaxLinkBytes {
				t.Fatal("size limit breached")
			}
			parsed, err := DecodeSetupLink(serialized)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Link() != link || parsed.Mode() != ModeQuick {
				t.Fatal("sender-facing Link changed")
			}
			if !bytes.Equal(parsed.RecipientCredential(), tt.credential) {
				t.Fatal("recipient credential changed")
			}
			if parsed.IsSensitive() != (len(tt.credential) > 0) {
				t.Fatal("sensitivity classification changed")
			}
			inverted := parsed.ReceiverLink()
			if inverted.ID != link.ID || inverted.Backend != link.Backend || inverted.Encapsulation != link.Encapsulation ||
				inverted.Underlay.Local != link.Underlay.Peer || inverted.Underlay.Peer != link.Underlay.Local ||
				inverted.Addresses.Local != link.Addresses.Peer || inverted.Addresses.Peer != link.Addresses.Local {
				t.Fatal("inversion failed")
			}
			if Invert(inverted) != link {
				t.Fatal("inversion is not involutive")
			}
			again, err := parsed.EncodeSetupLink()
			if err != nil || again != serialized {
				t.Fatal("encoding not deterministic")
			}
			preview := parsed.Preview()
			if preview.Link != inverted || preview.HasCredential != parsed.IsSensitive() || preview.SchemaVersion != SchemaVersion {
				t.Fatal("preview not recipient-oriented")
			}
		})
	}
}
func TestImportPreviewOnlyReturnsRedactedRecipientMetadata(t *testing.T) {
	offer, err := NewQuickOffer(testLink(idOne, domain.BackendWireGuard, domain.EncapUDP), wgTestKey())
	if err != nil {
		t.Fatal(err)
	}
	text, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewSetupLink(text)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Link != offer.ReceiverLink() || !preview.Sensitive || !preview.HasCredential || preview.Credential != CredentialWireGuardPrivateKey {
		t.Fatal("import preview was not receiver-oriented and redacted")
	}
	encoded, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, wgTestKey()) || bytes.Contains(encoded, []byte(base64.RawURLEncoding.EncodeToString(wgTestKey()))) {
		t.Fatal("credential leaked from import preview API")
	}
}

func TestSamePeerLinksRetainDistinctIdentities(t *testing.T) {
	for _, id := range []string{idOne, idTwo} {
		link := testLink(id, domain.BackendGRE, domain.EncapNative)
		o, err := NewQuickOffer(link, nil)
		if err != nil {
			t.Fatal(err)
		}
		value, err := o.EncodeSetupLink()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := DecodeSetupLink(value)
		if err != nil || string(parsed.ReceiverLink().ID) != id {
			t.Fatal("Link ID lost")
		}
	}
}
func TestSecretsNeverEnterOrdinaryJSONPreviewOrFormatting(t *testing.T) {
	for _, tt := range []struct {
		backend domain.Backend
		encap   domain.Encapsulation
		secret  []byte
	}{
		{domain.BackendWireGuard, domain.EncapUDP, wgTestKey()},
		{domain.BackendIPsec, domain.EncapESP, ipsecTestPSK()},
	} {
		offer, err := NewQuickOffer(testLink(idOne, tt.backend, tt.encap), tt.secret)
		if err != nil {
			t.Fatal(err)
		}
		generic, err := json.Marshal(offer)
		if err != nil {
			t.Fatal(err)
		}
		preview, err := json.Marshal(offer.Preview())
		if err != nil {
			t.Fatal(err)
		}
		for _, output := range []string{string(generic), string(preview), fmt.Sprint(offer), fmt.Sprintf("%+v", offer), fmt.Sprintf("%#v", offer)} {
			if strings.Contains(output, string(tt.secret)) || strings.Contains(output, base64.RawURLEncoding.EncodeToString(tt.secret)) {
				t.Fatal("credential leaked into generic output")
			}
		}
		if !strings.Contains(string(generic), "\"sensitive\":true") || !strings.Contains(string(preview), "\"has_credential\":true") {
			t.Fatal("sensitivity marker missing")
		}
		value, err := offer.EncodeSetupLink()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := DecodeSetupLink(value)
		if err != nil || !bytes.Equal(parsed.RecipientCredential(), tt.secret) {
			t.Fatal("credential not preserved in explicit export")
		}
		block, err := offer.HumanReadableBlock()
		if err != nil || !strings.Contains(block, "SENSITIVE") || !strings.Contains(block, value) {
			t.Fatal("explicit copy block not marked sensitive")
		}
		if strings.Contains(block, string(tt.secret)) {
			t.Fatal("unnecessary cleartext credential in copy block")
		}
	}
}
func TestSecretCopyIsolation(t *testing.T) {
	secret := ipsecTestPSK()
	offer, err := NewQuickOffer(testLink(idOne, domain.BackendIPsec, domain.EncapNATT), secret)
	if err != nil {
		t.Fatal(err)
	}
	secret[0] = 'X'
	first := offer.RecipientCredential()
	if len(first) == 0 || first[0] != 'r' {
		t.Fatal("constructor aliased caller buffer")
	}
	first[0] = 'Y'
	if offer.RecipientCredential()[0] != 'r' {
		t.Fatal("accessor aliased internal buffer")
	}
}
func TestRejectInvalidBackendCredentialCombinations(t *testing.T) {
	cases := []struct {
		name    string
		backend domain.Backend
		encap   domain.Encapsulation
		secret  []byte
	}{
		{"GRE credential", domain.BackendGRE, domain.EncapNative, []byte("secret")},
		{"GRE wrong encapsulation", domain.BackendGRE, domain.EncapUDP, nil},
		{"IPIP wrong encapsulation", domain.BackendIPIP, domain.EncapNATT, nil},
		{"WireGuard missing secret", domain.BackendWireGuard, domain.EncapUDP, nil},
		{"WireGuard invalid key", domain.BackendWireGuard, domain.EncapUDP, []byte("private")},
		{"WireGuard wrong mode", domain.BackendWireGuard, domain.EncapNative, wgTestKey()},
		{"IPsec missing PSK", domain.BackendIPsec, domain.EncapESP, nil},
		{"IPsec weak PSK", domain.BackendIPsec, domain.EncapESP, []byte("short")},
		{"IPsec oversized PSK", domain.BackendIPsec, domain.EncapESP, bytes.Repeat([]byte{'p'}, maxPSKBytes+1)},
		{"IPsec wrong encapsulation", domain.BackendIPsec, domain.EncapUDP, ipsecTestPSK()},
		{"unsupported backend", domain.Backend("other"), domain.EncapNative, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewQuickOffer(testLink(idOne, tc.backend, tc.encap), tc.secret)
			if err == nil || stlerr.CodeOf(err) != stlerr.CodeInvalid {
				t.Fatalf("invalid pairing accepted: %v", err)
			}
			if len(tc.secret) > 0 && strings.Contains(err.Error(), string(tc.secret)) {
				t.Fatal("rejected secret appeared in error")
			}
		})
	}
}
func TestRejectUnsafeOrInvalidLinkMetadata(t *testing.T) {
	tests := []struct {
		name string
		edit func(*domain.Link)
	}{
		{"invalid ID", func(l *domain.Link) { l.ID = "invalid" }},
		{"missing peer", func(l *domain.Link) { l.Underlay.Peer = netip.Addr{} }},
		{"identical underlay", func(l *domain.Link) { l.Underlay.Peer = l.Underlay.Local }},
		{"invalid address", func(l *domain.Link) { l.Addresses.Peer = netip.Prefix{} }},
		{"prefix mismatch", func(l *domain.Link) { l.Addresses.Peer = netip.MustParsePrefix("10.90.20.1/30") }},
		{"different underlay families", func(l *domain.Link) { l.Underlay.Peer = netip.MustParseAddr("2001:db8::20") }},
		{"embedded newline", func(l *domain.Link) { l.DisplayName = "line\ninject" }},
		{"format override", func(l *domain.Link) { l.DisplayName = "name\u202einjected" }},
		{"oversized name", func(l *domain.Link) { l.DisplayName = strings.Repeat("x", 65) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			link := testLink(idOne, domain.BackendGRE, domain.EncapNative)
			tc.edit(&link)
			if _, err := NewQuickOffer(link, nil); err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}
func TestManualBlockUsesCanonicalPairingOffer(t *testing.T) {
	offer, err := NewQuickOffer(testLink(idOne, domain.BackendGRE, domain.EncapFOU), nil)
	if err != nil {
		t.Fatal(err)
	}
	block, err := offer.HumanReadableBlock()
	if err != nil {
		t.Fatal(err)
	}
	value, err := offer.EncodeSetupLink()
	if err != nil || !strings.Contains(block, value) {
		t.Fatal("copy block does not use canonical pairing")
	}
	recv := offer.ReceiverLink()
	if !strings.Contains(block, recv.Underlay.Local.String()) || !strings.Contains(block, recv.Addresses.Local.String()) || !strings.Contains(block, string(recv.ID)) {
		t.Fatal("copy block not receiver-facing")
	}
	if strings.Contains(block, "SENSITIVE —") {
		t.Fatal("plaintext offer mislabeled as secret-bearing")
	}
}
