package masquehost

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func generateTestLinks(t *testing.T) (domain.Link, domain.Link) {
	t.Helper()
	listener := domain.Link{
		ID:      "lnk_0123456789abcdef0123456789abcdef",
		Backend: domain.BackendMASQUE, Encapsulation: domain.EncapTLS,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("2a01:4f8::1"), Peer: netip.MustParseAddr("2a10:ed40::2")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.252.99.1/32"), Peer: netip.MustParsePrefix("10.252.99.2/32")},
		MASQUE:    domain.MASQUEOptions{Role: "listen", TCPPort: 443, TLSServerName: "masque.example.org"},
	}
	dial := listener
	dial.Underlay.Local, dial.Underlay.Peer = listener.Underlay.Peer, listener.Underlay.Local
	dial.Addresses.Local, dial.Addresses.Peer = listener.Addresses.Peer, listener.Addresses.Local
	dial.MASQUE.Role = "dial"
	return listener, dial
}

func TestMaterialBuildPairUsesIndependentTLSKeysAndHashes(t *testing.T) {
	l, d := generateTestLinks(t)
	issue, err := masque.GeneratePair(l.ID, l.MASQUE.TLSServerName, 365)
	if err != nil {
		t.Fatal(err)
	}
	defer issue.Clear()
	root := t.TempDir()
	l, lFiles, err := BuildMaterial(root, l, issue)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearFiles(lFiles)
	d, dFiles, err := BuildMaterial(root, d, issue)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearFiles(dFiles)
	if l.MASQUE.MaterialSHA256 == d.MASQUE.MaterialSHA256 {
		t.Fatal("sender and receiver must have distinct original material identities")
	}
	if bytes.Equal(lFiles["server-key.pem"], dFiles["client-key.pem"]) {
		t.Fatal("sender must not have receiver's protected key")
	}
	if err := VerifyMaterialBundle(root, l, lFiles); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMaterialBundle(root, d, dFiles); err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Clone(dFiles["client-cert.pem"])
	mutated[len(mutated)-2] = 'x'
	dFiles["client-cert.pem"] = mutated
	if err := VerifyMaterialBundle(root, d, dFiles); err == nil {
		t.Fatal("accepted byte-mutated recipient material")
	}
}

func TestMASQUEMaterialHandoffCannotChangeOtherLink(t *testing.T) {
	l, _ := generateTestLinks(t)
	issue, err := masque.GeneratePair(l.ID, l.MASQUE.TLSServerName, 365)
	if err != nil {
		t.Fatal(err)
	}
	defer issue.Clear()
	root := t.TempDir()
	link, files, err := BuildMaterial(root, l, issue)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearFiles(files)
	link.ID = "lnk_ffffffffffffffffffffffffffffffff"
	if err := VerifyMaterialBundle(root, link, files); err == nil {
		t.Fatal("accepted material for a different Link owner")
	}
}

// Public TLS keeps the same exact per-Link protected-generation and retirement
// ownership model, but stores a request bearer instead of a client TLS key.
func TestMASQUEPublicTLSMaterialIsModeAndLinkBound(t *testing.T) {
	listener, dialer := generateTestLinks(t)
	listener.MASQUE.PublicTLS = true
	dialer.MASQUE.PublicTLS = true
	issued, err := masque.GeneratePair(listener.ID, listener.MASQUE.TLSServerName, 365)
	if err != nil {
		t.Fatal(err)
	}
	defer issued.Clear()
	root := t.TempDir()
	bad := issued
	bad.BearerToken = []byte("noncanonical")
	if _, files, err := BuildMaterial(root, listener, bad); err == nil || files != nil {
		t.Fatal("invalid public bearer must fail before creating private material copies")
	}
	listener, listenerFiles, err := BuildMaterial(root, listener, issued)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearFiles(listenerFiles)
	dialer, dialFiles, err := BuildMaterial(root, dialer, issued)
	if err != nil {
		t.Fatal(err)
	}
	defer ClearFiles(dialFiles)
	if err := VerifyMaterialBundle(root, listener, listenerFiles); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMaterialBundle(root, dialer, dialFiles); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(listenerFiles["bearer-token"], dialFiles["bearer-token"]) ||
		!masque.ValidBearerToken(listenerFiles["bearer-token"]) {
		t.Fatal("public Link bearer not bound to both protected material sets")
	}
	for _, files := range []map[string][]byte{listenerFiles, dialFiles} {
		if len(files["client-key.pem"]) != 0 || len(files["client-cert.pem"]) != 0 {
			t.Fatal("public TLS material unnecessarily retains a client TLS identity")
		}
	}
	if _, ok := listenerFiles["server-key.pem"]; !ok {
		t.Fatal("public TLS listener lost its server TLS private key")
	}
	if _, ok := dialFiles["server-ca.pem"]; !ok {
		t.Fatal("public TLS dialer lost server CA verification")
	}
	for _, link := range []domain.Link{listener, dialer} {
		link.MASQUE.PublicTLS = false
		if err := VerifyMaterialBundle(root, link, listenerFiles); err == nil {
			t.Fatal("accepted public bearer generation as private mTLS material")
		}
	}
	corrupted := append([]byte(nil), dialFiles["bearer-token"]...)
	dialFiles["bearer-token"][1] = '-'
	if err := VerifyMaterialBundle(root, dialer, dialFiles); err == nil {
		t.Fatal("accepted mutated request bearer in protected receiver material")
	}
	copy(dialFiles["bearer-token"], corrupted)
	dialer.ID = "lnk_ffffffffffffffffffffffffffffffff"
	if err := VerifyMaterialBundle(root, dialer, dialFiles); err == nil {
		t.Fatal("accepted original public bearer for a different Link")
	}
}
