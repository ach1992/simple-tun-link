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
