// Package ipsec provides the owner-scoped strongSwan VICI/XFRM planning
// substrate for the IPsec backend. No lifecycle or network mutation is
// enabled until canonical Engine ownership/credential gates are implemented.
package ipsec

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// Profile contains only PUBLIC per-Link identities. In particular, PSKs,
// swanctl configuration paths and credential bytes must never enter Link state.
type Profile struct {
	Link           domain.Link
	ConnectionName string
	ChildName      string
	SecretName     string
	InterfaceName  string
	InterfaceID    uint32
	LocalIKEID     string
	PeerIKEID      string
}

const pskBytes = 32

// GeneratePSK creates an independent, cryptographically random 256-bit
// shared secret for an explicitly SENSITIVE Quick Link exchange. The caller
// must zero its copy and explicitly provision both local and receiving keys
// through the protected credential transaction before applying any tunnel.
func GeneratePSK() ([]byte, error) {
	b := make([]byte, pskBytes)
	if _, err := rand.Read(b); err != nil {
		clear(b)
		return nil, fmt.Errorf("generate IPsec PSK: randomness unavailable")
	}
	return b, nil
}

// NewProfile derives the same XFRM identity and VICI connection/credential
// handles from the stable Link ID at both ends; endpoint-specific IKE IDs are
// deterministically inverted. Derived handles are exclusive collision CLAIMS,
// not sufficient proof to destroy/replace daemon state owned by another tool.
func NewProfile(link domain.Link) (Profile, error) {
	if err := link.Validate(); err != nil {
		return Profile{}, err
	}
	if link.Backend != domain.BackendIPsec ||
		(link.Encapsulation != domain.EncapESP && link.Encapsulation != domain.EncapNATT) ||
		!link.Underlay.Local.Is4() || !link.Underlay.Peer.Is4() {
		return Profile{}, fmt.Errorf("IPsec v0.1 profile requires ESP or NAT-T over two IPv4 endpoints")
	}
	// IsGlobalUnicast classifies addresses, not Internet route reachability,
	// so RFC1918 and TEST-NET endpoints remain valid for private networks and
	// disposable E2E fixtures. Explicitly reject 0/8 and 240/4 as well:
	// netip.IsGlobalUnicast alone can admit some non-concrete reserved addresses.
	// strongSwan treats 0.0.0.0 as an IKE wildcard, not a concrete STL peer.
	if !concreteIPv4Unicast(link.Underlay.Local) || !concreteIPv4Unicast(link.Underlay.Peer) {
		return Profile{}, fmt.Errorf("IPsec underlay endpoints must be concrete unicast IPv4")
	}
	// A /31 is valid for point-to-point addresses only if *both* host
	// selectors are concrete unicast. Do not admit a 0/8 or multicast /31
	// that would otherwise become an invalid or broad strongSwan TS.
	if !concreteIPv4Unicast(link.Addresses.Local.Addr()) ||
		!concreteIPv4Unicast(link.Addresses.Peer.Addr()) {
		return Profile{}, fmt.Errorf("IPsec Link Addresses must be concrete unicast IPv4")
	}
	if link.Addresses.Local.Bits() != 31 || link.Addresses.Peer.Bits() != 31 ||
		link.Addresses.Local.Masked() != link.Addresses.Peer.Masked() {
		return Profile{}, fmt.Errorf("IPsec Link Addresses must be a matched IPv4 /31 pair")
	}

	hexID := strings.TrimPrefix(string(link.ID), "lnk_")
	sum := sha256.Sum256([]byte("stl/ipsec/xfrm/v1/" + hexID))
	ifID := binary.BigEndian.Uint32(sum[:4])
	if ifID == 0 {
		// A nonzero XFRM identifier is mandatory, not the kernel wildcard.
		ifID = 1
	}
	lo, hi := "low", "high"
	if link.Underlay.Local.Compare(link.Underlay.Peer) > 0 {
		lo, hi = hi, lo
	}
	p := Profile{
		Link:           link,
		ConnectionName: "stl-ipsec-" + hexID,
		ChildName:      "stl-child-" + hexID,
		SecretName:     "stl-psk-" + hexID,
		InterfaceName:  "stlx" + hexID[:11],
		InterfaceID:    ifID,
		LocalIKEID:     "stl-" + hexID + "-" + lo,
		PeerIKEID:      "stl-" + hexID + "-" + hi,
	}
	return p, nil
}

func concreteIPv4Unicast(addr netip.Addr) bool {
	if !addr.Is4() || !addr.IsGlobalUnicast() {
		return false
	}
	// RFC 1122 identifies 0/8 as "this network"; 240/4 remains reserved.
	// Go's global-unicast classification does not reject their whole ranges.
	octets := addr.As4()
	return octets[0] != 0 && octets[0] < 240
}

// validateIdentity prevents callers from assembling or mutating a Profile by
// hand and bypassing the canonical policy/identity checks before VICI I/O.
// A profile name is a routing/ownership identity, not untrusted free-form
// operator input.
func (p Profile) validateIdentity() error {
	canonical, err := NewProfile(p.Link)
	if err != nil || canonical != p {
		return fmt.Errorf("noncanonical IPsec per-Link identity")
	}
	return nil
}

// ResourceClaims returns only public, exclusive identities for the Engine's
// existing per-resource locks. The full Link ID is retained for VICI handles;
// the bounded Linux interface name is independently checked on collision.
func (p Profile) ResourceClaims() []domain.ResourceClaim {
	return []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: p.InterfaceName},
		{Kind: domain.ResourceXFRMID, Key: strconv.FormatUint(uint64(p.InterfaceID), 10)},
		{Kind: domain.ResourceBackendID, Key: "ipsec/vici/conn/" + p.ConnectionName},
		{Kind: domain.ResourceBackendID, Key: "ipsec/vici/psk/" + p.SecretName},
		{Kind: domain.ResourceLinkAddress, Key: p.Link.Addresses.Local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: p.Link.Addresses.Local.Masked().String()},
	}
}

// LinkHostSelectors limits each policy to the Link Addresses themselves.
// Never negotiate 0.0.0.0/0 or an entire underlay by default: that could
// change unrelated traffic from a shared host.
func (p Profile) LinkHostSelectors() (local, remote netip.Prefix) {
	return netip.PrefixFrom(p.Link.Addresses.Local.Addr(), 32),
		netip.PrefixFrom(p.Link.Addresses.Peer.Addr(), 32)
}
