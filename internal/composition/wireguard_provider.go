package composition

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// WireGuardInterfaceName is the canonical local native-WG interface naming
// contract, shared by existing WireGuard/WSS and candidate carriers.
func WireGuardInterfaceName(id domain.LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return "stlwg" + string(id)[4:14], nil
}

// WireGuardProviderClaims derives the exact native kernel-WG identities
// reused by direct, WSS and prospective QUIC composition. It does not imply
// a live backend, kernel ownership or permission to mutate the host.
func WireGuardProviderClaims(id domain.LinkID, local netip.Prefix, wg domain.WireGuardOptions) ([]domain.ResourceClaim, error) {
	name, err := WireGuardInterfaceName(id)
	if err != nil {
		return nil, fmt.Errorf("invalid WireGuard Link owner: %w", err)
	}
	if err := wg.Validate(); err != nil || wg.ListenPort == 0 {
		return nil, fmt.Errorf("invalid proposed WireGuard identity")
	}
	if !local.IsValid() || !local.Addr().Is4() {
		return nil, fmt.Errorf("invalid proposed WireGuard Link address")
	}
	return []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: name},
		{Kind: domain.ResourceLinkAddress, Key: local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: local.Masked().String()},
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(wg.ListenPort))},
		{Kind: domain.ResourceBackendID, Key: "wireguard/local-public/" + wg.LocalPublicKey},
	}, nil
}
