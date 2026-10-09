package domain

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Common collision-sensitive resource kinds. Backend-specific identities use
// ResourceBackendID with a backend-qualified canonical key rather than adding
// one engine concept per tunnel implementation.
const (
	ResourceInterface     = "interface"
	ResourceLinkAddress   = "link-address"
	ResourceLinkSubnet    = "link-subnet"
	ResourceBackendID     = "backend-id"
	ResourceUDPListenPort = "udp-listen-port"
	ResourceXFRMID        = "xfrm-id"
	ResourceRoute         = "route"
	ResourceFirewall      = "firewall"
	ResourceState         = "state"
	ResourcePersistence   = "persistence"
)

func validateResourceClaim(r ResourceClaim) error {
	if strings.TrimSpace(r.Kind) == "" || strings.TrimSpace(r.Key) == "" {
		return fmt.Errorf("resource claim kind and key are required")
	}
	if strings.ContainsAny(r.Kind, "\r\n\x00") || strings.ContainsAny(r.Key, "\r\n\x00") {
		return fmt.Errorf("resource claim contains invalid control characters")
	}

	switch r.Kind {
	case ResourceLinkAddress:
		addr, err := netip.ParseAddr(r.Key)
		if err != nil || addr.String() != r.Key {
			return fmt.Errorf("link-address resource key must be a canonical IP address")
		}
	case ResourceLinkSubnet:
		prefix, err := netip.ParsePrefix(r.Key)
		if err != nil || prefix.Masked().String() != r.Key {
			return fmt.Errorf("link-subnet resource key must be a canonical masked prefix")
		}
	case ResourceUDPListenPort:
		port, err := strconv.Atoi(r.Key)
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != r.Key {
			return fmt.Errorf("udp-listen-port resource key must be a canonical port number")
		}
	}
	return nil
}

// GREReceiveClaim is the shared, secret-free GRE receive reservation. Kernel
// receive identity depends on underlay endpoints and key presence/value, not
// Native/FOU/GUE or the UDP port. It is intentionally a reservation identity,
// not proof that an interface, mapping, or firewall rule is owned.
func GREReceiveClaim(underlay Underlay, options GREOptions) ResourceClaim {
	key := "absent"
	if options.KeyEnabled {
		key = strconv.FormatUint(uint64(options.Key), 10)
	}
	return ResourceClaim{
		Kind: ResourceBackendID,
		Key:  "gre/rx/" + underlay.Local.String() + "/" + underlay.Peer.String() + "/key=" + key,
	}
}

// ResourceClaimsConflict reports whether two exclusive claims cannot safely be
// owned by separate Links. Most resources conflict by exact identity; Link
// addresses/subnets additionally conflict when their IP ranges overlap.
func ResourceClaimsConflict(a, b ResourceClaim) (bool, error) {
	if err := a.Validate(); err != nil {
		return false, fmt.Errorf("invalid first resource claim: %w", err)
	}
	if err := b.Validate(); err != nil {
		return false, fmt.Errorf("invalid second resource claim: %w", err)
	}
	if a.Canonical() == b.Canonical() {
		return true, nil
	}

	aPrefix, aNetwork := resourceNetwork(a)
	bPrefix, bNetwork := resourceNetwork(b)
	if aNetwork && bNetwork {
		return aPrefix.Overlaps(bPrefix), nil
	}
	return false, nil
}

func resourceNetwork(claim ResourceClaim) (netip.Prefix, bool) {
	switch claim.Kind {
	case ResourceLinkAddress:
		addr, _ := netip.ParseAddr(claim.Key)
		return netip.PrefixFrom(addr, addr.BitLen()), true
	case ResourceLinkSubnet:
		prefix, _ := netip.ParsePrefix(claim.Key)
		return prefix, true
	default:
		return netip.Prefix{}, false
	}
}
