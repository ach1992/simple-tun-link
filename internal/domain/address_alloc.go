package domain

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Private31Candidates produces bounded, unpredictable /31 proposals from all
// three RFC1918 ranges. The proposals are not reservations: only the Engine's
// resource locks and fresh host-state validation authorize an actual apply.
func Private31Candidates() ([]netip.Prefix, error) {
	type pool struct {
		base uint32
		bits uint
	}
	pools := [...]pool{
		{base: 0x0a000000, bits: 8},
		{base: 0xac100000, bits: 12},
		{base: 0xc0a80000, bits: 16},
	}
	const proposalsPerPool = 16
	candidates := make([]netip.Prefix, 0, len(pools)*proposalsPerPool)
	seen := make(map[netip.Prefix]bool)
	for attempt := 0; attempt < proposalsPerPool*len(pools)*4 && len(candidates) < cap(candidates); attempt++ {
		p := pools[attempt%len(pools)]
		var random [4]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, fmt.Errorf("cannot generate private Link Address candidates")
		}
		pairCount := uint32(1) << (32 - p.bits - 1)
		number := p.base + 2*(binary.BigEndian.Uint32(random[:])%pairCount)
		addr := [4]byte{byte(number >> 24), byte(number >> 16), byte(number >> 8), byte(number)}
		prefix := netip.PrefixFrom(netip.AddrFrom4(addr), 31)
		if !seen[prefix] {
			candidates = append(candidates, prefix)
			seen[prefix] = true
		}
	}
	if len(candidates) != cap(candidates) {
		return nil, fmt.Errorf("cannot generate distinct private Link Address candidates")
	}
	return candidates, nil
}

// ValidatePrivate31 validates a human-supplied /31 NETWORK, not an endpoint.
// Non-canonical host-side spellings are rejected rather than silently masked.
func ValidatePrivate31(prefix netip.Prefix) error {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() != 31 ||
		prefix.Masked() != prefix || !prefix.Addr().IsPrivate() {
		return fmt.Errorf("Link subnet must be a canonical RFC1918 IPv4 /31 network")
	}
	return nil
}

// FreePrivate31 compares proposals against claims from both the live Linux
// inspector and all persisted Links. It uses the engine's canonical overlap
// semantics; the mutable source snapshots must still be rechecked at apply.
func FreePrivate31(candidates []netip.Prefix, occupied []ResourceClaim) (netip.Prefix, bool, error) {
	for _, candidate := range candidates {
		if err := ValidatePrivate31(candidate); err != nil {
			return netip.Prefix{}, false, err
		}
		claim := ResourceClaim{Kind: ResourceLinkSubnet, Key: candidate.String()}
		busy := false
		for _, existing := range occupied {
			conflict, err := ResourceClaimsConflict(claim, existing)
			if err != nil {
				return netip.Prefix{}, false, fmt.Errorf("cannot compare Link Address reservations: %w", err)
			}
			if conflict {
				busy = true
				break
			}
		}
		if !busy {
			return candidate, true, nil
		}
	}
	return netip.Prefix{}, false, nil
}
