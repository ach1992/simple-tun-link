package composition

import (
	"fmt"
	"net/netip"
)

// ValidateComposedPrivateIPv4Route keeps the WSS and prospective QUIC
// kernel-WireGuard inner routing constraints identical. A host address can
// be unicast while its prefix still overlaps loopback/link-local space and
// capture a carrier's mandatory local socket. This is NOT an RFC1918-only
// rule, and native links retain their existing address policy.
func ValidateComposedPrivateIPv4Route(private netip.Prefix) error {
	if !private.IsValid() || !private.Addr().Is4() || !private.Addr().IsGlobalUnicast() {
		return fmt.Errorf("private Link Address must be a routable unicast IPv4 address")
	}
	for _, reserved := range [...]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	} {
		if private.Overlaps(reserved) {
			return fmt.Errorf("private Link route overlaps a non-routable or locally reserved IPv4 range")
		}
	}
	return nil
}
