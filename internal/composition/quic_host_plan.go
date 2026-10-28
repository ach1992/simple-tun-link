package composition

import (
	"fmt"
	"net/netip"
	"strings"
)

// QUICHostPlan retains all public, endpoint-local information of an already
// validated Hysteria Plan, rather than journaling the collision-only port
// projection as if it also pinned TLS and physical routing. No secrets.
// It is NOT a runnable Link or permission to create any host resources.
type QUICHostPlan struct {
	Local    QUICLocalAdmission `json:"local"`
	Physical netip.AddrPort     `json:"physical"`
	TLSName  string             `json:"tls_name"`
}

// ValidQUICTLSName is the precise existing Hysteria SAN/DNS selection rule,
// reused by the source renderer and canonical durable-journal validation.
// An IP SAN must be the exact physical endpoint, not an override.
func ValidQUICTLSName(name string, physical netip.Addr) bool {
	if name == "" || len(name) > 253 || strings.TrimSpace(name) != name ||
		strings.ContainsAny(name, "/\\:@ \t\r\n\x00") {
		return false
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		return addr.Is4() && addr.Zone() == "" && addr == physical
	}
	if strings.HasSuffix(name, ".") || !strings.Contains(name, ".") {
		return false
	}
	for _, part := range strings.Split(name, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, ch := range part {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func (p QUICHostPlan) Validate() error {
	if _, err := p.Local.CarrierClaims(); err != nil {
		return fmt.Errorf("invalid QUIC local carrier identity: %w", err)
	}
	if !p.Physical.IsValid() || !p.Physical.Addr().Is4() ||
		p.Physical.Addr().IsUnspecified() || p.Physical.Addr().IsMulticast() ||
		p.Physical.Addr().IsLoopback() || p.Physical.Port() == 0 ||
		!ValidQUICTLSName(p.TLSName, p.Physical.Addr()) {
		return fmt.Errorf("QUIC journal requires a concrete authenticated non-loopback physical endpoint")
	}
	if p.Local.Role == Listen && p.Local.LocalHelperUDPPort != p.Physical.Port() {
		return fmt.Errorf("QUIC listener's local physical UDP port differs from the journaled carrier")
	}
	return nil
}
