package ipsec

import (
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// DiagnosticOverhead is an intentionally conservative planning budget for the
// selected transport, not a claim about a negotiated transform's exact bytes.
// Linux/ICMP DF diagnostics measure the actual supported size; this value only
// bounds the initial search. No MTU is automatically applied to the host.
func DiagnosticOverhead(link domain.Link) (int, error) {
	if _, err := NewProfile(link); err != nil {
		return 0, fmt.Errorf("invalid IPsec diagnostic profile")
	}
	switch link.Encapsulation {
	case domain.EncapESP:
		return 128, nil
	case domain.EncapNATT:
		return 136, nil
	}
	return 0, fmt.Errorf("unsupported IPsec diagnostic encapsulation")
}
