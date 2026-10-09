package domain

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type LinkID string

type Backend string

type Encapsulation string

const (
	BackendGRE       Backend = "gre"
	BackendIPIP      Backend = "ipip"
	BackendWireGuard Backend = "wireguard"
	BackendIPsec     Backend = "ipsec"

	EncapNative Encapsulation = "native"
	EncapFOU    Encapsulation = "fou"
	EncapGUE    Encapsulation = "gue"
	EncapUDP    Encapsulation = "udp"
	EncapESP    Encapsulation = "esp"
	EncapNATT   Encapsulation = "nat-t"
)

type Underlay struct {
	Local netip.Addr `json:"local"`
	Peer  netip.Addr `json:"peer"`
}

type LinkAddresses struct {
	Local netip.Prefix `json:"local"`
	Peer  netip.Prefix `json:"peer"`
}

// GREOptions is the GRE-specific desired configuration carried by a Link.
// The zero value is the simple unkeyed GRE default. KeyEnabled distinguishes
// an explicit GRE key value of zero from an unkeyed tunnel.
type GREOptions struct {
	KeyEnabled   bool   `json:"key_enabled,omitempty"`
	Key          uint32 `json:"key,omitempty"`
	TTL          uint8  `json:"ttl,omitempty"`
	TOS          uint8  `json:"tos,omitempty"`
	DisablePMTUD bool   `json:"disable_pmtud,omitempty"`
	Checksum     bool   `json:"checksum,omitempty"`
	Sequence     bool   `json:"sequence,omitempty"`
	UDPPort      uint16 `json:"udp_port,omitempty"`
}

// Link is desired backend-neutral state. Interface names and backend-owned
// resource identities deliberately do not participate in Link identity.
type Link struct {
	ID            LinkID        `json:"id"`
	DisplayName   string        `json:"display_name,omitempty"`
	Underlay      Underlay      `json:"underlay"`
	Addresses     LinkAddresses `json:"addresses"`
	Backend       Backend       `json:"backend"`
	Encapsulation Encapsulation `json:"encapsulation"`
	// GRE is meaningful only when Backend == BackendGRE. omitzero keeps the
	// backend-neutral JSON compact while preserving Link comparability.
	GRE GREOptions `json:"gre,omitzero"`
}

// ResourceClaim is a secret-free identity for a collision-sensitive host
// resource. Backends must never place credential material in Kind or Key.
type ResourceClaim struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

func NewLinkID() (LinkID, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", stlerr.Wrap(stlerr.CodeInternal, "new_link_id", "", "", "cannot generate Link ID", err)
	}
	return LinkID("lnk_" + hex.EncodeToString(raw[:])), nil
}

func (id LinkID) Validate() error {
	s := string(id)
	if len(s) != 36 || !strings.HasPrefix(s, "lnk_") {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", s, "", "Link ID must use lnk_ followed by 32 hexadecimal characters")
	}
	if _, err := hex.DecodeString(s[4:]); err != nil {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", s, "", "Link ID contains non-hexadecimal characters")
	}
	return nil
}

func (l Link) Validate() error {
	if err := l.ID.Validate(); err != nil {
		return err
	}
	if !l.Underlay.Local.IsValid() || !l.Underlay.Peer.IsValid() {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "underlay local and peer addresses are required")
	}
	if l.Underlay.Local == l.Underlay.Peer {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "underlay local and peer addresses must differ")
	}
	if !l.Addresses.Local.IsValid() || !l.Addresses.Peer.IsValid() {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "local and peer Link Addresses are required")
	}
	if !l.Addresses.Local.Addr().Is4() || !l.Addresses.Peer.Addr().Is4() {
		return stlerr.New(stlerr.CodeUnsupported, "validate_link", string(l.ID), string(l.Backend), "v0.1 Link Addresses must be IPv4")
	}
	if l.Addresses.Local.Addr() == l.Addresses.Peer.Addr() {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "local and peer Link Addresses must differ")
	}
	if l.Backend == "" {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), "", "backend is required")
	}
	if l.Encapsulation == "" {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "encapsulation is required")
	}
	if l.Backend != BackendGRE && l.GRE != (GREOptions{}) {
		return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "GRE options are only valid for the GRE backend")
	}
	if l.Backend == BackendGRE {
		switch l.Encapsulation {
		case EncapNative, EncapFOU, EncapGUE:
		default:
			return stlerr.New(stlerr.CodeUnsupported, "validate_link", string(l.ID), string(l.Backend), "unsupported GRE encapsulation")
		}
		if !l.GRE.KeyEnabled && l.GRE.Key != 0 {
			return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "GRE key value requires key_enabled")
		}
		switch l.Encapsulation {
		case EncapNative:
			if l.GRE.UDPPort != 0 {
				return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "GRE Native does not use a UDP encapsulation port")
			}
		case EncapFOU, EncapGUE:
			if l.GRE.UDPPort == 0 {
				return stlerr.New(stlerr.CodeInvalid, "validate_link", string(l.ID), string(l.Backend), "GRE FOU/GUE requires a UDP encapsulation port")
			}
		}
	}
	return nil
}

func (r ResourceClaim) Validate() error {
	return validateResourceClaim(r)
}

func (r ResourceClaim) Canonical() string {
	return r.Kind + "\x00" + r.Key
}
