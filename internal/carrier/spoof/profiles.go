package spoof

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// These names are STL-owned raw IPv4 wire profiles, not names for TCP
// sessions, GRE tunnels, Linux L2TP devices or other managed STL Backends.
const (
	ProfileAuto        = "auto"
	ProfileUDP         = "udp"
	ProfileICMP        = "icmp"
	ProfileTCP         = "tcp"
	ProfileGRE         = "gre"
	ProfileIPIP        = "ipip"
	ProfileProto58     = "proto58"
	ProfileProto58Echo = "proto58-echo"
	ProfileL2TPv3      = "l2tpv3"
)

// The auto order favors the two already E2E-validated profiles, then explores
// other formats. Failed profiles remain eligible during future complete passes.
var allProfiles = []string{
	ProfileUDP, ProfileICMP, ProfileTCP, ProfileGRE, ProfileIPIP,
	ProfileProto58, ProfileProto58Echo, ProfileL2TPv3,
}

func ValidProfile(profile string) bool {
	if profile == "" || profile == ProfileAuto {
		return true
	}
	for _, name := range allProfiles {
		if profile == name {
			return true
		}
	}
	return false
}

func AllProfiles() []string { return append([]string(nil), allProfiles...) }

func TransmitProfiles(policy string) ([]string, error) {
	if !ValidProfile(policy) {
		return nil, fmt.Errorf("unsupported STL Spoof outer profile %q", policy)
	}
	switch policy {
	case "", ProfileUDP:
		return []string{ProfileUDP}, nil
	case ProfileAuto:
		return AllProfiles(), nil
	default:
		return []string{policy}, nil
	}
}

func ProfileNumber(profile string) (byte, error) {
	switch profile {
	case ProfileUDP:
		return 17, nil
	case ProfileICMP:
		return 1, nil
	case ProfileTCP:
		return 6, nil
	case ProfileGRE:
		return 47, nil
	case ProfileIPIP:
		return 4, nil
	case ProfileProto58, ProfileProto58Echo:
		return 58, nil
	case ProfileL2TPv3:
		return 115, nil
	default:
		return 0, fmt.Errorf("unsupported STL Spoof outer packet profile %q", profile)
	}
}

// ProfileID is the authenticated in-band path hint identifier. It never
// functions as a peer identity: Noise authenticates the entire hint.
func ProfileID(name string) byte {
	for i, profile := range allProfiles {
		if profile == name {
			return byte(i + 1)
		}
	}
	return 0
}
func ProfileFromID(id byte) string {
	if id == 0 || int(id) > len(allProfiles) {
		return ""
	}
	return allProfiles[id-1]
}

type SourcePath struct {
	Source  netip.Addr `json:"source"`
	Profile string     `json:"profile"`
	// Explicit real peer endpoint; zero means the original primary endpoint.
	Destination netip.AddrPort `json:"destination,omitempty"`
}

func (p SourcePath) Valid() bool {
	return p.Source.Is4() && !p.Source.IsUnspecified() && ValidProfile(p.Profile) &&
		p.Profile != "" && p.Profile != ProfileAuto &&
		(!p.Destination.IsValid() || (p.Destination.Addr().Is4() &&
			!p.Destination.Addr().IsUnspecified() && !p.Destination.Addr().IsMulticast() && p.Destination.Port() != 0))
}
func (p SourcePath) String() string {
	if p.Destination.IsValid() {
		return strings.Join([]string{p.Source.String(), p.Profile, p.Destination.String()}, "/")
	}
	return strings.Join([]string{p.Source.String(), p.Profile}, "/")
}

func ValidateProfiles(profiles []string) error {
	if len(profiles) == 0 {
		return errors.New("no outer profiles enabled")
	}
	for _, profile := range profiles {
		if ProfileID(profile) == 0 {
			return fmt.Errorf("invalid STL Spoof outer profile %q", profile)
		}
	}
	return nil
}
