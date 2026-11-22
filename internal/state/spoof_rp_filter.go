package state

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// SpoofRPFilterClaim is an explicit, confirmed operator policy for one Spoof
// Link. Mode is loose or off; passive status never creates this claim.
type SpoofRPFilterClaim struct {
	LinkID    domain.LinkID `json:"link_id"`
	Interface string        `json:"interface"`
	Mode      string        `json:"mode"`
}

// SpoofRPFilterSetting is a durable pre-effect journal for one Linux sysctl.
// Previous is the prior managed target (or original for first admission).
// At reboot/crash recovery only Original, Previous or Desired may be adopted.
type SpoofRPFilterSetting struct {
	Interface string `json:"interface"` // "all" or an exact incoming Linux NIC
	Original  int    `json:"original"`
	Previous  int    `json:"previous"`
	Desired   int    `json:"desired"`
}

var spoofRPFilterInterface = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

func validSpoofRPFilterInterface(name string) bool {
	return spoofRPFilterInterface.MatchString(name) && name != "." && name != ".." && name != "all" && name != "default"
}

func validateSpoofRPFilter(s Snapshot) error {
	owners := make(map[domain.LinkID]bool)
	settings := make(map[string]bool)
	for _, setting := range s.SpoofRPFilterSettings {
		if setting.Interface != "all" && !validSpoofRPFilterInterface(setting.Interface) ||
			setting.Original < 0 || setting.Original > 2 || setting.Previous < 0 || setting.Previous > 2 ||
			setting.Desired < 0 || setting.Desired > 2 || settings[setting.Interface] {
			return errors.New("invalid or duplicated Spoof rp_filter host setting journal")
		}
		settings[setting.Interface] = true
	}
	off := false
	for _, claim := range s.SpoofRPFilterClaims {
		if claim.LinkID.Validate() != nil || !validSpoofRPFilterInterface(claim.Interface) ||
			(claim.Mode != "off" && claim.Mode != "loose") || owners[claim.LinkID] || !settings[claim.Interface] {
			return errors.New("invalid or duplicated Spoof rp_filter Link claim")
		}
		record, active := s.Find(claim.LinkID)
		if active {
			if record.Desired.Backend != domain.BackendSpoof {
				return fmt.Errorf("rp_filter claim belongs to non-Spoof Link %s", claim.LinkID)
			}
		} else if receipt, present := s.FindSpoofRemovalReceipt(claim.LinkID); !present || receipt.Link.Backend != domain.BackendSpoof {
			return fmt.Errorf("rp_filter claim has no committed Link or exact removal receipt %s", claim.LinkID)
		}
		off = off || claim.Mode == "off"
		owners[claim.LinkID] = true
	}
	if off && !settings["all"] {
		return errors.New("Spoof rp_filter Off claim requires durable global baseline")
	}
	return nil
}
