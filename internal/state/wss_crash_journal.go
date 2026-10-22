package state

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// WSSCrashOperation is a durable, secret-free PRE-EFFECT intent. It is
// NOT proof of ownership of any nft table, kernel interface or systemd unit.
type WSSCrashOperation struct {
	Intent           domain.Link            `json:"intent"`
	Operation        string                 `json:"operation"`
	Nonce            string                 `json:"nonce"`
	Resources        []domain.ResourceClaim `json:"resources"`
	HadCommittedLink bool                   `json:"had_committed_link"`
}

func (s Snapshot) FindWSSCrashOperation(id domain.LinkID) (WSSCrashOperation, bool) {
	for _, op := range s.WSSCrashOperations {
		if op.Intent.ID == id {
			return op, true
		}
	}
	return WSSCrashOperation{}, false
}
func (s *Snapshot) DeleteWSSCrashOperation(id domain.LinkID) bool {
	for i := range s.WSSCrashOperations {
		if s.WSSCrashOperations[i].Intent.ID == id {
			s.WSSCrashOperations = append(s.WSSCrashOperations[:i], s.WSSCrashOperations[i+1:]...)
			return true
		}
	}
	return false
}

// This is a schema-integrity requirement, never host ownership evidence.
// Every durable prepared operation must reserve all compatibility-relevant
// host effects. A manually trimmed State record is a hard parse error, not
// permission for another Link to reuse the omitted port/interface.
func requiredWSSCrashClaims(op WSSCrashOperation) ([]domain.ResourceClaim, error) {
	link := op.Intent
	path, err := composition.Build(link, composition.CarrierForLink(link))
	if err != nil {
		return nil, fmt.Errorf("WSS crash journal has unsupported topology")
	}
	wanted := []domain.ResourceClaim{
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(link.WireGuard.ListenPort))},
		{Kind: domain.ResourceFirewall, Key: "wss/nft/" + string(link.ID)},
	}
	wanted = append(wanted, path.CarrierClaims()...)
	if op.Operation == "ensure" {
		name := "stlwg" + string(link.ID)[4:14]
		wanted = append(wanted,
			domain.ResourceClaim{Kind: domain.ResourceInterface, Key: name},
			domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
			domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
			domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "wireguard/local-public/" + link.WireGuard.LocalPublicKey},
		)
	}
	return wanted, nil
}

func validateWSSCrashOperations(s Snapshot) error {
	seen := map[domain.LinkID]bool{}
	for _, op := range s.WSSCrashOperations {
		if err := op.Intent.Validate(); err != nil || op.Intent.Backend != domain.BackendWireGuardWSS {
			return fmt.Errorf("invalid WSS pre-effect operation Link identity")
		}
		if op.Operation != "ensure" && op.Operation != "remove" {
			return fmt.Errorf("invalid WSS pre-effect operation")
		}
		id := op.Intent.ID
		if seen[id] {
			return fmt.Errorf("duplicate WSS pre-effect operation")
		}
		seen[id] = true
		nonce, err := hex.DecodeString(op.Nonce)
		if err != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != op.Nonce {
			return fmt.Errorf("invalid WSS pre-effect transaction nonce")
		}
		if len(op.Resources) == 0 {
			return fmt.Errorf("empty WSS pre-effect resource reservation")
		}
		claims := map[string]bool{}
		for _, c := range op.Resources {
			if err := c.Validate(); err != nil {
				return fmt.Errorf("invalid WSS pre-effect resource claim")
			}
			if claims[c.Canonical()] {
				return fmt.Errorf("duplicate WSS pre-effect resource claim")
			}
			claims[c.Canonical()] = true
		}
		required, err := requiredWSSCrashClaims(op)
		if err != nil {
			return err
		}
		for _, claim := range required {
			if !slices.Contains(op.Resources, claim) {
				return fmt.Errorf("WSS pre-effect journal is missing a required host-resource reservation")
			}
		}
		committed, exists := s.Find(id)
		if exists != op.HadCommittedLink || (exists && committed.Desired != op.Intent) {
			return fmt.Errorf("WSS pre-effect journal mismatches committed Link")
		}
		if op.Operation == "remove" && !exists {
			return fmt.Errorf("WSS Remove cannot be prepared without committed Link")
		}
		if _, ok := s.FindRemovalReceipt(id); ok {
			return fmt.Errorf("WSS pre-effect operation overlaps removal receipt")
		}
		if _, ok := s.FindPendingIPsec(id); ok {
			return fmt.Errorf("WSS pre-effect operation overlaps pending IPsec")
		}
	}
	return nil
}
