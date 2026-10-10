package state

import (
    "encoding/hex"
    "fmt"
    "net/netip"

    "github.com/ach1992/simple-tun-link/internal/domain"
)

// PendingIPsec is a credential-free, durable Link-specific pre-activation
// reservation. It binds a protected PSK to the entire canonical public Link
// before a SENSITIVE sender handoff can be published. It grants NO authority
// to mutate or delete strongSwan or Linux XFRM state.
type PendingIPsec struct {
    Link domain.Link `json:"link"`
    Origin string `json:"origin"` // "sender" or "recipient"
    // Exact SENSITIVE Quick Link digest; sender only. Never store the URL.
    HandoffSHA256 string `json:"handoff_sha256,omitempty"`
}

func (s Snapshot) FindPendingIPsec(id domain.LinkID) (PendingIPsec, bool) {
    for _, entry := range s.PendingIPsec {
        if entry.Link.ID == id {
            return entry, true
        }
    }
    return PendingIPsec{}, false
}

func (s *Snapshot) DeletePendingIPsec(id domain.LinkID) bool {
    for i, entry := range s.PendingIPsec {
        if entry.Link.ID == id {
            s.PendingIPsec = append(s.PendingIPsec[:i], s.PendingIPsec[i+1:]...)
            return true
        }
    }
    return false
}

func validateIPsecLifecycle(s Snapshot) error {
    seen := make(map[domain.LinkID]bool, len(s.PendingIPsec))
    for _, entry := range s.PendingIPsec {
        l := entry.Link
        if l.Validate() != nil || l.Backend != domain.BackendIPsec ||
            (l.Encapsulation != domain.EncapESP && l.Encapsulation != domain.EncapNATT) ||
            !concreteIPsecAddr(l.Underlay.Local) || !concreteIPsecAddr(l.Underlay.Peer) ||
            !concreteIPsecAddr(l.Addresses.Local.Addr()) || !concreteIPsecAddr(l.Addresses.Peer.Addr()) ||
            l.Addresses.Local.Bits() != 31 || l.Addresses.Peer.Bits() != 31 ||
            l.Addresses.Local.Masked() != l.Addresses.Peer.Masked() {
            return fmt.Errorf("invalid pending IPsec public Link")
        }
        if (entry.Origin != "sender" && entry.Origin != "recipient") ||
            (entry.Origin == "sender" && !validIPsecPendingDigest(entry.HandoffSHA256)) ||
            (entry.Origin == "recipient" && entry.HandoffSHA256 != "") {
            return fmt.Errorf("invalid IPsec credential intent origin or handoff identity")
        }
        if seen[l.ID] {
            return fmt.Errorf("duplicate pending IPsec Link identity")
        }
        if _, exists := s.Find(l.ID); exists {
            return fmt.Errorf("pending IPsec identity also committed")
        }
        if _, exists := s.FindPendingSender(l.ID); exists {
            return fmt.Errorf("pending IPsec identity overlaps WireGuard sender")
        }
        if _, exists := s.FindRemovalReceipt(l.ID); exists {
            return fmt.Errorf("pending IPsec identity overlaps removal receipt")
        }
        seen[l.ID] = true
    }
    return nil
}

func validIPsecPendingDigest(v string) bool {
    if len(v) != 64 { return false }
    decoded, err := hex.DecodeString(v)
    return err == nil && hex.EncodeToString(decoded) == v
}

func concreteIPsecAddr(a netip.Addr) bool {
    if !a.Is4() || !a.IsGlobalUnicast() { return false }
    b := a.As4()
    return b[0] != 0 && b[0] < 240
}
