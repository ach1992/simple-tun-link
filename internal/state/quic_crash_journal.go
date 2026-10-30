package state

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// QUICCrashOperation is an immutable, secret-free, pre-effect reservation
// for one *prospective* WireGuard/QUIC Link. Its exact public Plan, binary
// and anticipated protected-file fingerprints are expected identities, NOT
// an ownership certificate or authority to run Hysteria, WG or nft.
// Until a separately reviewed effect/recovery implementation is available,
// unresolved operations remain quarantined and cannot be cleared or replayed.
type QUICCrashOperation struct {
	Managed             *QUICManagedOperation    `json:"managed,omitempty"`
	Plan                composition.QUICHostPlan `json:"plan"`
	Addresses           domain.LinkAddresses     `json:"addresses"`
	WireGuard           domain.WireGuardOptions  `json:"wireguard"`
	Nonce               string                   `json:"nonce"`
	Resources           []domain.ResourceClaim   `json:"resources"`
	CertificateSHA256   string                   `json:"certificate_sha256"`
	TrustCASHA256       string                   `json:"trust_ca_sha256"`
	AuthorizationSHA256 string                   `json:"authorization_sha256"`
	HelperConfigSHA256  string                   `json:"helper_config_sha256"`
	ExecutablePath      string                   `json:"executable_path"`
	ExecutableSHA256    string                   `json:"executable_sha256"`
	ExecutableDevice    uint64                   `json:"executable_device"`
	ExecutableInode     uint64                   `json:"executable_inode"`
}

func (s Snapshot) FindQUICCrashOperation(id domain.LinkID) (QUICCrashOperation, bool) {
	for _, op := range s.QUICCrashOperations {
		if op.Plan.Local.LinkID == id {
			return op, true
		}
	}
	return QUICCrashOperation{}, false
}

// Validate enforces the complete public resource and identity envelope. It
// cannot attest actual private-file bytes, installed binary, live host
// vacancy or cross-host trust; a future runtime must check these separately.
func (op QUICCrashOperation) Validate() error {
	if err := op.Plan.Validate(); err != nil {
		return fmt.Errorf("invalid QUIC pre-effect physical/role/TLS topology: %w", err)
	}
	local := op.Plan.Local
	if !op.Addresses.Local.IsValid() || !op.Addresses.Peer.IsValid() ||
		op.Addresses.Local.Addr() == op.Addresses.Peer.Addr() ||
		composition.ValidateComposedPrivateIPv4Route(op.Addresses.Local) != nil ||
		composition.ValidateComposedPrivateIPv4Route(op.Addresses.Peer) != nil {
		return fmt.Errorf("invalid QUIC pre-effect private Link route")
	}
	// The private tunnel routes must not capture the physical helper endpoint.
	underlay := op.Plan.Physical.Addr()
	if op.Addresses.Local.Contains(underlay) || op.Addresses.Peer.Contains(underlay) {
		return fmt.Errorf("QUIC physical underlay is captured by the private Link route")
	}
	if op.WireGuard.PeerPort == 0 || op.WireGuard.ListenPort != local.LocalWGUDPPort ||
		(local.Role == composition.Dial && ((op.Managed == nil && op.WireGuard.PeerPort != local.LocalHelperUDPPort) || (op.Managed != nil && op.WireGuard.PeerPort != local.RemoteWGUDPPort))) {
		return fmt.Errorf("invalid QUIC pre-effect WireGuard and carrier UDP ports")
	}
	provider, err := composition.WireGuardProviderClaims(local.LinkID, op.Addresses.Local, op.WireGuard)
	if err != nil {
		return fmt.Errorf("invalid QUIC pre-effect native WireGuard identity: %w", err)
	}
	carrier, err := local.CarrierClaims()
	if err != nil {
		return err
	}
	uniqueRequired := make(map[string]domain.ResourceClaim, len(provider)+len(carrier))
	for _, claim := range append(provider, carrier...) {
		if err := claim.Validate(); err != nil {
			return fmt.Errorf("invalid required QUIC resource claim")
		}
		uniqueRequired[claim.Canonical()] = claim
	}
	got := make(map[string]bool, len(op.Resources))
	for _, claim := range op.Resources {
		if err := claim.Validate(); err != nil {
			return fmt.Errorf("invalid QUIC pre-effect resource claim")
		}
		if got[claim.Canonical()] {
			return fmt.Errorf("duplicate QUIC pre-effect resource claim")
		}
		got[claim.Canonical()] = true
	}
	if len(got) != len(uniqueRequired) {
		return fmt.Errorf("QUIC pre-effect journal has incomplete or foreign resource claims")
	}
	for key := range uniqueRequired {
		if !got[key] {
			return fmt.Errorf("QUIC pre-effect journal is missing a required resource")
		}
	}
	if raw, err := hex.DecodeString(op.Nonce); err != nil || len(raw) != 16 || hex.EncodeToString(raw) != op.Nonce {
		return fmt.Errorf("invalid QUIC pre-effect nonce")
	}
	for _, digest := range []string{op.CertificateSHA256, op.TrustCASHA256,
		op.AuthorizationSHA256, op.HelperConfigSHA256, op.ExecutableSHA256} {
		if !validIPsecPendingDigest(digest) {
			return fmt.Errorf("missing or invalid QUIC pre-effect fingerprint")
		}
	}
	if op.ExecutableDevice == 0 || op.ExecutableInode == 0 ||
		!filepath.IsAbs(op.ExecutablePath) || filepath.Clean(op.ExecutablePath) != op.ExecutablePath ||
		op.ExecutablePath == "/" || strings.ContainsAny(op.ExecutablePath, "\x00\r\n") {
		return fmt.Errorf("invalid QUIC pre-effect pinned executable identity")
	}
	if op.Managed != nil {
		return op.ValidateManaged()
	}
	return nil
}

func validateQUICCrashOperations(s Snapshot) error {
	seen := make(map[domain.LinkID]bool, len(s.QUICCrashOperations))
	for i, op := range s.QUICCrashOperations {
		if err := op.Validate(); err != nil {
			return err
		}
		id := op.Plan.Local.LinkID
		if seen[id] {
			return fmt.Errorf("duplicate QUIC pre-effect Link intent")
		}
		seen[id] = true
		record, exists := s.Find(id)
		if op.Managed == nil {
			if exists {
				return fmt.Errorf("QUIC pre-effect Link ID already committed")
			}
		} else if exists != op.Managed.HadCommittedLink || (exists && (record.Desired != op.Managed.Intent || record.QUICGeneration != op.Managed.OriginalGeneration)) {
			return fmt.Errorf("managed QUIC journal original committed owner changed")
		}
		if _, exists := s.FindPendingSender(id); exists {
			return fmt.Errorf("QUIC pre-effect Link ID overlaps pending WireGuard")
		}
		if _, exists := s.FindPendingIPsec(id); exists {
			return fmt.Errorf("QUIC pre-effect Link ID overlaps pending IPsec")
		}
		if _, exists := s.FindWSSCrashOperation(id); exists {
			return fmt.Errorf("QUIC pre-effect Link ID overlaps WSS crash journal")
		}
		if _, exists := s.FindRemovalReceipt(id); exists {
			return fmt.Errorf("QUIC pre-effect Link ID is retired")
		}
		if _, exists := s.FindIPsecRemovalReceipt(id); exists {
			return fmt.Errorf("QUIC pre-effect Link ID has an IPsec removal receipt")
		}
		for _, record := range s.Links {
			if op.Managed != nil && record.Desired.ID == id {
				continue
			}
			for _, reserved := range record.OwnedResources {
				if conflictQUICClaims(op.Resources, []domain.ResourceClaim{reserved}) {
					return fmt.Errorf("QUIC pre-effect claims overlap a committed Link")
				}
			}
		}
		// The corresponding canonical Engine also reserves these pending
		// resources. Persisted State must enforce them independently, so a
		// hand-edited or out-of-band State writer cannot bypass admission.
		for _, pending := range s.PendingSenders {
			if conflictQUICClaims(op.Resources, quicLocalAddressClaims(pending.Link.Addresses.Local)) {
				return fmt.Errorf("QUIC pre-effect claims overlap pending WireGuard sender")
			}
		}
		for _, pending := range s.PendingIPsec {
			if conflictQUICClaims(op.Resources, quicLocalAddressClaims(pending.Link.Addresses.Local)) {
				return fmt.Errorf("QUIC pre-effect claims overlap pending IPsec Link Address")
			}
		}
		// strongSwan's daemon-wide IKE sockets are shared and may be
		// temporarily absent while committed/pending IPsec still owns them.
		// Per-Link IPsec resource claims do NOT reserve these socket IDs.
		if quicReservesSharedIKE(op.Resources) &&
			(len(s.PendingIPsec) != 0 || slices.ContainsFunc(s.Links, func(record LinkRecord) bool {
				return record.Desired.Backend == domain.BackendIPsec
			})) {
			return fmt.Errorf("QUIC pre-effect intent overlaps shared strongSwan daemon UDP ports")
		}
		for _, wss := range s.WSSCrashOperations {
			if conflictQUICClaims(op.Resources, wss.Resources) {
				return fmt.Errorf("QUIC pre-effect claims overlap interrupted WSS")
			}
		}
		for j := 0; j < i; j++ {
			if conflictQUICClaims(op.Resources, s.QUICCrashOperations[j].Resources) {
				return fmt.Errorf("QUIC pre-effect claims overlap another QUIC journal")
			}
		}
	}
	return nil
}

// A malformed or uncomparable claim is a conflict, never permission to
// adopt a resource, even for an otherwise unowned candidate.
func conflictQUICClaims(a, b []domain.ResourceClaim) bool {
	return slices.ContainsFunc(a, func(first domain.ResourceClaim) bool {
		return slices.ContainsFunc(b, func(second domain.ResourceClaim) bool {
			conflict, err := domain.ResourceClaimsConflict(first, second)
			return err != nil || conflict
		})
	})
}

// Compatibility-only pending local routes are not committed ownership
// certificates; they must still block a competing pre-effect operation.
func quicLocalAddressClaims(local netip.Prefix) []domain.ResourceClaim {
	return []domain.ResourceClaim{
		{Kind: domain.ResourceLinkAddress, Key: local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: local.Masked().String()},
	}
}

func quicReservesSharedIKE(claims []domain.ResourceClaim) bool {
	return slices.ContainsFunc(claims, func(c domain.ResourceClaim) bool {
		return c.Kind == domain.ResourceUDPListenPort && (c.Key == "500" || c.Key == "4500")
	})
}
