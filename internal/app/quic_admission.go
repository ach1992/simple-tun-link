package app

import (
	"context"
	"net/netip"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// QUICWireGuardProvider is the candidate native WireGuard part of a QUIC
// composition, NOT a persistable or runnable native Link. A later runtime
// backend must commit the exact complete provider/carrier topology together.
type QUICWireGuardProvider struct {
	Addresses domain.LinkAddresses
	WireGuard domain.WireGuardOptions
}

// QUICHostCollisionInspector is a read-only live-host inspector. The existing
// linux.CollisionInspector satisfies this interface without coupling the
// Engine to Linux implementation packages. An empty State is not evidence
// of vacant UDP ports.
type QUICHostCollisionInspector interface {
	Vacant(context.Context, []domain.ResourceClaim) (bool, error)
}

// CheckQUICPreparation is a source-only, READ-ONLY canonical Engine admission
// probe for a NEW optional QUIC/WireGuard Link. The projection must come from
// an already validated quic.Plan.LocalAdmission; it does not carry TLS/peer
// trust and is not a substitute for revalidating the complete Plan. It takes
// maintenance -> Link
// -> resource locks, derives complete native-provider + QUIC carrier claims,
// reloads durable State AFTER acquiring them, checks other Link reservations
// and independently inspects the live host's common collision surfaces.
//
// It deliberately does NOT stage credentials/config, write a crash journal,
// install/start a helper, create WG/nft resources or expose a new backend. A
// successful probe is NOT an effect permit: these locks are released on return
// and real runtime effects must repeat admission under held locks and publish
// a durable pre-effect journal first. Namespace-local absence does not prove
// global kernel identity vacancy or authorize recovery/deletion of old links.
func (e *Engine) CheckQUICPreparation(ctx context.Context, plan composition.QUICLocalAdmission,
	provider QUICWireGuardProvider, host QUICHostCollisionInspector) ([]domain.ResourceClaim, error) {
	const operation = "quic_preparation"
	invalid := func(detail string) error {
		return stlerr.New(stlerr.CodeInvalid, operation, string(plan.LinkID), "quic", detail)
	}
	conflict := func(detail string) error {
		return stlerr.New(stlerr.CodeConflict, operation, string(plan.LinkID), "quic", detail)
	}
	unknown := func(detail string) error {
		return stlerr.New(stlerr.CodeState, operation, string(plan.LinkID), "quic", detail)
	}
	if e == nil || ctx == nil || host == nil {
		return nil, invalid("canonical Engine and live collision inspector are required")
	}
	addresses := provider.Addresses
	if !addresses.Local.IsValid() || !addresses.Peer.IsValid() ||
		!validQUICLinkAddress(addresses.Local) || !validQUICLinkAddress(addresses.Peer) ||
		addresses.Local.Addr() == addresses.Peer.Addr() {
		return nil, invalid("invalid distinct IPv4 WireGuard Link Addresses")
	}
	if provider.WireGuard.PeerPort == 0 {
		return nil, invalid("native WireGuard peer UDP port is required")
	}
	providerClaims, err := composition.WireGuardProviderClaims(plan.LinkID, addresses.Local, provider.WireGuard)
	if err != nil {
		return nil, invalid("invalid native WireGuard provider identity")
	}
	if provider.WireGuard.ListenPort != plan.LocalWGUDPPort {
		return nil, invalid("QUIC kernel WireGuard port differs from the proposed local carrier identity")
	}
	carrierClaims, err := plan.CarrierClaims()
	if err != nil {
		return nil, invalid("invalid QUIC role, TLS endpoint or local UDP topology")
	}
	if plan.Role == composition.Dial && provider.WireGuard.PeerPort != plan.LocalHelperUDPPort {
		// The kernel peer must send to the local QUIC forwarding socket,
		// not directly to the physical remote WireGuard port.
		return nil, invalid("QUIC dial WireGuard endpoint must use the local helper forwarding UDP port")
	}
	claims, err := validatedClaims(unionClaims(providerClaims, carrierClaims))
	if err != nil {
		return nil, invalid("invalid composed WireGuard and QUIC resource claims")
	}

	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return nil, unknown("maintenance gate unavailable")
	}
	defer maintenance()
	unlockLink, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(plan.LinkID)})
	if err != nil {
		return nil, unknown("Link lock unavailable")
	}
	defer unlockLink()
	lockClaims, err := resourceLockClaims(claims)
	if err != nil {
		return nil, unknown("resource lock identities unavailable")
	}
	unlockResources, err := e.locks.Acquire(ctx, lockClaims)
	if err != nil {
		return nil, unknown("resource locks unavailable")
	}
	defer unlockResources()

	fresh, err := e.store.Load(ctx)
	if err != nil {
		return nil, unknown("canonical State unavailable after resource locking")
	}
	if quicLinkIdentityReserved(fresh, plan.LinkID) {
		return nil, conflict("Link identity already committed, pending or retired")
	}
	if err := rejectResourceConflicts(fresh, plan.LinkID, claims); err != nil {
		return nil, conflict("planned resource reserved by another Link or transaction")
	}
	if quicConflictsWithSharedIPsecPorts(fresh, claims) {
		// Native strongSwan shares UDP/500 and /4500 across IPsec Links;
		// these sockets are not exclusively claimed by each IPsec Link.
		// A daemon restart can make ss temporarily report them as vacant.
		return nil, conflict("planned UDP port reserved by a shared IPsec daemon lifecycle")
	}
	var common []domain.ResourceClaim
	for _, claim := range claims {
		switch claim.Kind {
		case domain.ResourceInterface, domain.ResourceLinkAddress, domain.ResourceLinkSubnet, domain.ResourceUDPListenPort:
			common = append(common, claim)
		}
	}
	if len(common) == 0 {
		return nil, unknown("missing common host collision identities")
	}
	vacant, err := host.Vacant(ctx, common)
	if err != nil {
		return nil, unknown("live host collision inventory unavailable or ambiguous")
	}
	if !vacant {
		// Even an apparently STL-owned matching interface/port cannot be
		// adopted by a never-committed candidate QUIC Link.
		return nil, conflict("live host resource occupied or ownership is uncertain")
	}
	if ctx.Err() != nil {
		return nil, unknown("live collision inspection was interrupted")
	}
	return claims, nil
}

func validQUICLinkAddress(prefix netip.Prefix) bool {
	return prefix.Addr().Is4() && prefix.Bits() > 0 && prefix.Bits() <= 32 &&
		!prefix.Addr().IsUnspecified() && !prefix.Addr().IsMulticast()
}

func quicLinkIdentityReserved(s state.Snapshot, id domain.LinkID) bool {
	if _, ok := s.Find(id); ok {
		return true
	}
	if _, ok := s.FindPendingSender(id); ok {
		return true
	}
	if _, ok := s.FindPendingIPsec(id); ok {
		return true
	}
	if _, ok := s.FindWSSCrashOperation(id); ok {
		return true
	}
	if _, ok := s.FindRemovalReceipt(id); ok {
		return true
	}
	if _, ok := s.FindIPsecRemovalReceipt(id); ok {
		return true
	}
	return false
}

func quicConflictsWithSharedIPsecPorts(s state.Snapshot, claims []domain.ResourceClaim) bool {
	usesIKEPort := false
	for _, claim := range claims {
		if claim.Kind == domain.ResourceUDPListenPort && (claim.Key == "500" || claim.Key == "4500") {
			usesIKEPort = true
			break
		}
	}
	if !usesIKEPort {
		return false
	}
	for _, record := range s.Links {
		if record.Desired.Backend == domain.BackendIPsec {
			return true
		}
	}
	// Even a pending private IPsec intent may activate a shared daemon;
	// never treat current listener absence as an exclusive QUIC permit.
	return len(s.PendingIPsec) != 0
}
