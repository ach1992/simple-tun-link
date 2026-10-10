package app

import (
	"context"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// IPsecVICIInventory is deliberately read-only. A daemon name is presence,
// NOT evidence of STL's ownership.
type IPsecVICIInventory interface {
	Inspect(context.Context, ipsec.Profile) (ipsec.Snapshot, error)
}

// IPsecXFRMVacancy verifies kernel interface/name/if_id and orphan policy/SA
// collisions, without modifying the host.
type IPsecXFRMVacancy interface {
	RequireVacant(context.Context, ipsec.Profile) error
}

// IPsecProtectedKeyReader loads only verified, protected per-Link PSKs.
// Callers zeroize the returned opaque value and never expose its bytes.
type IPsecProtectedKeyReader interface {
	Load(domain.LinkID) (ipsec.PSK, error)
}

// CheckIPsecActivationVacancy is a READ-ONLY precursor for the eventual
// operational transaction. It holds the canonical maintenance -> Link ->
// resource locks, verifies an exact durable PendingIPsec record and protected
// key, then checks daemon and kernel collision surfaces. A passing check
// does NOT grant VICI/XFRM mutation or ownership: the future activation
// transaction must repeat all checks immediately before its own writes,
// preserving locks and its own durable creation/recovery proof.
func (e *Engine) CheckIPsecActivationVacancy(ctx context.Context, id domain.LinkID, keys IPsecProtectedKeyReader, vici IPsecVICIInventory, xfrm IPsecXFRMVacancy) error {
	const op = "ipsec_vacancy"
	invalid := func(msg string) error {
		return stlerr.New(stlerr.CodeInvalid, op, string(id), "ipsec", msg)
	}
	conflict := func(msg string) error {
		return stlerr.New(stlerr.CodeConflict, op, string(id), "ipsec", msg)
	}
	unknown := func(msg string) error {
		return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", msg)
	}
	if e == nil || ctx == nil || keys == nil || vici == nil || xfrm == nil {
		return invalid("canonical Engine, protected key and both read-only inspectors are required")
	}
	if err := id.Validate(); err != nil {
		return invalid("invalid Link identity")
	}
	releaseMaintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return unknown("maintenance gate unavailable")
	}
	defer releaseMaintenance()
	releaseLink, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return unknown("Link ownership lock unavailable")
	}
	defer releaseLink()
	initial, err := e.store.Load(ctx)
	if err != nil {
		return unknown("canonical state unavailable")
	}
	entry, present := initial.FindPendingIPsec(id)
	if !present {
		return conflict("durable IPsec credential intent is required")
	}
	if _, committed := initial.Find(id); committed {
		return conflict("IPsec Link is already committed")
	}
	profile, err := ipsec.NewProfile(entry.Link)
	if err != nil {
		return invalid("noncanonical pending IPsec identity")
	}
	claims, err := validatedClaims(profile.ResourceClaims())
	if err != nil {
		return invalid("invalid IPsec resource claims")
	}
	lockClaims, err := resourceLockClaims(claims)
	if err != nil {
		return unknown("invalid resource locks")
	}
	releaseResources, err := e.locks.Acquire(ctx, lockClaims)
	if err != nil {
		return unknown("resource ownership locks unavailable")
	}
	defer releaseResources()

	// Recheck AFTER acquiring resources. A previous observation does not
	// reserve them, and no per-Link key or name is enough to claim ownership.
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return unknown("canonical state cannot be revalidated")
	}
	updated, exists := snapshot.FindPendingIPsec(id)
	if !exists || updated != entry {
		return conflict("IPsec pending intent changed during preflight")
	}
	if _, committed := snapshot.Find(id); committed {
		return conflict("IPsec Link is already committed")
	}
	if _, sender := snapshot.FindPendingSender(id); sender {
		return conflict("WireGuard reserves Link identity")
	}
	if _, receipt := snapshot.FindRemovalReceipt(id); receipt {
		return conflict("credential retirement reserves Link identity")
	}
	if err := rejectResourceConflicts(snapshot, id, claims); err != nil {
		return conflict("IPsec resource reserved by another Link")
	}
	key, err := keys.Load(id)
	if err != nil {
		return conflict("staged IPsec protected credential is missing or unsafe")
	}
	key.Zeroize()

	daemon, err := vici.Inspect(ctx, profile)
	if err != nil {
		return unknown("strongSwan inventory unavailable or ambiguous")
	}
	if daemon.ConnectionNamePresent || daemon.SecretNamePresent {
		return conflict("matching strongSwan identity already exists; ownership cannot be inferred")
	}
	if err := xfrm.RequireVacant(ctx, profile); err != nil {
		return conflict("XFRM inventory ambiguous or resource is already occupied")
	}
	if err := ctx.Err(); err != nil {
		return unknown("IPsec vacancy check was interrupted")
	}
	// Never emit a writable grant/permit, nor record ownership in state here.
	// In particular, a foreign strongSwan administrator can race this check.
	return nil
}

// Explicit interface assertions ensure the production protected store and
// read-only VICI reader implement the exact preflight surfaces.
var (
	_ IPsecProtectedKeyReader = (*ipsec.PSKStore)(nil)
	_ IPsecVICIInventory      = ipsec.Reader{}
	_ IPsecXFRMVacancy        = ipsec.XFRMVacancyInspector{}
)
