package wireguard

import (
	"context"
	"errors"
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"runtime"
	"slices"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// QUICHost is the one concrete managed QUIC composition, injected at the
// command composition root. Production adapters fix their manager and host
// readers. The native provider never imports the app-dependent helper package.
type QUICHost interface {
	GuardPresent(context.Context, domain.Link) (bool, error)
	HelperPresent(context.Context, domain.Link) (bool, error)
	HelperLoaded(context.Context, domain.Link) (bool, error)
	Preflight(context.Context, domain.Link, bool) error
	EnsureGuard(context.Context, domain.Link) (core.Rollback, error)
	StartHelper(context.Context, domain.Link) (core.Rollback, error)
	StopHelper(context.Context, domain.Link) (core.Rollback, error)
	RemoveGuard(context.Context, domain.Link) (core.Rollback, error)
	Begin(context.Context, domain.Link, *state.QUICGeneration) (context.Context, func() error, error)
	Attest(context.Context, domain.Link) (state.QUICGeneration, error)
}

func NewQUIC(opts Options) (*Backend, error) {
	if opts.QUICHost == nil || opts.WSSHost != nil {
		return nil, fmt.Errorf("QUIC requires its admitted managed host")
	}
	return New(opts)
}

func (b *Backend) BeginQUIC(ctx context.Context, link domain.Link, prior *state.QUICGeneration) (context.Context, func() error, error) {
	if b.quicHost == nil {
		return nil, nil, fmt.Errorf("managed QUIC host unavailable")
	}
	return b.quicHost.Begin(ctx, link, prior)
}

func (b *Backend) AttestQUIC(ctx context.Context, link domain.Link) (state.QUICGeneration, error) {
	g, err := b.quicHost.Attest(ctx, link)
	if err != nil {
		return state.QUICGeneration{}, err
	}
	o, err := b.Inspect(ctx, link)
	if err != nil {
		return state.QUICGeneration{}, err
	}
	observed := o.(observation)
	if err := b.requireCompleteQUICOriginal(ctx, link, observed.Target, observed.Target.Name); err != nil {
		return state.QUICGeneration{}, err
	}
	g.WGIfIndex = observed.Target.IfIndex
	if err := g.Validate(link); err != nil {
		return state.QUICGeneration{}, err
	}
	return g, nil
}

func (b *Backend) managedHost() WSSHost {
	if b.quicHost != nil {
		return b.quicHost
	}
	return b.wssHost
}
func managedGuardClaim(link domain.Link) domain.ResourceClaim {
	if link.Backend == domain.BackendWireGuardQUIC {
		return domain.ResourceClaim{Kind: domain.ResourceFirewall, Key: "quic/nft/" + string(link.ID)}
	}
	return wssGuardClaim(link.ID)
}
func managedHelperClaim(link domain.Link) domain.ResourceClaim {
	if link.Backend == domain.BackendWireGuardQUIC {
		return domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "quic/helper/" + string(link.ID)}
	}
	return wssHelperClaim(link.ID)
}
func managedOwnerTag(ctx context.Context, link domain.Link) (string, error) {
	if link.Backend == domain.BackendWireGuardQUIC {
		return linux.QUICWGOwnerTag(link.ID, core.QUICOrigin(ctx))
	}
	return linux.WSSOwnerTag(link.ID, core.WSSOrigin(ctx))
}
func managedColdBootWitness(ctx context.Context, link domain.Link) bool {
	if link.Backend == domain.BackendWireGuardQUIC {
		return core.HasQUICColdBootExtinctionWitness(ctx, link.ID)
	}
	return core.HasWSSColdBootExtinctionWitness(ctx, link.ID)
}
func managedWGDeleted(ctx context.Context, link domain.Link) (context.Context, error) {
	if link.Backend == domain.BackendWireGuardQUIC {
		return core.WithQUICWGDeleted(ctx, link.ID)
	}
	return core.WithWSSWGDeleted(ctx, link.ID)
}
func (b *Backend) managedHostVacant(ctx context.Context, link domain.Link, observed core.Observation) (bool, error) {
	if link.Backend == domain.BackendWireGuardQUIC {
		return b.QUICHostVacant(ctx, link)
	}
	return b.CrashHostVacant(ctx, observed)
}

func (b *Backend) requireCompleteQUICOriginal(ctx context.Context, link domain.Link, wg observedLink, name string) error {
	alias, err := linux.QUICWGOwnerTag(link.ID, core.QUICOrigin(ctx))
	if err != nil || !wg.Exists || wg.IfIndex <= 0 || wg.Name != name || wg.Alias != alias ||
		wg.Owner != link.ID || !wg.matches(link, name) || wg.FwMark != 0 {
		return fmt.Errorf("original QUIC WireGuard identity/configuration differs")
	}
	if prior, ok := core.QUICGenerationFromContext(ctx); ok && !core.HasQUICColdBootExtinctionWitness(ctx, link.ID) && wg.IfIndex != prior.WGIfIndex {
		return fmt.Errorf("committed QUIC original ifindex changed")
	}
	addresses, err := b.originalWSSAddresses(ctx, name, wg.IfIndex)
	if err != nil || len(addresses) != 1 || addresses[0] != link.Addresses.Local || !slices.Equal(addresses, wg.IPv4Addresses) {
		return fmt.Errorf("original QUIC WireGuard address metadata differs")
	}
	if err := b.requireOriginalWSSNoPSK(ctx, wg); err != nil {
		return err
	}
	return ctx.Err()
}

func (o observation) QUICOriginalIfIndex() int { return o.Target.IfIndex }
func (p plan) QUICOriginalRemoveIndex() int    { return p.wssOriginalRemoveIfIndex }

func (b *Backend) QUICHostVacant(ctx context.Context, link domain.Link) (bool, error) {
	if b.quicHost == nil || link.Backend != domain.BackendWireGuardQUIC || link.Validate() != nil {
		return false, fmt.Errorf("invalid managed QUIC vacancy request")
	}
	if !core.HasQUICWGDeletionWitness(ctx, link.ID) && !core.HasQUICColdBootExtinctionWitness(ctx, link.ID) {
		return false, fmt.Errorf("QUIC original termination proof missing")
	}
	o, err := b.Inspect(ctx, link)
	if err != nil {
		return false, err
	}
	obs := o.(observation)
	if obs.Target.Exists || obs.GuardPresent || obs.HelperLoaded {
		return false, nil
	}
	staging, err := linux.QUICWGStagingName(link.ID, core.QUICOrigin(ctx))
	if err != nil {
		return false, err
	}
	alias, err := linux.QUICWGOwnerTag(link.ID, core.QUICOrigin(ctx))
	if err != nil {
		return false, err
	}
	for _, entry := range obs.Links {
		if entry.Name == staging || entry.Alias == alias {
			return false, nil
		}
	}
	runner, ok := b.runner.(linux.BoundedRunner)
	if !ok {
		return false, fmt.Errorf("bounded QUIC WG inventory unavailable")
	}
	vacant, err := linux.WSSGlobalWGKernelVacant(ctx, runner, b.wgBinary, link.WireGuard.LocalPublicKey, link.WireGuard.ListenPort)
	if err != nil || !vacant {
		return false, err
	}
	return linux.QUICWGAllStateUDPPortVacant(ctx, runner, link.WireGuard.ListenPort)
}

// QUICRecoveryHostVacant is read-only. It accepts a typed extinction witness
// only to demand complete fresh vacancy; it cannot stop, delete or adopt any
// same-name resource. The fixed helper reader independently reloads the exact
// managed journal and verifies its attempt's later trusted kernel generation.
func (b *Backend) QUICRecoveryHostVacant(ctx context.Context, op state.QUICCrashOperation) (bool, error) {
	if op.Managed == nil || op.Validate() != nil || !core.HasQUICColdBootExtinctionWitness(ctx, op.Managed.Intent.ID) {
		return false, fmt.Errorf("QUIC managed recovery proof missing")
	}
	reader, ok := b.quicHost.(interface {
		VerifyRecoveryHostAbsent(context.Context, state.QUICCrashOperation) error
	})
	if !ok {
		return false, fmt.Errorf("fixed managed QUIC recovery inspection unavailable")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := reader.VerifyRecoveryHostAbsent(ctx, op); err != nil {
		return false, err
	}
	vacant, err := b.QUICHostVacant(ctx, op.Managed.Intent)
	if err != nil || !vacant {
		return false, err
	}
	// Also reject a current non-WireGuard occupant of the reserved interface
	// or private address/subnet. Owner labels never exempt an observation.
	var claims []domain.ResourceClaim
	for _, claim := range op.Resources {
		if claim.Kind == domain.ResourceInterface || claim.Kind == domain.ResourceLinkAddress || claim.Kind == domain.ResourceLinkSubnet {
			claims = append(claims, claim)
		}
	}
	observed, err := b.collisions.Inspect(ctx, claims)
	if err != nil {
		return false, err
	}
	for _, actual := range observed {
		for _, claim := range claims {
			conflict, err := domain.ResourceClaimsConflict(claim, actual.Claim)
			if err != nil {
				return false, err
			}
			if conflict {
				return false, nil
			}
		}
	}
	if err := reader.VerifyRecoveryHostAbsent(ctx, op); err != nil {
		return false, err
	}
	return true, ctx.Err()
}

func (b *Backend) verifyQUIC(ctx context.Context, req core.Request, obs observation) (core.Observation, error) {
	if req.Operation == core.OperationRemove {
		vacant, err := b.QUICHostVacant(ctx, req.Link)
		if err != nil || !vacant {
			return nil, fmt.Errorf("QUIC removal vacancy unverified: %w", errors.Join(err, core.ErrIndeterminateHostEffect))
		}
		return obs, nil
	}
	name, _ := InterfaceName(req.Link.ID)
	if !obs.GuardPresent || !obs.HelperPresent {
		return nil, fmt.Errorf("QUIC guard and helper are not concurrently ready")
	}
	if err := b.requireCompleteQUICOriginal(ctx, req.Link, obs.Target, name); err != nil {
		return nil, err
	}
	return obs, nil
}

// Removing the original kernel object is irreversible as an identity change.
// A later failure retains the managed journal instead of fabricating a
// replacement with the original's persisted ifindex. Before deletion, stopping
// the helper can still be safely compensated by its admitted host scope.
func (b *Backend) removeQUIC(ctx context.Context, req core.Request, obs observation, p plan) (core.Rollback, error) {
	var undoHelper core.Rollback
	deleted := false
	undo := func(c context.Context) error {
		if deleted {
			return fmt.Errorf("QUIC original deleted; retain journal for explicit completion")
		}
		if undoHelper != nil {
			return undoHelper(c)
		}
		return nil
	}
	if p.helperChange {
		var err error
		undoHelper, err = b.quicHost.StopHelper(ctx, req.Link)
		if err != nil {
			if errors.Is(err, core.ErrIndeterminateHostEffect) {
				return nil, err
			}
			return undo, err
		}
	}
	if p.interfaceChange {
		current, err := b.Inspect(ctx, req.Link)
		if err != nil {
			return undo, err
		}
		target := current.(observation).Target
		if target.IfIndex != obs.Target.IfIndex || target.IfIndex != p.wssOriginalRemoveIfIndex {
			return undo, fmt.Errorf("QUIC original ifindex changed before deletion")
		}
		if err := b.requireCompleteQUICOriginal(ctx, req.Link, target, p.name); err != nil {
			return undo, err
		}
		if err := b.deleteLink(ctx, target.IfIndex); err != nil {
			return nil, fmt.Errorf("%w: QUIC kernel deletion outcome uncertain", core.ErrIndeterminateHostEffect)
		}
		deleted = true
	}
	if p.guardChange {
		if !deleted {
			return undo, fmt.Errorf("QUIC original WG deletion missing; retain guard")
		}
		witnessed, err := core.WithQUICWGDeleted(ctx, req.Link.ID)
		if err != nil {
			return undo, err
		}
		if _, err = b.quicHost.RemoveGuard(witnessed, req.Link); err != nil {
			return undo, err
		}
	}
	return undo, nil
}

func (b *Backend) QUICDiagnostic(ctx context.Context, link domain.Link) (core.QUICDiagnostic, error) {
	if b.quicHost == nil {
		return core.QUICDiagnostic{}, fmt.Errorf("managed QUIC host unavailable")
	}
	o, err := b.Inspect(ctx, link)
	if err != nil {
		return core.QUICDiagnostic{}, err
	}
	obs := o.(observation)
	name, _ := InterfaceName(link.ID)
	d := core.QUICDiagnostic{Interface: name, IfIndex: obs.Target.IfIndex, KernelPresent: obs.Target.Exists, GuardActive: obs.GuardPresent, HelperActive: obs.HelperPresent, HelperLoaded: obs.HelperLoaded}
	if !obs.Target.Exists {
		return d, nil
	}
	if err := b.requireCompleteQUICOriginal(ctx, link, obs.Target, name); err != nil {
		return core.QUICDiagnostic{}, err
	}
	wg, err := b.DiagnosticState(ctx, link)
	if err != nil {
		return core.QUICDiagnostic{}, err
	}
	after, err := b.Inspect(ctx, link)
	if err != nil {
		return core.QUICDiagnostic{}, err
	}
	if err := b.requireCompleteQUICOriginal(ctx, link, after.(observation).Target, name); err != nil || wg.IfIndex != obs.Target.IfIndex || after.(observation).Target.IfIndex != obs.Target.IfIndex {
		return core.QUICDiagnostic{}, fmt.Errorf("QUIC original changed during diagnostic observation")
	}
	d.LatestHandshakeUnix, d.RXBytes, d.TXBytes = wg.LatestHandshakeUnix, wg.RXBytes, wg.TXBytes
	return d, nil
}
