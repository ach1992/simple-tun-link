package wireguard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// WSSHost is an owned, fail-closed sidecar and ingress controller. Its
// operations are performed exclusively from the canonical Engine's locked
// Backend transaction. A successful start proves no peer handshake or traffic.
type WSSHost interface {
	GuardPresent(context.Context, domain.Link) (bool, error)
	HelperPresent(context.Context, domain.Link) (bool, error)
	HelperLoaded(context.Context, domain.Link) (bool, error)
	Preflight(context.Context, domain.Link, bool) error
	EnsureGuard(context.Context, domain.Link) (core.Rollback, error)
	StartHelper(context.Context, domain.Link) (core.Rollback, error)
	StopHelper(context.Context, domain.Link) (core.Rollback, error)
	RemoveGuard(context.Context, domain.Link) (core.Rollback, error)
}

func wssGuardClaim(id domain.LinkID) domain.ResourceClaim {
	return domain.ResourceClaim{Kind: domain.ResourceFirewall, Key: "wss/nft/" + string(id)}
}
func wssHelperClaim(id domain.LinkID) domain.ResourceClaim {
	return domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "wss/helper/" + string(id)}
}

func (b *Backend) planWSS(ctx context.Context, req core.Request, obs observation) (core.Plan, error) {
	path, err := composition.Build(req.Link, composition.CarrierForLink(req.Link))
	if err != nil {
		return nil, err
	}
	name, _ := InterfaceName(req.Link.ID)
	p := plan{link: req.Link, name: name, guardChange: !obs.GuardPresent,
		helperChange: !obs.HelperPresent}
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(req.Link.WireGuard.ListenPort))},
		wssGuardClaim(req.Link.ID),
	}
	claims = append(claims, path.CarrierClaims()...)
	switch req.Operation {
	case core.OperationEnsure:
		route, err := b.routes.Resolve(ctx, req.Link.Underlay.Peer)
		if err != nil {
			return nil, fmt.Errorf("WSS underlay route: %w", err)
		}
		if route.Source != req.Link.Underlay.Local {
			return nil, fmt.Errorf("WSS physical source does not match resolved route")
		}
		p.route = route
		p.interfaceChange = !obs.Target.matches(req.Link, name)
		p.resources = append(desiredResources(req.Link, name, wssGuardClaim(req.Link.ID)), path.CarrierClaims()...)
	case core.OperationRemove:
		p.interfaceChange = obs.Target.Exists && obs.Target.Owner == req.Link.ID
		p.guardChange = obs.GuardPresent
		p.helperChange = obs.HelperLoaded
		p.resources = claims
	default:
		return nil, fmt.Errorf("unsupported WSS operation")
	}
	return p, nil
}

func (b *Backend) validateWSS(ctx context.Context, req core.Request, obs observation, p plan) error {
	path, err := composition.Build(req.Link, composition.CarrierForLink(req.Link))
	if err != nil {
		return err
	}
	_ = path
	if req.Prior != nil && *req.Prior != req.Link {
		return stlerr.New(stlerr.CodeConflict, "wss_validate", string(req.Link.ID), "wireguard-wss",
			"changing a live WSS Link configuration is not admitted; remove and provision a new Link")
	}
	if obs.Target.Exists {
		original, err := linux.WSSOwnerTag(req.Link.ID, core.WSSOrigin(ctx))
		if err != nil || obs.Target.Alias != original {
			return fmt.Errorf("original WSS kernel interface provenance mismatch")
		}
		if obs.Target.Owner != req.Link.ID {
			return fmt.Errorf("WireGuard interface is foreign; WSS cannot adopt it")
		}
		if err := linux.RequireOwned(req.Link.ID,
			domain.ResourceClaim{Kind: domain.ResourceInterface, Key: p.name}, req.OwnedResources); err != nil {
			return err
		}
		if !obs.Target.matches(req.Link, p.name) {
			return fmt.Errorf("WireGuard interface drift; preserving original state")
		}
	}
	// An existing same-name nft table or systemd service is NOT proof of
	// STL ownership. The Engine must have committed their exact claims.
	if obs.GuardPresent {
		if err := linux.RequireOwned(req.Link.ID, wssGuardClaim(req.Link.ID), req.OwnedResources); err != nil {
			return err
		}
	}
	if obs.HelperLoaded {
		if err := linux.RequireOwned(req.Link.ID, wssHelperClaim(req.Link.ID), req.OwnedResources); err != nil {
			return err
		}
	}
	if req.Operation == core.OperationRemove {
		if p.interfaceChange {
			if err := b.requireRecreationCredential(req.Link); err != nil {
				return err
			}
		}
		return b.rejectForeignReplacement(ctx, req.Link.ID, p.name)
	}
	route, err := b.routes.Resolve(ctx, req.Link.Underlay.Peer)
	if err != nil {
		return err
	}
	if route.Source != req.Link.Underlay.Local || route.Device != p.route.Device {
		return fmt.Errorf("WSS route changed under resource lock")
	}
	if err := b.wssHost.Preflight(ctx, req.Link, obs.GuardPresent); err != nil {
		return err
	}
	if !obs.Target.Exists {
		var claims []domain.ResourceClaim
		for _, claim := range p.resources {
			switch claim.Kind {
			case domain.ResourceInterface, domain.ResourceLinkAddress, domain.ResourceLinkSubnet, domain.ResourceUDPListenPort:
				claims = append(claims, claim)
			}
		}
		collision, err := b.collisions.Inspect(ctx, claims)
		if err != nil {
			return err
		}
		for _, conflict := range collision {
			if conflict.Owner != req.Link.ID {
				return fmt.Errorf("WSS host resource collision: %s", conflict.Claim.Kind)
			}
		}
	}
	if err := b.rejectForeignReplacement(ctx, req.Link.ID, p.name); err != nil {
		return err
	}
	return b.rejectWireGuardSocketAndKeyCollision(ctx, req.Link)
}

func (b *Backend) applyWSS(ctx context.Context, req core.Request, obs observation, p plan) (core.Rollback, error) {
	if req.Operation == core.OperationEnsure {
		return b.ensureWSS(ctx, req, obs, p)
	}
	if req.Operation == core.OperationRemove {
		return b.removeWSS(ctx, req, p)
	}
	return nil, fmt.Errorf("unsupported WSS operation")
}

func (b *Backend) ensureWSS(ctx context.Context, req core.Request, obs observation, p plan) (core.Rollback, error) {
	var undos []core.Rollback
	var progress creationProgress
	verifiedKernelDeletion := false
	undo := func(c context.Context) error {
		for i := len(undos) - 1; i >= 0; i-- {
			if undos[i] == nil {
				continue
			}
			if err := undos[i](c); err != nil {
				// WSS layers have a safety dependency: if a helper cannot
				// be collected, NEVER remove its kernel WG/UDP guard; if
				// WG cannot be undone, never remove the ingress guard.
				return fmt.Errorf("WSS dependency rollback halted, preserving lower protection: %w", err)
			}
		}
		return nil
	}
	// The guard MUST be effective before kernel WG binds its host-wide UDP
	// socket. Reverse-order compensation removes the guard last.
	if p.guardChange {
		revert, err := b.wssHost.EnsureGuard(ctx, req.Link)
		if revert != nil {
			undos = append(undos, func(c context.Context) error {
				if !verifiedKernelDeletion {
					return fmt.Errorf("WSS original kernel deletion not established; retain ingress guard")
				}
				witnessed, witnessErr := core.WithWSSWGDeleted(c, req.Link.ID)
				if witnessErr != nil {
					return witnessErr
				}
				return revert(witnessed)
			})
		}
		if err != nil {
			if errors.Is(err, core.ErrIndeterminateHostEffect) {
				return nil, err
			}
			return undo, err
		}
	}
	if p.interfaceChange {
		if obs.Target.Exists {
			return undo, fmt.Errorf("WSS WG drift blocks recreation")
		}
		revert := func(c context.Context) error {
			if !progress.Created {
				return nil
			}
			if err := b.rollbackCreatedInterface(c, req.Link, p.name, progress); err != nil {
				return err
			}
			verifiedKernelDeletion = true
			return nil
		}
		undos = append(undos, revert)
		var err error
		progress, err = b.createOwnedInterface(ctx, req.Link, p.name)
		if err != nil {
			if errors.Is(err, core.ErrIndeterminateHostEffect) {
				// A kernel NEWLINK can succeed before the caller sees an
				// ACK or before an ifindex can be captured. NEVER undo the
				// only ingress firewall while that outcome is uncertain.
				// Keep durable journal and original nonce-derived staging
				// identity for explicit owner-attested compensation.
				return nil, err
			}
			return undo, err
		}
	}
	if p.helperChange {
		revert, err := b.wssHost.StartHelper(ctx, req.Link)
		if err != nil && errors.Is(err, core.ErrIndeterminateHostEffect) {
			// Could be a live helper. Never undo the kernel socket's
			// protective nft guard while a dependent effect is unknown.
			return nil, err
		}
		if revert != nil {
			undos = append(undos, revert)
		}
		if err != nil {
			return undo, err
		}
	}
	return undo, nil
}

func (b *Backend) removeWSS(ctx context.Context, req core.Request, p plan) (core.Rollback, error) {
	if p.interfaceChange {
		if err := b.requireRecreationCredential(req.Link); err != nil {
			return nil, err
		}
	}
	var undos []core.Rollback
	verifiedKernelDeletion := false
	undo := func(c context.Context) error {
		for i := len(undos) - 1; i >= 0; i-- {
			if undos[i] == nil {
				continue
			}
			if err := undos[i](c); err != nil {
				// WSS layers have a safety dependency: if a helper cannot
				// be collected, NEVER remove its kernel WG/UDP guard; if
				// WG cannot be undone, never remove the ingress guard.
				return fmt.Errorf("WSS dependency rollback halted, preserving lower protection: %w", err)
			}
		}
		return nil
	}
	if p.helperChange {
		revert, err := b.wssHost.StopHelper(ctx, req.Link)
		if err != nil && errors.Is(err, core.ErrIndeterminateHostEffect) {
			return nil, err // keep the kernel/guard relationship intact
		}
		if revert != nil {
			undos = append(undos, revert)
		}
		if err != nil {
			return undo, err
		}
	}
	if p.interfaceChange {
		current, err := b.Inspect(ctx, req.Link)
		if err != nil {
			return undo, err
		}
		target := current.(observation).Target
		if !target.matches(req.Link, p.name) || target.IfIndex <= 0 {
			return undo, fmt.Errorf("WSS WG identity drift before Remove")
		}
		if err := b.deleteLink(ctx, target.IfIndex); err != nil {
			return nil, fmt.Errorf("%w: kernel WG Delete outcome unverified", core.ErrIndeterminateHostEffect)
		}
		verifiedKernelDeletion = true
		undos = append(undos, func(c context.Context) error {
			_, err := b.createOwnedInterface(c, req.Link, p.name)
			return err
		})
	}
	// Only a successful, exact original index-targeted kernel deletion can
	// authorize lifting the UDP guard. A missing/migrated WG interface, even
	// when its socket is momentarily down, is NOT retirement proof.
	if p.guardChange {
		if !verifiedKernelDeletion {
			return undo, fmt.Errorf("WSS kernel original was not verifiably deleted; ingress guard retained")
		}
		witnessed, witnessErr := core.WithWSSWGDeleted(ctx, req.Link.ID)
		if witnessErr != nil {
			return undo, witnessErr
		}
		revert, err := b.wssHost.RemoveGuard(witnessed, req.Link)
		if err != nil && errors.Is(err, core.ErrIndeterminateHostEffect) {
			return nil, err
		}
		if revert != nil {
			undos = append(undos, revert)
		}
		if err != nil {
			return undo, err
		}
	}
	return undo, nil
}

func (b *Backend) verifyWSS(req core.Request, obs observation) (core.Observation, error) {
	name, _ := InterfaceName(req.Link.ID)
	switch req.Operation {
	case core.OperationEnsure:
		if !obs.GuardPresent || !obs.HelperPresent || !obs.Target.matches(req.Link, name) {
			return nil, fmt.Errorf("WSS sidecar/ingress/kernel WireGuard are not concurrently ready")
		}
	case core.OperationRemove:
		if obs.GuardPresent || obs.HelperLoaded || (obs.Target.Exists && obs.Target.Owner == req.Link.ID) {
			return nil, fmt.Errorf("WSS resources remain after Remove")
		}
	default:
		return nil, fmt.Errorf("unsupported WSS Verify")
	}
	return obs, nil
}

// Exact resource-identity comparison is also used by state reconciliations.
func wssOwned(claims []domain.ResourceClaim, id domain.LinkID) bool {
	return slices.Contains(claims, wssGuardClaim(id)) && slices.Contains(claims, wssHelperClaim(id))
}

// CrashHostVacant is ONLY a read-only strict vacancy test for a pre-effect
// WSS journal. A matching name, alias, certificate or public peer key
// must never be treated as sufficient proof to delete or adopt anything.
func (b *Backend) CrashHostVacant(ctx context.Context, observed core.Observation) (bool, error) {
	if b.wssHost == nil {
		return false, fmt.Errorf("WSS host controller not configured")
	}
	current, ok := observed.(observation)
	if !ok {
		return false, fmt.Errorf("unexpected WSS host observation type")
	}
	if current.WSSLink.Backend != domain.BackendWireGuardWSS ||
		current.WSSLink.Validate() != nil {
		return false, fmt.Errorf("WSS crash vacancy has no original valid public Link")
	}
	if current.Target.Exists || current.GuardPresent || current.HelperLoaded {
		return false, nil
	}
	// A namespace-local empty interface inventory AND empty birthplace UDP
	// socket set cannot prove that a moved, DOWN original WG is absent.
	// Require a witness issued after this transaction deleted that exact
	// original kernel object. Read-only vacancy reconciliation of an
	// unproven prior crash remains quarantined for manual recovery.
	if !core.HasWSSWGDeletionWitness(ctx, current.WSSLink.ID) {
		return false, fmt.Errorf("original WSS WG kernel deletion witness absent; preserve crash journal and private material")
	}
	staging, err := linux.WSSStagingName(current.WSSLink.ID, core.WSSOrigin(ctx))
	if err != nil {
		return false, fmt.Errorf("cannot verify WSS original staging provenance")
	}
	original, err := linux.WSSOwnerTag(current.WSSLink.ID, core.WSSOrigin(ctx))
	if err != nil {
		return false, fmt.Errorf("cannot verify WSS original alias provenance")
	}
	for _, entry := range current.Links {
		if entry.Name == staging || entry.Alias == original {
			return false, nil
		}
	}
	// Absence also requires public-only global WireGuard key/port evidence.
	return b.crashWSSGlobalKernelVacant(ctx, current.WSSLink)
}

// crashWSSGlobalKernelVacant is the same complete global inventory proof
// enforced by the WSS host immediately before every nft guard deletion.
func (b *Backend) crashWSSGlobalKernelVacant(ctx context.Context, link domain.Link) (bool, error) {
	if link.Backend != domain.BackendWireGuardWSS || link.Validate() != nil {
		return false, fmt.Errorf("global WSS identity is invalid")
	}
	bounded, ok := b.runner.(linux.BoundedRunner)
	if !ok {
		return false, fmt.Errorf("bounded WireGuard inventory runner unavailable")
	}
	return linux.WSSGlobalWGKernelVacant(ctx, bounded, b.wgBinary,
		link.WireGuard.LocalPublicKey, link.WireGuard.ListenPort)
}
