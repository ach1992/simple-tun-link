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
	undo := func(c context.Context) error {
		var errs []error
		for i := len(undos) - 1; i >= 0; i-- {
			if undos[i] != nil {
				errs = append(errs, undos[i](c))
			}
		}
		return errors.Join(errs...)
	}
	// The guard MUST be effective before kernel WG binds its host-wide UDP
	// socket. Reverse-order compensation removes the guard last.
	if p.guardChange {
		revert, err := b.wssHost.EnsureGuard(ctx, req.Link)
		if revert != nil {
			undos = append(undos, revert)
		}
		if err != nil {
			return undo, err
		}
	}
	if p.interfaceChange {
		if obs.Target.Exists {
			return undo, fmt.Errorf("WSS WG drift blocks recreation")
		}
		revert := func(c context.Context) error {
			if progress.Created {
				return b.rollbackCreatedInterface(c, req.Link, p.name, progress)
			}
			return nil
		}
		undos = append(undos, revert)
		var err error
		progress, err = b.createOwnedInterface(ctx, req.Link, p.name)
		if err != nil {
			return undo, err
		}
	}
	if p.helperChange {
		revert, err := b.wssHost.StartHelper(ctx, req.Link)
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
	undo := func(c context.Context) error {
		var errs []error
		for i := len(undos) - 1; i >= 0; i-- {
			if undos[i] != nil {
				errs = append(errs, undos[i](c))
			}
		}
		return errors.Join(errs...)
	}
	if p.helperChange {
		revert, err := b.wssHost.StopHelper(ctx, req.Link)
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
			return undo, err
		}
		undos = append(undos, func(c context.Context) error {
			_, err := b.createOwnedInterface(c, req.Link, p.name)
			return err
		})
	}
	// With kernel WG gone, the exact owned nft guard can be removed safely.
	if p.guardChange {
		revert, err := b.wssHost.RemoveGuard(ctx, req.Link)
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
