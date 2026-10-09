package gre

import (
	"context"
	"errors"
	"fmt"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

func (b *Backend) Apply(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) (core.Rollback, error) {
	obs, ok := observed.(observation)
	if !ok {
		return nil, fmt.Errorf("unexpected GRE observation type")
	}
	p, ok := candidate.(plan)
	if !ok {
		return nil, fmt.Errorf("unexpected GRE plan type")
	}
	switch req.Operation {
	case core.OperationEnsure:
		return b.applyEnsure(ctx, req, obs, p)
	case core.OperationRemove:
		return b.applyRemove(ctx, req, obs, p)
	default:
		return nil, fmt.Errorf("unsupported GRE operation %q", req.Operation)
	}
}

func (b *Backend) applyEnsure(ctx context.Context, req core.Request, obs observation, p plan) (core.Rollback, error) {
	createdIndex := 0
	interfaceCreated := false
	ownershipMarked := false
	fouCreated := false
	var firewallUndo func(context.Context) error
	rollback := func(undoCtx context.Context) error {
		var errs []error
		if firewallUndo != nil {
			errs = append(errs, firewallUndo(undoCtx))
		}
		if interfaceCreated {
			if createdIndex > 0 {
				errs = append(errs, b.rollbackCreatedInterface(undoCtx, req.Link, p.name, createdIndex, ownershipMarked))
			} else {
				errs = append(errs, b.deleteUnownedCreatedInterface(undoCtx, req.Link, p.name))
			}
		}
		if fouCreated {
			_, err := b.deleteFOU(undoCtx, p.fouMapping)
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}

	if p.fouChange {
		changed, err := b.addFOU(ctx, p.fouMapping)
		fouCreated = changed
		if err != nil {
			return rollback, err
		}
	}
	if p.interfaceChange {
		if obs.Target.Exists {
			return rollback, fmt.Errorf("GRE repair requires explicit reconciliation")
		}
		index, created, owned, err := b.createOwnedInterface(ctx, req.Link, p.name)
		createdIndex, interfaceCreated, ownershipMarked = index, created, owned
		if err != nil {
			return rollback, err
		}
	}
	if p.firewallChange {
		undo, _, err := b.firewall.EnsureInboundLocked(ctx, req.Link.ID, p.firewallRule)
		if err != nil {
			return rollback, err
		}
		firewallUndo = undo
	}
	return rollback, nil
}

func (b *Backend) applyRemove(ctx context.Context, req core.Request, _ observation, p plan) (core.Rollback, error) {
	firewallRemoved := false
	interfaceRemoved := false
	fouRemoved := false
	rollback := func(undoCtx context.Context) error {
		var errs []error
		if fouRemoved {
			_, err := b.addFOU(undoCtx, p.fouMapping)
			errs = append(errs, err)
		}
		if interfaceRemoved {
			_, _, _, err := b.createOwnedInterface(undoCtx, req.Link, p.name)
			errs = append(errs, err)
		}
		if firewallRemoved {
			_, _, err := b.firewall.EnsureInboundLocked(undoCtx, req.Link.ID, p.firewallRule)
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}

	if p.firewallChange {
		removed, err := b.firewall.RemoveInboundLocked(ctx, req.Link.ID, p.firewallRule)
		if err != nil {
			return rollback, err
		}
		firewallRemoved = removed
	}
	if p.interfaceChange {
		fresh, err := b.Inspect(ctx, req.Link)
		if err != nil {
			return rollback, err
		}
		state := fresh.(observation).Target
		if !state.matches(req.Link, p.name) {
			return rollback, fmt.Errorf("GRE interface identity changed before removal")
		}
		if err := b.deleteLink(ctx, state.IfIndex); err != nil {
			return rollback, fmt.Errorf("delete owned GRE interface: %w", err)
		}
		interfaceRemoved = true
	}
	if p.fouChange {
		removed, err := b.deleteFOU(ctx, p.fouMapping)
		fouRemoved = removed
		if err != nil {
			return rollback, err
		}
	}
	return rollback, nil
}

func (b *Backend) createOwnedInterface(ctx context.Context, link domain.Link, name string) (int, bool, bool, error) {
	args := []string{"link", "add", name}
	args = append(args, greTypeArgs(link)...)
	if _, err := b.runner.Run(ctx, b.ipBinary, args...); err != nil {
		return 0, false, false, fmt.Errorf("create GRE interface: %w", err)
	}

	// The successful exclusive name add proves that this operation created an
	// interface at that instant. From here onward we capture and use its kernel
	// ifindex, and revalidate name/index/configuration before ownership marking.
	index, err := b.lookupIndex(name)
	if err != nil || index <= 0 {
		return 0, true, false, fmt.Errorf("resolve created GRE interface identity: %w", err)
	}
	if _, err := b.verifyCreatedInterface(ctx, link, name, index, ""); err != nil {
		return index, true, false, err
	}

	owner, err := linux.OwnerTag(link.ID)
	if err != nil {
		return index, true, false, err
	}
	if err := b.setAlias(ctx, index, owner); err != nil {
		return index, true, false, fmt.Errorf("mark GRE interface ownership: %w", err)
	}
	if _, err := b.verifyCreatedInterface(ctx, link, name, index, link.ID); err != nil {
		return index, true, true, err
	}

	if err := b.addAddress(ctx, index, link.Addresses.Local); err != nil {
		return index, true, true, fmt.Errorf("assign GRE Link Address: %w", err)
	}
	state, err := b.verifyCreatedInterface(ctx, link, name, index, link.ID)
	if err != nil {
		return index, true, true, err
	}
	if len(state.IPv4Addresses) != 1 || state.IPv4Addresses[0] != link.Addresses.Local {
		return index, true, true, fmt.Errorf("verify GRE Link Address: created interface address changed or is ambiguous")
	}
	if err := b.setUp(ctx, index); err != nil {
		return index, true, true, fmt.Errorf("activate GRE interface: %w", err)
	}
	state, err = b.verifyCreatedInterface(ctx, link, name, index, link.ID)
	if err != nil {
		return index, true, true, err
	}
	if !state.matches(link, name) {
		return index, true, true, fmt.Errorf("verify activated GRE interface: final state changed or is incomplete")
	}
	return index, true, true, nil
}

func (b *Backend) verifyCreatedInterface(ctx context.Context, link domain.Link, name string, index int, expectedOwner domain.LinkID) (observedLink, error) {
	fresh, err := b.Inspect(ctx, link)
	if err != nil {
		return observedLink{}, fmt.Errorf("inspect created GRE interface identity: %w", err)
	}
	obs := fresh.(observation)
	state := obs.Target
	if !state.Exists || state.IfIndex != index || state.Owner != expectedOwner || !state.matchesConfigurationBeforeOwnership(link, name) {
		return observedLink{}, fmt.Errorf("created GRE interface identity changed; preserving current host state")
	}
	return state, nil
}

func (b *Backend) rollbackCreatedInterface(ctx context.Context, link domain.Link, name string, index int, ownershipMarked bool) error {
	fresh, err := b.Inspect(ctx, link)
	if err != nil {
		return fmt.Errorf("inspect GRE interface before rollback: %w", err)
	}
	obs := fresh.(observation)
	state := obs.Target
	if !state.Exists {
		for _, candidate := range obs.Links {
			if candidate.IfIndex == index {
				return fmt.Errorf("created GRE ifindex now identifies different state; preserving current host state")
			}
		}
		return nil
	}
	expectedOwner := domain.LinkID("")
	if ownershipMarked {
		expectedOwner = link.ID
	}
	if state.IfIndex != index || state.Owner != expectedOwner || !state.matchesConfigurationBeforeOwnership(link, name) {
		return fmt.Errorf("created GRE interface identity changed before rollback; preserving current host state")
	}
	if err := b.deleteLink(ctx, index); err != nil {
		return fmt.Errorf("delete created GRE interface during rollback: %w", err)
	}
	return nil
}

func (b *Backend) deleteUnownedCreatedInterface(ctx context.Context, link domain.Link, name string) error {
	fresh, err := b.Inspect(ctx, link)
	if err != nil {
		return fmt.Errorf("inspect GRE interface for rollback: %w", err)
	}
	state := fresh.(observation).Target
	if !state.Exists {
		return nil
	}
	if state.Owner != "" || !state.matchesConfigurationBeforeOwnership(link, name) {
		return fmt.Errorf("created GRE interface identity is ambiguous; preserving current state")
	}
	if err := b.deleteLink(ctx, state.IfIndex); err != nil {
		return fmt.Errorf("delete unowned created GRE interface: %w", err)
	}
	return nil
}
