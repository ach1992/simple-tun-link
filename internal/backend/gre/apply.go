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
	fouCreated := false
	var firewallUndo func(context.Context) error
	rollback := func(undoCtx context.Context) error {
		var errs []error
		if firewallUndo != nil {
			errs = append(errs, firewallUndo(undoCtx))
		}
		if interfaceCreated {
			if createdIndex > 0 {
				errs = append(errs, b.deleteLink(undoCtx, createdIndex))
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
		index, created, err := b.createOwnedInterface(ctx, req.Link, p.name)
		createdIndex, interfaceCreated = index, created
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
			_, _, err := b.createOwnedInterface(undoCtx, req.Link, p.name)
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

func (b *Backend) createOwnedInterface(ctx context.Context, link domain.Link, name string) (int, bool, error) {
	args := []string{"link", "add", name}
	args = append(args, greTypeArgs(link)...)
	if _, err := b.runner.Run(ctx, b.ipBinary, args...); err != nil {
		return 0, false, fmt.Errorf("create GRE interface: %w", err)
	}

	// Capture the kernel identity created by the successful exclusive name add.
	index, err := b.lookupIndex(name)
	if err != nil || index <= 0 {
		return 0, true, fmt.Errorf("resolve created GRE interface identity: %w", err)
	}
	owner, err := linux.OwnerTag(link.ID)
	if err != nil {
		return index, true, err
	}
	if err := b.setAlias(ctx, index, owner); err != nil {
		return index, true, fmt.Errorf("mark GRE interface ownership: %w", err)
	}
	if _, err := b.runner.Run(ctx, b.ipBinary, "address", "add", link.Addresses.Local.String(), "dev", name); err != nil {
		return index, true, fmt.Errorf("assign GRE Link Address: %w", err)
	}
	if _, err := b.runner.Run(ctx, b.ipBinary, "link", "set", "dev", name, "up"); err != nil {
		return index, true, fmt.Errorf("activate GRE interface: %w", err)
	}
	return index, true, nil
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
