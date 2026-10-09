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

type creationProgress struct {
	IfIndex          int
	Created          bool
	OwnershipMarked  bool
	AddressAttempted bool
	AddressAssigned  bool
	UpAttempted      bool
	UpConfirmed      bool
}

func (b *Backend) applyEnsure(ctx context.Context, req core.Request, obs observation, p plan) (core.Rollback, error) {
	progress := creationProgress{}
	fouCreated := false
	var firewallUndo func(context.Context) error
	rollback := func(undoCtx context.Context) error {
		var errs []error
		if firewallUndo != nil {
			errs = append(errs, firewallUndo(undoCtx))
		}
		if progress.Created {
			errs = append(errs, b.rollbackCreatedInterface(undoCtx, req.Link, p.name, progress))
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
		var err error
		progress, err = b.createOwnedInterface(ctx, req.Link, p.name)
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
			_, err := b.createOwnedInterface(undoCtx, req.Link, p.name)
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

func (b *Backend) createOwnedInterface(ctx context.Context, link domain.Link, name string) (creationProgress, error) {
	progress := creationProgress{}
	args := []string{"link", "add", name}
	args = append(args, greTypeArgs(link)...)
	if _, err := b.runner.Run(ctx, b.ipBinary, args...); err != nil {
		return progress, fmt.Errorf("create GRE interface: %w", err)
	}
	progress.Created = true

	// The successful exclusive name add proves that this operation created an
	// interface at that instant. From here onward we capture and use its kernel
	// ifindex, and revalidate identity/configuration plus the creation stage
	// before every later mutation and any destructive rollback.
	index, err := b.lookupIndex(name)
	if err != nil || index <= 0 {
		return progress, fmt.Errorf("resolve created GRE interface identity: %w", err)
	}
	progress.IfIndex = index
	state, err := b.verifyCreatedInterface(ctx, link, name, index, "")
	if err != nil {
		return progress, err
	}
	if !rollbackStateMatchesCreationProgress(state, link, name, progress) {
		return progress, fmt.Errorf("created GRE interface gained unexpected state before ownership marking; preserving current host state")
	}

	owner, err := linux.OwnerTag(link.ID)
	if err != nil {
		return progress, err
	}
	if err := b.setAlias(ctx, index, owner); err != nil {
		return progress, fmt.Errorf("mark GRE interface ownership: %w", err)
	}
	progress.OwnershipMarked = true
	state, err = b.verifyCreatedInterface(ctx, link, name, index, link.ID)
	if err != nil {
		return progress, err
	}
	if !rollbackStateMatchesCreationProgress(state, link, name, progress) {
		return progress, fmt.Errorf("created GRE interface gained unexpected state before address assignment; preserving current host state")
	}

	progress.AddressAttempted = true
	if err := b.addAddress(ctx, index, link.Addresses.Local); err != nil {
		return progress, fmt.Errorf("assign GRE Link Address: %w", err)
	}
	progress.AddressAssigned = true
	state, err = b.verifyCreatedInterface(ctx, link, name, index, link.ID)
	if err != nil {
		return progress, err
	}
	if !rollbackStateMatchesCreationProgress(state, link, name, progress) {
		return progress, fmt.Errorf("verify GRE Link Address: created interface address state changed or is ambiguous")
	}

	progress.UpAttempted = true
	if err := b.setUp(ctx, index); err != nil {
		return progress, fmt.Errorf("activate GRE interface: %w", err)
	}
	progress.UpConfirmed = true
	state, err = b.verifyCreatedInterface(ctx, link, name, index, link.ID)
	if err != nil {
		return progress, err
	}
	if !state.matches(link, name) || !rollbackStateMatchesCreationProgress(state, link, name, progress) {
		return progress, fmt.Errorf("verify activated GRE interface: final state changed or is incomplete")
	}
	return progress, nil
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

func rollbackStateMatchesCreationProgress(state observedLink, link domain.Link, name string, progress creationProgress) bool {
	if !state.Exists || state.Name != name || state.IfIndex != progress.IfIndex || !state.matchesConfigurationBeforeOwnership(link, name) {
		return false
	}
	expectedOwner := domain.LinkID("")
	if progress.OwnershipMarked {
		expectedOwner = link.ID
	}
	if state.Owner != expectedOwner {
		return false
	}

	switch {
	case !progress.AddressAttempted:
		if len(state.IPv4Addresses) != 0 {
			return false
		}
	case progress.AddressAssigned:
		if len(state.IPv4Addresses) != 1 || state.IPv4Addresses[0] != link.Addresses.Local {
			return false
		}
	default:
		// An address mutation that returned an error may still be ambiguous.
		// Only the pre-attempt state or the exact intended address is
		// attributable to this operation; any other/additional address is not.
		if len(state.IPv4Addresses) > 1 ||
			(len(state.IPv4Addresses) == 1 && state.IPv4Addresses[0] != link.Addresses.Local) {
			return false
		}
	}

	switch {
	case !progress.UpAttempted:
		return !state.Up
	case progress.UpConfirmed:
		return state.Up
	default:
		// A failed/ambiguous up mutation can legitimately leave either state.
		return true
	}
}

func (b *Backend) rollbackCreatedInterface(ctx context.Context, link domain.Link, name string, progress creationProgress) error {
	if progress.IfIndex <= 0 {
		return b.preserveUnindexedCreatedInterface(ctx, link, name)
	}
	fresh, err := b.Inspect(ctx, link)
	if err != nil {
		return fmt.Errorf("inspect GRE interface before rollback: %w", err)
	}
	obs := fresh.(observation)
	state := obs.Target
	if !state.Exists {
		for _, candidate := range obs.Links {
			if candidate.IfIndex == progress.IfIndex {
				return fmt.Errorf("created GRE ifindex now identifies different state; preserving current host state")
			}
		}
		return nil
	}
	if !rollbackStateMatchesCreationProgress(state, link, name, progress) {
		return fmt.Errorf("created GRE interface state changed before rollback; preserving current host state")
	}
	if err := b.deleteLink(ctx, progress.IfIndex); err != nil {
		return fmt.Errorf("delete created GRE interface during rollback: %w", err)
	}
	return nil
}

func (b *Backend) preserveUnindexedCreatedInterface(ctx context.Context, link domain.Link, name string) error {
	fresh, err := b.Inspect(ctx, link)
	if err != nil {
		return fmt.Errorf("inspect unindexed GRE interface for rollback: %w", err)
	}
	state := fresh.(observation).Target
	if !state.Exists {
		return nil
	}
	return fmt.Errorf("created GRE interface identity was never captured; preserving current host state for explicit reconciliation")
}
