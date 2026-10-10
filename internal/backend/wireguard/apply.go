package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

func (b *Backend) Apply(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) (core.Rollback, error) {
	obs, ok := observed.(observation)
	if !ok {
		return nil, fmt.Errorf("unexpected WireGuard observation")
	}
	p, ok := candidate.(plan)
	if !ok {
		return nil, fmt.Errorf("unexpected WireGuard plan")
	}
	switch req.Operation {
	case core.OperationEnsure:
		return b.applyEnsure(ctx, req, obs, p)
	case core.OperationRemove:
		return b.applyRemove(ctx, req, p)
	default:
		return nil, fmt.Errorf("unsupported WireGuard operation")
	}
}

type creationProgress struct {
	IfIndex                           int
	Created, Marked                   bool
	ConfigAttempted, ConfigConfirmed  bool
	AddressAttempted, AddressAssigned bool
	UpAttempted, UpConfirmed          bool
}

func (b *Backend) applyEnsure(ctx context.Context, req core.Request, obs observation, p plan) (core.Rollback, error) {
	progress := creationProgress{}
	var firewallUndo func(context.Context) error
	rollback := func(undoCtx context.Context) error {
		var errs []error
		if firewallUndo != nil {
			errs = append(errs, firewallUndo(undoCtx))
		}
		if progress.Created {
			errs = append(errs, b.rollbackCreatedInterface(undoCtx, req.Link, p.name, progress))
		}
		return errors.Join(errs...)
	}
	if p.interfaceChange {
		if obs.Target.Exists {
			return rollback, fmt.Errorf("WireGuard configuration drift requires manual reconciliation")
		}
		var err error
		progress, err = b.createOwnedInterface(ctx, req.Link, p.name)
		if err != nil {
			return rollback, err
		}
	}
	if p.firewallChange {
		undo, _, err := b.firewall.EnsureInboundLocked(ctx, req.Link.ID, p.firewallRule)
		firewallUndo = undo
		if err != nil {
			return rollback, err
		}
	}
	return rollback, nil
}

func (b *Backend) applyRemove(ctx context.Context, req core.Request, p plan) (core.Rollback, error) {
	removedFirewall, removedInterface := false, false
	rollback := func(undoCtx context.Context) error {
		var errs []error
		if removedInterface {
			_, err := b.createOwnedInterface(undoCtx, req.Link, p.name)
			errs = append(errs, err)
		}
		if removedFirewall {
			_, _, err := b.firewall.EnsureInboundLocked(undoCtx, req.Link.ID, p.firewallRule)
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
	if p.firewallChange {
		removed, err := b.firewall.RemoveInboundLocked(ctx, req.Link.ID, p.firewallRule)
		removedFirewall = removed
		if err != nil {
			return rollback, err
		}
	}
	if p.interfaceChange {
		current, err := b.Inspect(ctx, req.Link)
		if err != nil {
			return rollback, err
		}
		state := current.(observation).Target
		if !state.matches(req.Link, p.name) || state.IfIndex <= 0 {
			return rollback, fmt.Errorf("WireGuard interface identity changed before removal")
		}
		if err := b.deleteLink(ctx, state.IfIndex); err != nil {
			return rollback, fmt.Errorf("cannot remove owned WireGuard interface: %w", err)
		}
		removedInterface = true
	}
	// Private credential is deliberately retained after interface deletion:
	// KeyStore retirement must be separately reconciled against durable state.
	return rollback, nil
}

func (b *Backend) createOwnedInterface(ctx context.Context, link domain.Link, name string) (creationProgress, error) {
	progress := creationProgress{}
	if _, err := b.runner.Run(ctx, b.ipBinary, "link", "add", name, "type", "wireguard"); err != nil {
		return progress, fmt.Errorf("cannot create WireGuard interface: %w", err)
	}
	progress.Created = true
	index, err := b.lookupIndex(name)
	if err != nil || index <= 0 {
		return progress, fmt.Errorf("cannot resolve created WireGuard ifindex")
	}
	progress.IfIndex = index
	if err := b.verifyCreation(ctx, link, name, progress); err != nil {
		return progress, err
	}
	alias, err := linux.OwnerTag(link.ID)
	if err != nil {
		return progress, err
	}
	if err := b.setAlias(ctx, index, alias); err != nil {
		return progress, fmt.Errorf("cannot mark WireGuard ownership: %w", err)
	}
	progress.Marked = true
	if err := b.verifyCreation(ctx, link, name, progress); err != nil {
		return progress, err
	}

	file, err := b.keys.OpenForWireGuard(link.ID, link.WireGuard.LocalPublicKey)
	if err != nil {
		return progress, fmt.Errorf("WireGuard credential not safely available: %w", err)
	}
	defer file.Close()
	// Exactly one inherited, already-validated 0600 credential descriptor.
	// The child's /proc/self/fd/3 has no filesystem pathname race or secret
	// bytes in argv, stdout, shell history or generic runtime state.
	args := []string{"set", name, "listen-port", strconv.Itoa(int(link.WireGuard.ListenPort)),
		"private-key", "/proc/self/fd/3", "peer", link.WireGuard.PeerPublicKey,
		"endpoint", endpoint(link), "allowed-ips", netip.PrefixFrom(link.Addresses.Peer.Addr(), 32).String(),
		"persistent-keepalive", strconv.Itoa(int(link.WireGuard.LocalKeepalive))}
	progress.ConfigAttempted = true
	if _, err := b.runner.RunWithFiles(ctx, b.wgBinary, []*os.File{file}, args...); err != nil {
		return progress, fmt.Errorf("cannot configure WireGuard public peer settings")
	}
	progress.ConfigConfirmed = true
	if err := b.verifyCreation(ctx, link, name, progress); err != nil {
		return progress, err
	}

	progress.AddressAttempted = true
	if err := b.addAddress(ctx, index, link.Addresses.Local); err != nil {
		return progress, fmt.Errorf("cannot assign WireGuard Link Address: %w", err)
	}
	progress.AddressAssigned = true
	if err := b.verifyCreation(ctx, link, name, progress); err != nil {
		return progress, err
	}
	progress.UpAttempted = true
	if err := b.setUp(ctx, index); err != nil {
		return progress, fmt.Errorf("cannot activate WireGuard interface: %w", err)
	}
	progress.UpConfirmed = true
	if err := b.verifyCreation(ctx, link, name, progress); err != nil {
		return progress, err
	}
	return progress, nil
}

func (b *Backend) verifyCreation(ctx context.Context, link domain.Link, name string, progress creationProgress) error {
	current, err := b.Inspect(ctx, link)
	if err != nil {
		return err
	}
	state := current.(observation).Target
	if !createdStateMatches(state, link, name, progress) {
		return fmt.Errorf("created WireGuard interface identity/configuration changed; preserving state")
	}
	return nil
}

func createdStateMatches(state observedLink, link domain.Link, name string, p creationProgress) bool {
	if !state.Exists || state.Name != name || state.IfIndex != p.IfIndex {
		return false
	}
	alias := ""
	owner := domain.LinkID("")
	if p.Marked {
		alias, _ = linux.OwnerTag(link.ID)
		owner = link.ID
	}
	if state.Alias != alias || state.Owner != owner {
		return false
	}
	if !p.ConfigAttempted {
		if !state.emptyConfig() {
			return false
		}
	} else if p.ConfigConfirmed {
		if !state.configuredFor(link) {
			return false
		}
		// Before the interface is activated, verify the configured peer
		// endpoint as well. Later authenticated roaming is not drift.
		if !p.UpAttempted && state.Endpoint != endpoint(link) {
			return false
		}
	} else {
		// wg set may have applied only a prefix before reporting failure.
		// Never destroy state whose complete owned delta cannot be proven.
		return false
	}
	if !p.AddressAttempted || !p.AddressAssigned {
		if len(state.IPv4Addresses) != 0 {
			return false
		}
	} else if len(state.IPv4Addresses) != 1 || state.IPv4Addresses[0] != link.Addresses.Local {
		return false
	}
	switch {
	case !p.UpAttempted:
		return !state.Up
	case p.UpConfirmed:
		return state.Up
	default:
		return !state.Up
	}
}

func (b *Backend) rollbackCreatedInterface(ctx context.Context, link domain.Link, name string, p creationProgress) error {
	if p.IfIndex <= 0 {
		// A name alone is not proof: the newly allocated kernel identity was
		// never captured, so do not delete a possible replacement.
		return fmt.Errorf("created WireGuard ifindex unknown; reconcile interface before retry")
	}
	current, err := b.Inspect(ctx, link)
	if err != nil {
		return err
	}
	obs := current.(observation)
	if !obs.Target.Exists {
		for _, other := range obs.Links {
			if other.IfIndex == p.IfIndex {
				return fmt.Errorf("WireGuard ifindex was reused; preserving foreign interface")
			}
		}
		return nil
	}
	if !createdStateMatches(obs.Target, link, name, p) {
		return fmt.Errorf("WireGuard state changed before rollback; preserving interface")
	}
	return b.deleteLink(ctx, p.IfIndex)
}
