package l2tpv3

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

func (b *Backend) command(ctx context.Context, args ...string) error {
	_, err := b.runner.Run(ctx, b.ip, args...)
	if err != nil {
		return fmt.Errorf("L2TPv3 kernel operation %q failed: %w", args[1:], err)
	}
	return nil
}

type progress struct {
	tunnelAttempted, tunnelCreated     bool
	sessionAttempted, sessionCreated   bool
	ifindex                            int
	macAttempted, macWritten           bool
	aliasAttempted, aliasWritten       bool
	addressAttempted, addressWritten   bool
	upAttempted, upWritten             bool
	neighborAttempted, neighborWritten bool
}

func (b *Backend) addTunnel(ctx context.Context, l domain.Link, id identity) error {
	return b.command(ctx, "l2tp", "add", "tunnel",
		"tunnel_id", strconv.FormatUint(uint64(id.tunnel), 10),
		"peer_tunnel_id", strconv.FormatUint(uint64(id.peerTunnel), 10),
		"encap", "ip", "local", l.Underlay.Local.String(), "remote", l.Underlay.Peer.String())
}
func (b *Backend) addSession(ctx context.Context, id identity) error {
	return b.command(ctx, "l2tp", "add", "session",
		"name", id.name, "tunnel_id", strconv.FormatUint(uint64(id.tunnel), 10),
		"session_id", strconv.FormatUint(uint64(id.session), 10),
		"peer_session_id", strconv.FormatUint(uint64(id.peerSession), 10))
}
func (b *Backend) deleteSession(ctx context.Context, id identity) error {
	return b.command(ctx, "l2tp", "del", "session",
		"tunnel_id", strconv.FormatUint(uint64(id.tunnel), 10),
		"session_id", strconv.FormatUint(uint64(id.session), 10))
}
func (b *Backend) deleteTunnel(ctx context.Context, id identity) error {
	return b.command(ctx, "l2tp", "del", "tunnel", "tunnel_id", strconv.FormatUint(uint64(id.tunnel), 10))
}
func (b *Backend) setPermanentNeighbor(ctx context.Context, l domain.Link, id identity, index int) error {
	if err := b.addNeighbor(ctx, index, l.Addresses.Peer.Addr(), id.peerMAC); err != nil {
		return fmt.Errorf("exclusive ifindex-bound L2TPv3 peer neighbor create: %w", err)
	}
	return nil
}

// Re-read both the L2TP generic-netlink objects AND the Ethernet device after
// creation. An untrusted interface name or a matching tunnel ID alone cannot
// authorize any subsequent mutation of a replaced device.
func (b *Backend) createdState(ctx context.Context, l domain.Link, p progress) (observation, error) {
	raw, err := b.Inspect(ctx, l)
	if err != nil {
		return observation{}, err
	}
	o := raw.(observation)
	if !o.tunnelMatches(l) || p.sessionCreated && !o.sessionMatches() {
		return observation{}, fmt.Errorf("created L2TPv3 tunnel/session identity changed; preserving host state")
	}
	if p.sessionCreated {
		if o.foreignAddress {
			return observation{}, fmt.Errorf("created L2TPv3 interface contains a foreign IPv6/unknown address")
		}
		if o.iface == nil || o.iface.IfIndex <= 0 || p.ifindex != 0 && o.iface.IfIndex != p.ifindex {
			return observation{}, fmt.Errorf("created L2TPv3 Ethernet interface identity changed")
		}
		if p.macWritten && o.iface.Address != o.id.mac {
			return observation{}, fmt.Errorf("created L2TPv3 MAC changed unexpectedly")
		}
		if p.aliasWritten {
			tag, err := linux.OwnerTag(l.ID)
			if err != nil || o.iface.IfAlias != tag {
				return observation{}, fmt.Errorf("created L2TPv3 interface owner tag changed")
			}
		} else if o.iface.IfAlias != "" {
			return observation{}, fmt.Errorf("created L2TPv3 interface unexpectedly gained an owner tag")
		}
		if p.addressWritten && (len(o.addresses) != 1 || o.addresses[0] != l.Addresses.Local) {
			return observation{}, fmt.Errorf("created L2TPv3 Link Address changed")
		}
		if !p.addressWritten && len(o.addresses) != 0 {
			return observation{}, fmt.Errorf("unexpected address appeared during L2TPv3 creation")
		}
		if p.upWritten && !slicesUp(o.iface.Flags) {
			return observation{}, fmt.Errorf("created L2TPv3 link went down")
		}
		if p.neighborWritten && !onlyManagedNeighbor(o, l) {
			return observation{}, fmt.Errorf("L2TPv3 permanent neighbor changed during creation")
		}
	}
	return o, nil
}
func slicesUp(flags []string) bool {
	for _, f := range flags {
		if f == "UP" {
			return true
		}
	}
	return false
}
func correctNeighbor(o observation, l domain.Link) bool {
	for _, n := range o.neighbors {
		if n.Dst == l.Addresses.Peer.Addr().String() {
			return strings.EqualFold(n.LLAddr, o.id.peerMAC) && neighborPermanent(n)
		}
	}
	return false
}

// A session deletion destroys every neighbor attached to its Ethernet
// interface. A second neighbor could belong to another program or operator:
// refuse destructive Remove/rollback instead of silently deleting it.
func onlyManagedNeighbor(o observation, l domain.Link) bool {
	return len(o.neighbors) == 1 && correctNeighbor(o, l)
}
func (b *Backend) createKernel(ctx context.Context, l domain.Link, id identity, existingTunnel bool) (p progress, err error) {
	if !existingTunnel {
		p.tunnelAttempted = true
		if err = b.addTunnel(ctx, l, id); err != nil {
			return p, err
		}
		p.tunnelCreated = true
	}
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	p.sessionAttempted = true
	if err = b.addSession(ctx, id); err != nil {
		return p, err
	}
	p.sessionCreated = true
	o, e := b.createdState(ctx, l, p)
	if e != nil {
		return p, e
	}
	p.ifindex = o.iface.IfIndex
	p.macAttempted = true
	if err = b.setMAC(ctx, p.ifindex, id.mac); err != nil {
		return p, fmt.Errorf("L2TPv3 MAC set not verified: %w", err)
	}
	p.macWritten = true
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	tag, err := linux.OwnerTag(l.ID)
	if err != nil {
		return p, err
	}
	p.aliasAttempted = true
	if err = b.setAlias(ctx, p.ifindex, tag); err != nil {
		return p, err
	}
	p.aliasWritten = true
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	p.addressAttempted = true
	if err = b.addAddress(ctx, p.ifindex, l.Addresses.Local); err != nil {
		return p, err
	}
	p.addressWritten = true
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	p.upAttempted = true
	if err = b.setUp(ctx, p.ifindex); err != nil {
		return p, err
	}
	p.upWritten = true
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	p.neighborAttempted = true
	if err = b.setPermanentNeighbor(ctx, l, id, p.ifindex); err != nil {
		return p, err
	}
	p.neighborWritten = true
	o, err = b.createdState(ctx, l, p)
	if err != nil {
		return p, err
	}
	if !o.matches(l) {
		return p, fmt.Errorf("created L2TPv3 pseudowire is not in complete owned operational state")
	}
	return p, nil
}

// Indeterminate effects must never be reported as a completed rollback.
// In particular, an iproute2 process can apply its netlink mutation before
// an error or timeout reaches Go.
func uncertainKernelEffect(reason string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%s: %w", reason, errors.Join(cause, core.ErrIndeterminateHostEffect))
	}
	return fmt.Errorf("%s: %w", reason, core.ErrIndeterminateHostEffect)
}

// An unrelated tunnel may own the same globally indexed session identity.
// Exact vacancy cannot be asserted from the absence of only OUR interface.
func kernelIdentityVacant(o observation) bool {
	if o.present() {
		return false
	}
	for _, s := range o.sessions {
		if s.SessionID == o.id.session || s.TunnelID == o.id.tunnel {
			return false
		}
	}
	return true
}

func (b *Backend) undoCreated(ctx context.Context, l domain.Link, p progress) error {
	if !p.tunnelAttempted && !p.sessionAttempted {
		return nil
	}
	raw, err := b.Inspect(ctx, l)
	if err != nil {
		return uncertainKernelEffect("cannot re-observe L2TPv3 creation result", err)
	}
	o := raw.(observation)

	// The add-tunnel command may have created a kernel tunnel and then
	// returned an error. There is NO owner alias before add-session:
	// preserve any observed object, even if its numeric ID is familiar.
	if p.tunnelAttempted && !p.tunnelCreated {
		if !kernelIdentityVacant(o) {
			return uncertainKernelEffect("uncommitted L2TPv3 tunnel may exist after failed add; inspect ip l2tp before manual reconciliation", nil)
		}
		return nil // Bounded fresh observation proves the attempted effect absent.
	}
	if !o.tunnelMatches(l) {
		if kernelIdentityVacant(o) {
			return nil
		}
		return uncertainKernelEffect("L2TPv3 tunnel identity changed during rollback; preserving kernel state", nil)
	}
	if p.sessionAttempted && !p.sessionCreated && (o.session != nil || o.iface != nil) {
		// If add-session errored AFTER the kernel created it, no successful
		// ifindex/owner-tag receipt exists. Never delete/adopt this object.
		return uncertainKernelEffect("L2TPv3 session may exist after failed add without a confirmed owner tag", nil)
	}
	if p.sessionCreated {
		if p.ifindex == 0 || !o.sessionMatches() || o.iface == nil ||
			o.iface.IfIndex != p.ifindex || o.foreignAddress {
			return uncertainKernelEffect("cannot undo L2TPv3 session: interface/index or address ownership changed", nil)
		}
		if p.addressAttempted && !p.addressWritten && len(o.addresses) != 0 ||
			p.addressWritten && (len(o.addresses) != 1 || o.addresses[0] != l.Addresses.Local) ||
			!p.addressAttempted && len(o.addresses) != 0 {
			return uncertainKernelEffect("L2TPv3 address effect or foreign address cannot be safely attributed", nil)
		}
		if p.neighborAttempted && !p.neighborWritten && len(o.neighbors) != 0 ||
			p.neighborWritten && !onlyManagedNeighbor(o, l) ||
			!p.neighborAttempted && len(o.neighbors) != 0 {
			return uncertainKernelEffect("L2TPv3 neighbor effect or foreign neighbor cannot be safely attributed", nil)
		}
		wantAlias := ""
		if p.aliasWritten {
			wantAlias, err = linux.OwnerTag(l.ID)
			if err != nil {
				return err
			}
		}
		if o.iface.IfAlias != wantAlias {
			return uncertainKernelEffect("L2TPv3 alias/owner changed during rollback", nil)
		}
		if p.macWritten && !strings.EqualFold(o.iface.Address, pExpectedMAC(l)) {
			return uncertainKernelEffect("L2TPv3 device MAC changed during rollback", nil)
		}
		if p.macAttempted && !p.macWritten && strings.EqualFold(o.iface.Address, pExpectedMAC(l)) ||
			p.upAttempted && !p.upWritten && slicesUp(o.iface.Flags) {
			return uncertainKernelEffect("L2TPv3 partially applied device mutation is unverified", nil)
		}
		// The netlink command can succeed at deleting and still return error.
		// Re-observe the exact tunnel/session pair before declaring failure.
		if err := b.deleteSession(ctx, o.id); err != nil {
			fresh, observeErr := b.Inspect(ctx, l)
			if observeErr != nil {
				return uncertainKernelEffect("cannot verify delete-session after error", errors.Join(err, observeErr))
			}
			now := fresh.(observation)
			if !now.tunnelMatches(l) || now.session != nil || now.iface != nil {
				return uncertainKernelEffect("delete-session outcome was not confirmed absent", err)
			}
		}
	}
	if p.tunnelCreated {
		fresh, err := b.Inspect(ctx, l)
		if err != nil {
			return uncertainKernelEffect("cannot inspect L2TPv3 tunnel before deletion", err)
		}
		now := fresh.(observation)
		if kernelIdentityVacant(now) {
			return nil
		}
		if !now.tunnelMatches(l) || now.session != nil || now.iface != nil {
			return uncertainKernelEffect("cannot undo L2TPv3 tunnel: unexpected kernel resource", nil)
		}
		for _, other := range now.sessions {
			if other.TunnelID == now.id.tunnel || other.SessionID == now.id.session {
				return uncertainKernelEffect("L2TPv3 tunnel/session ID has a foreign occupant; preserve", nil)
			}
		}
		if err := b.deleteTunnel(ctx, now.id); err != nil {
			check, inspectErr := b.Inspect(ctx, l)
			if inspectErr != nil || !kernelIdentityVacant(check.(observation)) {
				if inspectErr != nil {
					return uncertainKernelEffect("cannot establish vacancy after delete-tunnel error", errors.Join(err, inspectErr))
				}
				return uncertainKernelEffect("delete-tunnel outcome was not confirmed absent", err)
			}
		}
	}
	return nil
}
func pExpectedMAC(l domain.Link) string { id, _ := identityFor(l); return id.mac }

func (b *Backend) Apply(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) (core.Rollback, error) {
	o, ok := observed.(observation)
	if !ok {
		return nil, fmt.Errorf("unexpected L2TPv3 observation")
	}
	p, ok := candidate.(plan)
	if !ok {
		return nil, fmt.Errorf("unexpected L2TPv3 plan")
	}
	switch req.Operation {
	case core.OperationEnsure:
		return b.applyEnsure(ctx, req, o, p)
	case core.OperationRemove:
		return b.applyRemove(ctx, req, o, p)
	default:
		return nil, fmt.Errorf("unsupported L2TPv3 operation")
	}
}
func (b *Backend) applyEnsure(ctx context.Context, req core.Request, o observation, p plan) (core.Rollback, error) {
	var progress progress
	var fwUndo func(context.Context) error
	undo := func(undoCtx context.Context) error {
		var errs []error
		if fwUndo != nil {
			errs = append(errs, fwUndo(undoCtx))
		}
		if progress.tunnelAttempted || progress.sessionAttempted {
			errs = append(errs, b.undoCreated(undoCtx, req.Link, progress))
		}
		return errors.Join(errs...)
	}
	if p.create {
		if o.present() {
			return undo, fmt.Errorf("L2TPv3 cannot recreate occupied or altered state")
		}
		var err error
		progress, err = b.createKernel(ctx, req.Link, p.id, false)
		if err != nil {
			return undo, err
		}
	}
	if p.firewallChange {
		cb, _, err := b.firewall.EnsureInboundLocked(ctx, req.Link.ID, p.firewallRule)
		if err != nil {
			return undo, err
		}
		fwUndo = cb
	}
	return undo, nil
}

// A fresh session ID ownership check is essential because a foreign session
// may be inserted into a tunnel after Engine's earlier Validate/Plan snapshot.
func noForeignL2TPSessions(o observation) bool {
	for _, candidate := range o.sessions {
		if candidate.TunnelID == o.id.tunnel {
			if !o.sessionMatches() || candidate.SessionID != o.id.session {
				return false
			}
		} else if candidate.SessionID == o.id.session {
			return false
		}
	}
	return true
}

// A committed Remove can fail after either iproute2 delete has already
// effected the kernel. Restore only a positively identified prior Link or
// an independently verified empty slot; do not adopt someone else's object.
func (b *Backend) restoreAfterRemove(ctx context.Context, link domain.Link, id identity) error {
	raw, err := b.Inspect(ctx, link)
	if err != nil {
		return uncertainKernelEffect("cannot inspect L2TPv3 after attempted Remove", err)
	}
	o := raw.(observation)
	if !noForeignL2TPSessions(o) {
		return uncertainKernelEffect("foreign session appeared while reconciling failed L2TPv3 Remove", nil)
	}
	switch {
	case o.matches(link) && onlyManagedNeighbor(o, link):
		// The delete returned an error before affecting kernel state, or
		// a previous compensation already reconstructed the exact Link.
	case kernelIdentityVacant(o):
		if _, err = b.createKernel(ctx, link, id, false); err != nil {
			return uncertainKernelEffect("L2TPv3 full recreation after Remove was not verified", err)
		}
	case o.tunnelMatches(link) && o.session == nil && o.iface == nil:
		if _, err = b.createKernel(ctx, link, id, true); err != nil {
			return uncertainKernelEffect("L2TPv3 session recreation after Remove was not verified", err)
		}
	default:
		return uncertainKernelEffect("L2TPv3 Remove left ambiguous or foreign kernel state; preserve", nil)
	}
	restored, err := b.Inspect(ctx, link)
	if err != nil || !restored.(observation).matches(link) || !onlyManagedNeighbor(restored.(observation), link) ||
		!noForeignL2TPSessions(restored.(observation)) {
		return uncertainKernelEffect("L2TPv3 Remove compensation has no exact owner verification", err)
	}
	return nil
}

func (b *Backend) applyRemove(ctx context.Context, req core.Request, _ observation, p plan) (core.Rollback, error) {
	firewallRemoved := false
	sessionDeleteAttempted := false
	tunnelDeleteAttempted := false
	undo := func(undoCtx context.Context) error {
		var errs []error
		if sessionDeleteAttempted || tunnelDeleteAttempted {
			errs = append(errs, b.restoreAfterRemove(undoCtx, req.Link, p.id))
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
			return undo, err
		}
		firewallRemoved = removed
	}
	if p.remove {
		raw, err := b.Inspect(ctx, req.Link)
		if err != nil {
			return undo, err
		}
		current := raw.(observation)
		// Validate ran earlier under the Engine lock; the kernel, unlike
		// STL's State, can also be changed by unrelated host actors.
		// Recheck complete address+neighbor and session ownership NOW.
		if !current.matches(req.Link) || !current.interfaceOwned(req.Link) ||
			!onlyManagedNeighbor(current, req.Link) || !noForeignL2TPSessions(current) {
			return undo, fmt.Errorf("L2TPv3 delete requires exact current session, address, neighbor and interface ownership")
		}
		sessionDeleteAttempted = true
		if err = b.deleteSession(ctx, p.id); err != nil {
			// It may already be gone: rollback must inspect and restore.
			return undo, err
		}
		raw, err = b.Inspect(ctx, req.Link)
		if err != nil {
			return undo, err
		}
		current = raw.(observation)
		if !current.tunnelMatches(req.Link) || current.session != nil || current.iface != nil ||
			!noForeignL2TPSessions(current) {
			return undo, uncertainKernelEffect("L2TPv3 session deletion did not release only the owned resources", nil)
		}
		tunnelDeleteAttempted = true
		if err = b.deleteTunnel(ctx, p.id); err != nil {
			return undo, err
		}
	}
	return undo, nil
}
