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
	tunnelCreated   bool
	sessionCreated  bool
	ifindex         int
	macWritten      bool
	aliasWritten    bool
	addressWritten  bool
	upWritten       bool
	neighborWritten bool
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
func (b *Backend) setPermanentNeighbor(ctx context.Context, l domain.Link, id identity) error {
	return b.command(ctx, "neigh", "replace", l.Addresses.Peer.Addr().String(),
		"lladdr", id.peerMAC, "nud", "permanent", "dev", id.name)
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
		if p.neighborWritten && !correctNeighbor(o, l) {
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
		if err = b.addTunnel(ctx, l, id); err != nil {
			return p, err
		}
		p.tunnelCreated = true
	}
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	if err = b.addSession(ctx, id); err != nil {
		return p, err
	}
	p.sessionCreated = true
	o, e := b.createdState(ctx, l, p)
	if e != nil {
		return p, e
	}
	p.ifindex = o.iface.IfIndex
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
	if err = b.setAlias(ctx, p.ifindex, tag); err != nil {
		return p, err
	}
	p.aliasWritten = true
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	if err = b.addAddress(ctx, p.ifindex, l.Addresses.Local); err != nil {
		return p, err
	}
	p.addressWritten = true
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	if err = b.setUp(ctx, p.ifindex); err != nil {
		return p, err
	}
	p.upWritten = true
	if _, err = b.createdState(ctx, l, p); err != nil {
		return p, err
	}
	if err = b.setPermanentNeighbor(ctx, l, id); err != nil {
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
func (b *Backend) undoCreated(ctx context.Context, l domain.Link, p progress) error {
	if !p.tunnelCreated && !p.sessionCreated {
		return nil
	}
	raw, err := b.Inspect(ctx, l)
	if err != nil {
		return err
	}
	o := raw.(observation)
	if !o.tunnelMatches(l) {
		return fmt.Errorf("cannot undo L2TPv3 tunnel: creation identity no longer matches")
	}
	if p.sessionCreated {
		if p.ifindex == 0 {
			return fmt.Errorf("cannot undo unindexed L2TPv3 session: preserve for manual reconciliation")
		}
		if !o.sessionMatches() || o.iface == nil || o.iface.IfIndex != p.ifindex {
			return fmt.Errorf("cannot undo L2TPv3 session: kernel identity changed")
		}
		// A destructive rollback must not erase someone else's additional
		// addresses/neighboring state, even on a familiar interface.
		if p.addressWritten && (len(o.addresses) != 1 || o.addresses[0] != l.Addresses.Local) ||
			!p.addressWritten && len(o.addresses) != 0 {
			return fmt.Errorf("cannot undo L2TPv3 session: address state has changed")
		}
		if p.neighborWritten && !onlyManagedNeighbor(o, l) || !p.neighborWritten && len(o.neighbors) != 0 {
			return fmt.Errorf("cannot undo L2TPv3 session: neighbor state changed")
		}
		wantAlias := ""
		if p.aliasWritten {
			wantAlias, err = linux.OwnerTag(l.ID)
			if err != nil {
				return err
			}
		}
		if o.iface.IfAlias != wantAlias {
			return fmt.Errorf("cannot undo L2TPv3 session: alias/owner changed")
		}
		if p.macWritten && o.iface.Address != pExpectedMAC(l) {
			return fmt.Errorf("cannot undo L2TPv3 session: MAC changed")
		}
		if err = b.deleteSession(ctx, o.id); err != nil {
			return err
		}
	}
	if p.tunnelCreated {
		fresh, err := b.Inspect(ctx, l)
		if err != nil {
			return err
		}
		now := fresh.(observation)
		if !now.tunnelMatches(l) || now.session != nil || now.iface != nil {
			return fmt.Errorf("cannot undo L2TPv3 tunnel: unexpected remaining device/session")
		}
		// Preserve a tunnel that gained a foreign session, even with a familiar
		// tunnel ID, rather than deleting another application's attached object.
		for _, s := range now.sessions {
			if s.TunnelID == now.id.tunnel {
				return fmt.Errorf("L2TPv3 tunnel has an unexpected session; preserving")
			}
		}
		return b.deleteTunnel(ctx, now.id)
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
		if progress.tunnelCreated || progress.sessionCreated {
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
func (b *Backend) applyRemove(ctx context.Context, req core.Request, _ observation, p plan) (core.Rollback, error) {
	removedFirewall := false
	removedSession := false
	removedTunnel := false
	undo := func(undoCtx context.Context) error {
		var errs []error
		if removedTunnel {
			raw, err := b.Inspect(undoCtx, req.Link)
			if err != nil {
				errs = append(errs, err)
			} else if raw.(observation).present() {
				errs = append(errs, fmt.Errorf("cannot recreate removed L2TPv3: kernel identity is not vacant"))
			} else {
				_, err = b.createKernel(undoCtx, req.Link, p.id, false)
				errs = append(errs, err)
			}
		} else if removedSession {
			raw, err := b.Inspect(undoCtx, req.Link)
			if err != nil {
				errs = append(errs, err)
			} else if !raw.(observation).tunnelMatches(req.Link) || raw.(observation).session != nil || raw.(observation).iface != nil {
				errs = append(errs, fmt.Errorf("cannot restore L2TPv3 session: existing tunnel state is inconsistent"))
			} else {
				_, err = b.createKernel(undoCtx, req.Link, p.id, true)
				errs = append(errs, err)
			}
		}
		if removedFirewall {
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
		removedFirewall = removed
	}
	if p.remove {
		raw, err := b.Inspect(ctx, req.Link)
		if err != nil {
			return undo, err
		}
		current := raw.(observation)
		if !current.matches(req.Link) || !current.interfaceOwned(req.Link) {
			return undo, fmt.Errorf("L2TPv3 delete requires exact current interface and kernel ownership")
		}
		if err = b.deleteSession(ctx, p.id); err != nil {
			return undo, err
		}
		removedSession = true
		raw, err = b.Inspect(ctx, req.Link)
		if err != nil {
			return undo, err
		}
		current = raw.(observation)
		if !current.tunnelMatches(req.Link) || current.session != nil || current.iface != nil {
			return undo, fmt.Errorf("L2TPv3 session deletion did not release expected resources")
		}
		for _, s := range current.sessions {
			if s.TunnelID == p.id.tunnel {
				return undo, fmt.Errorf("L2TPv3 tunnel gained unexpected session; preserve")
			}
		}
		if err = b.deleteTunnel(ctx, p.id); err != nil {
			return undo, err
		}
		removedTunnel = true
	}
	return undo, nil
}
