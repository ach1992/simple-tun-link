package quicguard

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Managed is the fixed production nft adapter used by the canonical managed
// QUIC backend. It never reads or promotes source-only original receipts.
type Managed struct {
	root         string
	store        state.Store
	runner       linux.BoundedRunner
	apply        func(context.Context, string) error
	kernelBootID func() (string, error)
}
type managedScopeKey struct{}
type managedScope struct {
	link     domain.Link
	prior    state.QUICGeneration
	boot, ns string
	created  bool
	handles  linux.WGIngressLiveHandles
}

func NewManaged(root string, store state.Store) (*Managed, error) {
	if store == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, fmt.Errorf("canonical QUIC guard root and Store required")
	}
	provider, ok := store.(interface{ RootDir() string })
	if !ok || provider.RootDir() != root {
		return nil, fmt.Errorf("QUIC guard Store root differs")
	}
	return &Managed{root: root, store: store, runner: linux.ExecRunner{}, apply: runOriginalNFTCreate, kernelBootID: hostidentity.CurrentKernelBootID}, nil
}

func (m *Managed) Begin(ctx context.Context, link domain.Link, prior *state.QUICGeneration) (context.Context, error) {
	if ctx == nil || link.Backend != domain.BackendWireGuardQUIC || link.Validate() != nil {
		return nil, fmt.Errorf("invalid managed QUIC guard scope")
	}
	boot, err := m.kernelBootID()
	if err != nil {
		return nil, err
	}
	ns, err := currentNetworkNamespace()
	if err != nil {
		return nil, err
	}
	s := &managedScope{link: link, boot: boot, ns: ns}
	snapshot, err := m.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	record, present := snapshot.Find(link.ID)
	if prior != nil {
		if err := prior.Validate(link); err != nil {
			return nil, err
		}
		bound, ok := core.QUICGenerationFromContext(ctx)
		if !present || record.Desired != link || record.QUICGeneration != *prior || !ok || bound != *prior {
			return nil, fmt.Errorf("managed QUIC guard original owner changed")
		}
		if prior.KernelBootID == boot && prior.NetworkNS != ns {
			return nil, fmt.Errorf("managed QUIC original network namespace changed")
		}
		s.prior = *prior
	} else if present {
		return nil, fmt.Errorf("managed QUIC guard cannot replace a committed owner")
	}
	return context.WithValue(ctx, managedScopeKey{}, s), nil
}

func (m *Managed) scope(ctx context.Context, link domain.Link) (*managedScope, error) {
	op, admitted := core.QUICManagedOperation(ctx)
	if !admitted || op.Managed.Intent != link {
		return nil, fmt.Errorf("managed QUIC guard requires durable operation")
	}
	snapshot, err := m.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	actual, found := snapshot.FindQUICCrashOperation(link.ID)
	if !found || !reflect.DeepEqual(actual, op) {
		return nil, fmt.Errorf("managed QUIC guard durable journal changed")
	}
	origin := op.Nonce
	if op.Managed.HadCommittedLink {
		origin = op.Managed.OriginalGeneration.OriginNonce
	}
	if core.QUICOrigin(ctx) != origin {
		return nil, fmt.Errorf("managed QUIC guard origin differs from journal")
	}
	s, err := m.retainedScope(ctx, link)
	if err != nil {
		return nil, err
	}
	if s.prior.Version != 0 && (s.prior.KernelBootID != s.boot) != core.HasQUICColdBootExtinctionWitness(ctx, link.ID) {
		return nil, fmt.Errorf("managed QUIC guard kernel transition proof differs")
	}
	return s, nil
}

func (m *Managed) retainedScope(ctx context.Context, link domain.Link) (*managedScope, error) {
	s, ok := ctx.Value(managedScopeKey{}).(*managedScope)
	if !ok || s.link != link {
		return nil, fmt.Errorf("managed QUIC guard requires canonical journal and retained scope")
	}
	boot, err := m.kernelBootID()
	if err != nil || boot != s.boot {
		return nil, fmt.Errorf("managed QUIC guard kernel generation changed")
	}
	ns, err := currentNetworkNamespace()
	if err != nil || ns != s.ns {
		return nil, fmt.Errorf("managed QUIC guard network namespace changed")
	}
	return s, nil
}

func (m *Managed) plan(ctx context.Context, link domain.Link) (linux.QUICWGIngressPlan, error) {
	return linux.NewQUICWGIngressPlan(link.ID, link.WireGuard.ListenPort, core.QUICOrigin(ctx))
}

func (m *Managed) GuardPresent(ctx context.Context, link domain.Link) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	p, err := m.plan(ctx, link)
	if err != nil {
		return false, err
	}
	present, handles, err := linux.ReadWGIngressGuardHandles(ctx, m.runner, p)
	if err != nil || !present {
		return present, err
	}
	if s, ok := ctx.Value(managedScopeKey{}).(*managedScope); ok && s.link == link && s.created {
		if s.handles != handles {
			return false, fmt.Errorf("new managed QUIC guard changed")
		}
		return true, nil
	}
	g, ok := core.QUICGenerationFromContext(ctx)
	if !ok || g.Validate(link) != nil {
		return false, fmt.Errorf("pre-existing QUIC guard lacks committed creation provenance")
	}
	boot, err := m.kernelBootID()
	if err != nil {
		return false, err
	}
	ns, err := currentNetworkNamespace()
	if err != nil {
		return false, err
	}
	if g.KernelBootID != boot || g.NetworkNS != ns || handles != (linux.WGIngressLiveHandles{Table: g.GuardTableHandle, Chain: g.GuardChainHandle, Rule: g.GuardRuleHandle}) {
		return false, fmt.Errorf("committed QUIC guard generation differs")
	}
	return true, nil
}

func (m *Managed) Preflight(ctx context.Context, link domain.Link, guardPresent bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	p, err := m.plan(ctx, link)
	if err != nil {
		return err
	}
	present, err := m.GuardPresent(ctx, link)
	if err != nil || present != guardPresent {
		return fmt.Errorf("managed QUIC guard observation changed")
	}
	snapshot, err := m.store.Load(ctx)
	if err != nil {
		return err
	}
	ws, qs, err := linux.VerifiedManagedWGIngressSiblings(ctx, m.runner, snapshot, link.ID)
	if err != nil {
		return err
	}
	if err := p.ProbeQUICWGFirewallCoexistenceWithVerifiedCurrent(ctx, m.runner, ws, qs, present); err != nil {
		return err
	}
	return ctx.Err()
}

func (m *Managed) EnsureGuard(ctx context.Context, link domain.Link) (core.Rollback, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s, err := m.scope(ctx, link)
	if err != nil {
		return nil, err
	}
	op, _ := core.QUICManagedOperation(ctx)
	if op.Managed.Operation != "ensure" {
		return nil, fmt.Errorf("managed QUIC guard creation requires Ensure journal")
	}
	present, err := m.GuardPresent(ctx, link)
	if err != nil {
		return nil, err
	}
	if present {
		return func(context.Context) error { return nil }, nil
	}
	if err := m.Preflight(ctx, link, false); err != nil {
		return nil, err
	}
	// A fresh original must establish vacancy immediately before creation.
	// A committed visible WG repair has already been checked in native
	// Validate, and may reinstall its missing protection under the journal.
	if s.prior == (state.QUICGeneration{}) || core.HasQUICColdBootExtinctionWitness(ctx, link.ID) {
		vacant, err := linux.WSSGlobalWGKernelVacant(ctx, m.runner, "wg", link.WireGuard.LocalPublicKey, link.WireGuard.ListenPort)
		if err != nil || !vacant {
			return nil, fmt.Errorf("QUIC original WG vacancy unverified before guard")
		}
		vacant, err = linux.QUICWGAllStateUDPPortVacant(ctx, m.runner, link.WireGuard.ListenPort)
		if err != nil || !vacant {
			return nil, fmt.Errorf("QUIC all-state UDP vacancy unverified before guard")
		}
	}
	p, err := m.plan(ctx, link)
	if err != nil {
		return nil, err
	}
	batch, err := p.NFTBatch()
	if err != nil {
		return nil, err
	}
	if err := m.apply(ctx, batch); err != nil {
		return nil, fmt.Errorf("%w: managed QUIC guard create outcome uncertain", core.ErrIndeterminateHostEffect)
	}
	present, handles, err := linux.ReadWGIngressGuardHandles(ctx, m.runner, p)
	if err != nil || !present {
		return nil, fmt.Errorf("%w: managed QUIC guard create readback unavailable", core.ErrIndeterminateHostEffect)
	}
	s.created, s.handles = true, handles
	if _, err := m.scope(ctx, link); err != nil {
		return nil, fmt.Errorf("%w: managed QUIC guard host identity changed", core.ErrIndeterminateHostEffect)
	}
	return func(c context.Context) error { _, err := m.RemoveGuard(c, link); return err }, nil
}

func (m *Managed) RemoveGuard(ctx context.Context, link domain.Link) (core.Rollback, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := m.scope(ctx, link); err != nil {
		return nil, err
	}
	if !core.HasQUICWGDeletionWitness(ctx, link.ID) {
		return nil, fmt.Errorf("original QUIC WG deletion proof required before guard removal")
	}
	present, err := m.GuardPresent(ctx, link)
	if err != nil {
		return nil, err
	}
	if !present {
		return func(context.Context) error { return nil }, nil
	}
	vacant, err := linux.WSSGlobalWGKernelVacant(ctx, m.runner, "wg", link.WireGuard.LocalPublicKey, link.WireGuard.ListenPort)
	if err != nil || !vacant {
		return nil, fmt.Errorf("QUIC WG identity or socket still occupied; retain guard")
	}
	vacant, err = linux.QUICWGAllStateUDPPortVacant(ctx, m.runner, link.WireGuard.ListenPort)
	if err != nil || !vacant {
		return nil, fmt.Errorf("QUIC all-state UDP vacancy unverified; retain guard")
	}
	p, err := m.plan(ctx, link)
	if err != nil {
		return nil, err
	}
	if err := m.apply(ctx, "delete table inet "+p.TableName()+"\n"); err != nil {
		return nil, fmt.Errorf("%w: QUIC guard deletion outcome uncertain", core.ErrIndeterminateHostEffect)
	}
	present, err = linux.InspectWGIngressGuard(ctx, m.runner, p)
	if err != nil || present {
		return nil, fmt.Errorf("%w: QUIC guard removal readback uncertain", core.ErrIndeterminateHostEffect)
	}
	if _, err := m.scope(ctx, link); err != nil {
		return nil, fmt.Errorf("%w: QUIC guard host changed after deletion", core.ErrIndeterminateHostEffect)
	}
	// The original identity has ended. Recreating an equal-shaped table is
	// not rollback of that identity and must not be reported as such.
	return func(context.Context) error {
		return fmt.Errorf("QUIC original guard removed; retain operation journal on commit failure")
	}, nil
}

func (m *Managed) Attest(ctx context.Context, link domain.Link) (linux.WGIngressLiveHandles, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := m.retainedScope(ctx, link); err != nil {
		return linux.WGIngressLiveHandles{}, err
	}
	present, err := m.GuardPresent(ctx, link)
	if err != nil || !present {
		return linux.WGIngressLiveHandles{}, fmt.Errorf("managed QUIC guard is not ready")
	}
	p, _ := m.plan(ctx, link)
	present, handles, err := linux.ReadWGIngressGuardHandles(ctx, m.runner, p)
	if err != nil || !present {
		return linux.WGIngressLiveHandles{}, fmt.Errorf("managed QUIC guard readback changed")
	}
	return handles, nil
}
