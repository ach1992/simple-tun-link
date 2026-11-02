package l2tpv3

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func committedFixture(t *testing.T) (domain.Link, *Backend, *fakeKernel, *fakeFirewall, []domain.ResourceClaim) {
	t.Helper()
	l := testLink()
	k := newFakeKernel(t, l)
	fw := &fakeFirewall{}
	b := testBackend(t, l, k, fw, fakeCollisions{})
	plan, _, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
	if err != nil {
		t.Fatal(err)
	}
	return l, b, k, fw, plan.Resources()
}
func foreignIPv6() map[string]any {
	return map[string]any{"family": "inet6", "local": "2001:db8::99", "prefixlen": 128, "scope": "global", "protocol": "static"}
}
func manualIPv6LinkLocal() map[string]any {
	return map[string]any{"family": "inet6", "local": "fe80::99", "prefixlen": 64, "scope": "link", "protocol": "static"}
}
func autoIPv6LinkLocal() map[string]any {
	return map[string]any{"family": "inet6", "local": "fe80::1234", "prefixlen": 64, "scope": "link", "protocol": "kernel_ll"}
}
func fakePermanentNeighbor(dst, mac string) neighbor {
	return neighbor{Dst: dst, LLAddr: mac, State: []byte("[\"PERMANENT\"]")}
}
func assertNoSessionDelete(t *testing.T, calls []string) {
	t.Helper()
	for _, call := range calls {
		if strings.HasPrefix(call, "l2tp del session ") {
			t.Fatalf("unsafe L2TP session deletion: %s", call)
		}
	}
}
func TestForeignIPv6AddressOwnership(t *testing.T) {
	t.Run("remove rejects global and manual-linklocal", func(t *testing.T) {
		for _, entry := range []map[string]any{foreignIPv6(), manualIPv6LinkLocal()} {
			l, b, k, fw, owned := committedFixture(t)
			k.ipv6 = []map[string]any{entry}
			_, _, err := exercise(t, b, core.Request{Operation: core.OperationRemove, Link: l, Prior: &l, OwnedResources: owned})
			if err == nil || k.ifc == nil || len(k.ipv6) != 1 || !fw.active {
				t.Fatalf("foreign IPv6 was lost or accepted: %v", err)
			}
			assertNoSessionDelete(t, k.calls)
		}
	})
	t.Run("foreign inserted after Validate before Apply", func(t *testing.T) {
		l, b, k, fw, owned := committedFixture(t)
		req := core.Request{Operation: core.OperationRemove, Link: l, Prior: &l, OwnedResources: owned}
		ctx := context.Background()
		o, err := b.Inspect(ctx, l)
		if err != nil {
			t.Fatal(err)
		}
		p, err := b.Plan(ctx, req, o)
		if err != nil {
			t.Fatal(err)
		}
		if err = b.Validate(ctx, req, o, p); err != nil {
			t.Fatal(err)
		}
		k.ipv6 = []map[string]any{foreignIPv6()}
		priorCalls := len(k.calls)
		undo, err := b.Apply(ctx, req, o, p)
		if err == nil || undo == nil {
			t.Fatalf("foreign address accepted after validation: %v", err)
		}
		assertNoSessionDelete(t, k.calls[priorCalls:])
		if e := undo(ctx); e != nil {
			t.Fatalf("firewall rollback failed: %v", e)
		}
		if !fw.active || k.ifc == nil || len(k.ipv6) != 1 {
			t.Fatal("foreign IPv6 or original session lost")
		}
	})
	t.Run("foreign address blocks create rollback", func(t *testing.T) {
		l := testLink()
		k := newFakeKernel(t, l)
		fw := &fakeFirewall{}
		b := testBackend(t, l, k, fw, fakeCollisions{})
		k.onAddNeighbor = func() { k.ipv6 = []map[string]any{foreignIPv6()} }
		k.fail = "neighbor add"
		_, undo, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
		if err == nil || undo == nil {
			t.Fatal("injected failure was not reported")
		}
		if err = undo(context.Background()); !errors.Is(err, core.ErrIndeterminateHostEffect) {
			t.Fatalf("unowned IPv6 rollback must be indeterminate: %v", err)
		}
		if k.ifc == nil || len(k.ipv6) != 1 {
			t.Fatal("foreign IPv6/interface deleted during rollback")
		}
	})
	t.Run("normal auto kernel link local can be removed", func(t *testing.T) {
		l := testLink()
		k := newFakeKernel(t, l)
		fw := &fakeFirewall{}
		b := testBackend(t, l, k, fw, fakeCollisions{})
		k.onAddNeighbor = func() { k.ipv6 = []map[string]any{autoIPv6LinkLocal()} }
		p, _, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = exercise(t, b, core.Request{Operation: core.OperationRemove, Link: l, Prior: &l, OwnedResources: p.Resources()})
		if err != nil || k.ifc != nil {
			t.Fatalf("kernel-generated IPv6 link-local should not block owned Remove: %v", err)
		}
	})
	t.Run("older kernel deterministic EUI64 fallback", func(t *testing.T) {
		if !autoKernelLinkLocal("fe80::1a2b:3cff:fe4d:5e6f", 64, "link", "", "18:2b:3c:4d:5e:6f") {
			t.Fatal("older kernel exact EUI-64 auto link-local rejected")
		}
		if autoKernelLinkLocal("fe80::1234", 64, "link", "", "18:2b:3c:4d:5e:6f") {
			t.Fatal("unverified older-kernel manual link-local accepted")
		}
	})
}
func TestNeighborMutationsRemainExclusiveAndPinned(t *testing.T) {
	t.Run("foreign neighbor arrives between Validate and Apply", func(t *testing.T) {
		l, b, k, fw, owned := committedFixture(t)
		req := core.Request{Operation: core.OperationRemove, Link: l, Prior: &l, OwnedResources: owned}
		ctx := context.Background()
		o, err := b.Inspect(ctx, l)
		if err != nil {
			t.Fatal(err)
		}
		p, err := b.Plan(ctx, req, o)
		if err != nil {
			t.Fatal(err)
		}
		if err = b.Validate(ctx, req, o, p); err != nil {
			t.Fatal(err)
		}
		foreign := fakePermanentNeighbor("10.253.115.3", "02:01:02:03:04:05")
		k.neigh = append(k.neigh, foreign)
		start := len(k.calls)
		undo, err := b.Apply(ctx, req, o, p)
		if err == nil || undo == nil {
			t.Fatal("stale owner observation incorrectly authorized Delete")
		}
		assertNoSessionDelete(t, k.calls[start:])
		if err = undo(ctx); err != nil {
			t.Fatal(err)
		}
		if !fw.active || k.ifc == nil || len(k.neigh) != 2 || k.neigh[1].LLAddr != foreign.LLAddr {
			t.Fatal("foreign neighbor destroyed or firewall not restored")
		}
	})
	t.Run("exclusive add refuses competitor peer neighbor", func(t *testing.T) {
		l := testLink()
		k := newFakeKernel(t, l)
		fw := &fakeFirewall{}
		b := testBackend(t, l, k, fw, fakeCollisions{})
		foreign := fakePermanentNeighbor(l.Addresses.Peer.Addr().String(), "02:99:88:77:66:55")
		k.onAddNeighbor = func() { k.neigh = []neighbor{foreign} }
		_, undo, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
		if err == nil || undo == nil {
			t.Fatal("expected exclusive neighbor conflict")
		}
		if err = undo(context.Background()); !errors.Is(err, core.ErrIndeterminateHostEffect) {
			t.Fatalf("foreign neighbor must prevent destructive rollback: %v", err)
		}
		if k.ifc == nil || len(k.neigh) != 1 || k.neigh[0].LLAddr != foreign.LLAddr {
			t.Fatal("foreign neighbor overwritten or interface removed")
		}
		for _, call := range k.calls {
			if strings.Contains(call, "neigh replace") {
				t.Fatal("non-exclusive neighbor path was used")
			}
		}
	})
	t.Run("index-bound neighbor cannot reach replaced interface", func(t *testing.T) {
		l := testLink()
		k := newFakeKernel(t, l)
		fw := &fakeFirewall{}
		b := testBackend(t, l, k, fw, fakeCollisions{})
		k.onAddNeighbor = func() {
			k.ifc = &iface{IfIndex: 999, IfName: k.id.name, IfAlias: "foreign", Address: "02:00:00:00:00:01"}
		}
		_, undo, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
		if err == nil || undo == nil {
			t.Fatal("replaced ifindex incorrectly modified")
		}
		if err = undo(context.Background()); !errors.Is(err, core.ErrIndeterminateHostEffect) {
			t.Fatalf("unsafe rollback: %v", err)
		}
		if len(k.neigh) != 0 || k.ifc == nil || k.ifc.IfIndex != 999 {
			t.Fatal("foreign ifindex received a neighbor or was deleted")
		}
	})
}
func TestAmbiguousL2TPMutationAfterKernelEffect(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		cause         error
	}{
		{"add tunnel error", "l2tp add tunnel", errors.New("exit error")},
		{"add tunnel timeout", "l2tp add tunnel", context.DeadlineExceeded},
		{"add session error", "l2tp add session", errors.New("exit error")},
		{"add session cancel", "l2tp add session", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := testLink()
			k := newFakeKernel(t, l)
			fw := &fakeFirewall{}
			b := testBackend(t, l, k, fw, fakeCollisions{})
			k.failAfter = tc.command
			k.failAfterErr = tc.cause
			_, undo, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
			if err == nil || undo == nil {
				t.Fatal("post-effect command error not propagated")
			}
			if err = undo(context.Background()); !errors.Is(err, core.ErrIndeterminateHostEffect) {
				t.Fatalf("unverified post-effect kernel mutation misclassified as clean: %v", err)
			}
			if len(k.tunnels) != 1 {
				t.Fatal("unknown tunnel incorrectly deleted")
			}
			if tc.command == "l2tp add session" && (k.ifc == nil || k.ifc.IfAlias != "") {
				t.Fatal("unowned session was deleted/adopted instead of preserved")
			}
		})
	}
	t.Run("pre-effect add error allows vacancy-proven rollback", func(t *testing.T) {
		l := testLink()
		k := newFakeKernel(t, l)
		fw := &fakeFirewall{}
		b := testBackend(t, l, k, fw, fakeCollisions{})
		k.fail = "l2tp add tunnel"
		_, undo, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
		if err == nil || undo == nil {
			t.Fatal("missing pre-effect error")
		}
		if err = undo(context.Background()); err != nil {
			t.Fatalf("vacancy-proven rollback should succeed: %v", err)
		}
		if len(k.tunnels) != 0 || len(k.sessions) != 0 {
			t.Fatal("rollback did not retain exact vacancy")
		}
	})
	for _, tc := range []struct {
		name, command string
		cause         error
	}{
		{"delete session post-effect error", "l2tp del session", errors.New("exit error")},
		{"delete session timeout", "l2tp del session", context.DeadlineExceeded},
		{"delete tunnel post-effect error", "l2tp del tunnel", errors.New("exit error")},
		{"delete tunnel cancellation", "l2tp del tunnel", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, b, k, fw, owned := committedFixture(t)
			k.failAfter = tc.command
			k.failAfterErr = tc.cause
			req := core.Request{Operation: core.OperationRemove, Link: l, Prior: &l, OwnedResources: owned}
			_, undo, err := exercise(t, b, req)
			if err == nil || undo == nil {
				t.Fatal("post-effect delete failure not propagated")
			}
			k.failAfter = ""
			if err = undo(context.Background()); err != nil {
				t.Fatalf("committed Link could not be restored safely: %v", err)
			}
			if !fw.active || k.ifc == nil || len(k.tunnels) != 1 || len(k.sessions) != 1 {
				t.Fatal("kernel/owned firewall were not restored")
			}
			if _, err = b.Verify(context.Background(), core.Request{Operation: core.OperationEnsure, Link: l}); err != nil {
				t.Fatalf("failed to prove exact restoration: %v", err)
			}
		})
	}
	t.Run("foreign session after delete error blocks reconstruction", func(t *testing.T) {
		l, b, k, fw, owned := committedFixture(t)
		k.failAfter = "l2tp del session"
		_, undo, err := exercise(t, b, core.Request{Operation: core.OperationRemove, Link: l, Prior: &l, OwnedResources: owned})
		if err == nil || undo == nil {
			t.Fatal("missing post-effect failure")
		}
		k.sessions = append(k.sessions, session{TunnelID: k.id.tunnel, SessionID: 999, PeerTunnelID: k.id.peerTunnel})
		if err = undo(context.Background()); !errors.Is(err, core.ErrIndeterminateHostEffect) {
			t.Fatalf("recovery overwrote foreign session: %v", err)
		}
		if len(k.sessions) != 1 || k.sessions[0].SessionID != 999 || !fw.active {
			t.Fatal("foreign session or original firewall lost")
		}
	})
}

// Engine classification is part of the public operator contract. An
// unknown kernel effect with an unsafe rollback must produce evidence
// rollback=incomplete, not completed_unverified, and must not commit State.
func TestEngineEvidenceForAmbiguousL2TPv3(t *testing.T) {
	for _, command := range []string{"l2tp add tunnel", "l2tp add session"} {
		t.Run(command, func(t *testing.T) {
			l := testLink()
			k := newFakeKernel(t, l)
			fw := &fakeFirewall{}
			b := testBackend(t, l, k, fw, fakeCollisions{})
			reg, err := core.NewRegistry(b)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			engine, err := app.New(reg, state.NewFileStore(root), state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			k.failAfter = command
			_, err = engine.Ensure(context.Background(), l)
			proof := stlerr.EvidenceOf(err)
			if err == nil || proof == nil || proof.Stage != "apply" ||
				proof.HostMutation != "attempted" || proof.Rollback != "incomplete" ||
				proof.DesiredState != "no_commit_attempted" ||
				stlerr.CodeOf(err) != stlerr.CodeRollback {
				t.Fatalf("unverified kernel effect incorrectly classified: %v evidence=%+v", err, proof)
			}
			if snap, err := state.NewFileStore(root).Load(context.Background()); err != nil {
				t.Fatal(err)
			} else if _, ok := snap.Find(l.ID); ok {
				t.Fatal("indeterminate Ensure committed Link")
			}
			if stlerr.Public(err).ReasonCode != "l2tpv3_kernel_effect_indeterminate" ||
				stlerr.Public(err).NextStep == "" {
				t.Fatalf("no safe operator guidance for uncertain kernel effect: %+v", stlerr.Public(err))
			}
			if len(k.tunnels) != 1 {
				t.Fatal("unattributed tunnel was deleted")
			}
		})
	}
	t.Run("delete session post-effect restored and state retained", func(t *testing.T) {
		l := testLink()
		k := newFakeKernel(t, l)
		fw := &fakeFirewall{}
		b := testBackend(t, l, k, fw, fakeCollisions{})
		reg, err := core.NewRegistry(b)
		if err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		engine, err := app.New(reg, state.NewFileStore(root), state.NewLockManager(root))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = engine.Ensure(context.Background(), l); err != nil {
			t.Fatal(err)
		}
		k.failAfter = "l2tp del session"
		_, err = engine.Remove(context.Background(), l.ID)
		proof := stlerr.EvidenceOf(err)
		if err == nil || proof == nil || proof.Stage != "apply" || proof.Rollback != "completed_unverified" {
			t.Fatalf("exact compensated Remove evidence mismatch: %v %+v", err, proof)
		}
		if !fw.active || k.ifc == nil {
			t.Fatal("original committed Link did not survive compensation")
		}
		if snap, err := state.NewFileStore(root).Load(context.Background()); err != nil {
			t.Fatal(err)
		} else if _, ok := snap.Find(l.ID); !ok {
			t.Fatal("compensated Remove lost committed State")
		}
	})
}
