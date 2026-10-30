package managedmtu

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

func quicMTUFixture(t *testing.T) (context.Context, HostMTUManager, *managedRunner, domain.Link, []domain.ResourceClaim) {
	t.Helper()
	m, r, link, claims := managerFixture(t)
	link.Backend, link.Encapsulation = domain.BackendWireGuardQUIC, domain.EncapUDP
	link.WireGuard = domain.WireGuardOptions{
		LocalPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		PeerPublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		ListenPort:     51821, PeerPort: 51820,
	}
	link.QUIC = domain.QUICOptions{Role: "dial", UDPPort: 443, ForwardUDPPort: 52211}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	const nonce = "11111111111111111111111111111111"
	ctx, err := backend.WithQUICOrigin(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	name, err := wireguard.InterfaceName(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := linux.QUICWGOwnerTag(link.ID, nonce)
	if err != nil {
		t.Fatal(err)
	}
	entry := r.ifaces[claims[0].Key]
	delete(r.ifaces, claims[0].Key)
	entry.IfName, entry.IfAlias = name, alias
	r.ifaces[name] = entry
	claims[0].Key = name
	return ctx, m, r, link, claims
}

func TestManagedQUICMTUUsesHelperCapacityAndQUICMinimum(t *testing.T) {
	for _, tc := range []struct {
		name        string
		obfuscation string
		policy      domain.MTUPolicy
		routeMTU    int
		want        int
	}{
		{"conservative_auto", "", domain.MTUPolicy{Mode: domain.MTUAuto}, 1228, 1280},
		{"fragmented_inner_packet", "", domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 4032}, 1500, 4032},
		{"over_helper_capacity", "", domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 4033}, 9000, 0},
		{"underlay_too_small", "", domain.MTUPolicy{Mode: domain.MTUAuto}, 1227, 0},
		{"salamander_minimum", domain.QUICObfuscationSalamander, domain.MTUPolicy{Mode: domain.MTUAuto}, 1236, 1280},
		{"salamander_underlay_too_small", domain.QUICObfuscationSalamander, domain.MTUPolicy{Mode: domain.MTUAuto}, 1235, 0},
		{"salamander_capacity_unchanged", domain.QUICObfuscationSalamander, domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 4032}, 1500, 4032},
		{"salamander_over_capacity", domain.QUICObfuscationSalamander, domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 4033}, 9000, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, m, r, link, claims := quicMTUFixture(t)
			link.MTU, r.routeMTU = tc.policy, tc.routeMTU
			link.QUIC.Obfuscation = tc.obfuscation
			undo, changed, err := m.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Link: link}, false, claims)
			if tc.want == 0 {
				if err == nil || changed || undo != nil || r.ifaces[claims[0].Key].MTU != 1500 {
					t.Fatalf("invalid MTU mutated Link: changed=%v err=%v", changed, err)
				}
				return
			}
			if err != nil || !changed || undo == nil || r.ifaces[claims[0].Key].MTU != tc.want {
				t.Fatalf("QUIC MTU=%d changed=%v err=%v", r.ifaces[claims[0].Key].MTU, changed, err)
			}
			if err := undo(ctx); err != nil || r.ifaces[claims[0].Key].MTU != 1500 {
				t.Fatalf("QUIC guarded rollback: %v", err)
			}
		})
	}
}

func TestManagedQUICMTURequiresTheTransactionNonce(t *testing.T) {
	for _, mode := range []string{"missing_context", "other_nonce", "generic_owner"} {
		t.Run(mode, func(t *testing.T) {
			ctx, m, r, link, claims := quicMTUFixture(t)
			switch mode {
			case "missing_context":
				ctx = context.Background()
			case "other_nonce":
				ctx, _ = backend.WithQUICOrigin(ctx, "22222222222222222222222222222222")
			case "generic_owner":
				entry := r.ifaces[claims[0].Key]
				entry.IfAlias, _ = linux.OwnerTag(link.ID)
				r.ifaces[claims[0].Key] = entry
			}
			undo, changed, err := m.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Link: link}, false, claims)
			if err == nil || changed || undo != nil || r.ifaces[claims[0].Key].MTU != 1500 {
				t.Fatalf("unproven QUIC owner changed: changed=%v err=%v", changed, err)
			}
		})
	}
	ctx, m, r, link, claims := quicMTUFixture(t)
	undo, changed, err := m.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Link: link}, false, claims)
	if err != nil || !changed || undo == nil {
		t.Fatalf("apply before owner replacement: %v", err)
	}
	entry := r.ifaces[claims[0].Key]
	entry.IfAlias, _ = linux.QUICWGOwnerTag(link.ID, "22222222222222222222222222222222")
	r.ifaces[claims[0].Key] = entry
	if err := undo(ctx); err == nil || r.ifaces[claims[0].Key].MTU != 1300 {
		t.Fatal("rollback touched a different QUIC generation")
	}
}
