package managedmtu

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/gre"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type managedRunner struct {
	ifaces   map[string]mtuInterface
	routeMTU int
	calls    int
}

func (r *managedRunner) Run(_ context.Context, binary string, args ...string) (linux.CommandResult, error) {
	r.calls++
	if binary != "ip" {
		return linux.CommandResult{}, fmt.Errorf("unexpected command")
	}
	if len(args) == 5 && args[0] == "-4" && args[1] == "-json" &&
		args[2] == "route" && args[3] == "get" && args[4] == "198.51.100.20" {
		jsonBytes, _ := json.Marshal([]any{map[string]any{
			"dst": args[4], "dev": "eth0", "prefsrc": "192.0.2.10", "mtu": r.routeMTU,
		}})
		return linux.CommandResult{Stdout: jsonBytes}, nil
	}
	if len(args) == 5 && args[0] == "-json" && args[1] == "link" &&
		args[2] == "show" && args[3] == "dev" {
		i, exists := r.ifaces[args[4]]
		if !exists {
			return linux.CommandResult{}, fmt.Errorf("device not found")
		}
		raw, _ := json.Marshal([]mtuInterface{i})
		return linux.CommandResult{Stdout: raw}, nil
	}
	return linux.CommandResult{}, fmt.Errorf("unexpected ip inspection")
}

func managedLink(t *testing.T) domain.Link {
	t.Helper()
	link := domain.Link{
		ID:        "lnk_11111111111111111111111111111111",
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("198.51.100.20")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.20.30.0/31"), Peer: netip.MustParsePrefix("10.20.30.1/31")},
		Backend:   domain.BackendGRE, Encapsulation: domain.EncapNative,
		MTU: domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1300},
	}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	return link
}

func managerFixture(t *testing.T) (HostMTUManager, *managedRunner, domain.Link, []domain.ResourceClaim) {
	t.Helper()
	link := managedLink(t)
	name, err := gre.InterfaceName(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := linux.OwnerTag(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	runner := &managedRunner{routeMTU: 1500, ifaces: map[string]mtuInterface{
		name:   {IfName: name, IfIndex: 91, IfAlias: alias, MTU: 1500},
		"eth0": {IfName: "eth0", IfIndex: 2, MTU: 1500},
	}}
	manager := HostMTUManager{Runner: runner,
		SetByIndex: func(_ context.Context, index, value int) error {
			for name, entry := range runner.ifaces {
				if entry.IfIndex == index {
					entry.MTU = value
					runner.ifaces[name] = entry
					return nil
				}
			}
			return errors.New("no such pinned interface index")
		},
	}
	return manager, runner, link, []domain.ResourceClaim{{Kind: domain.ResourceInterface, Key: name}}
}

func TestManagedLocalManualAutoAndRollback(t *testing.T) {
	ctx := context.Background()
	manager, runner, link, claims := managerFixture(t)
	undo, changed, err := manager.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Link: link}, false, claims)
	if err != nil || !changed || undo == nil || runner.ifaces[claims[0].Key].MTU != 1300 {
		t.Fatalf("manual application: changed=%v err=%v", changed, err)
	}
	if err := undo(ctx); err != nil || runner.ifaces[claims[0].Key].MTU != 1500 {
		t.Fatalf("manual rollback failed: %v", err)
	}
	link.MTU = domain.MTUPolicy{Mode: domain.MTUAuto}
	undo, changed, err = manager.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Link: link}, false, claims)
	if err != nil || !changed || undo == nil || runner.ifaces[claims[0].Key].MTU != 1280 {
		t.Fatalf("conservative Auto application: changed=%v err=%v", changed, err)
	}
	// Repeated Engine Ensure/reapply is idempotent when the policy is already applied.
	prior := link
	noUndo, again, err := manager.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Prior: &prior, Link: link}, true, claims)
	if err != nil || again || noUndo != nil {
		t.Fatalf("idempotent reapply unexpectedly changed Link: %v %v", again, err)
	}
}

func TestManagedMTULegacyOwnershipAndConstraintGuards(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		change func(*HostMTUManager, *managedRunner, *domain.Link, *[]domain.ResourceClaim)
		before bool
	}{
		{"unmanaged", func(_ *HostMTUManager, _ *managedRunner, l *domain.Link, _ *[]domain.ResourceClaim) {
			l.MTU = domain.MTUPolicy{}
		}, false},
		{"excessive", func(_ *HostMTUManager, _ *managedRunner, l *domain.Link, _ *[]domain.ResourceClaim) {
			l.MTU.Bytes = 1499
		}, false},
		{"bad_owner", func(_ *HostMTUManager, r *managedRunner, _ *domain.Link, c *[]domain.ResourceClaim) {
			v := r.ifaces[(*c)[0].Key]
			v.IfAlias = "owned-by-other"
			r.ifaces[(*c)[0].Key] = v
		}, false},
		{"missing_claim", func(_ *HostMTUManager, _ *managedRunner, _ *domain.Link, c *[]domain.ResourceClaim) { *c = nil }, false},
		{"uncommitted_adoption", func(_ *HostMTUManager, _ *managedRunner, _ *domain.Link, _ *[]domain.ResourceClaim) {}, true},
		{"unknown_underlay", func(_ *HostMTUManager, r *managedRunner, _ *domain.Link, _ *[]domain.ResourceClaim) {
			delete(r.ifaces, "eth0")
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, r, l, c := managerFixture(t)
			tc.change(&m, r, &l, &c)
			count := r.calls
			undo, changed, err := m.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Link: l}, tc.before, c)
			if tc.name == "unmanaged" {
				if err != nil || changed || undo != nil || r.calls != count {
					t.Fatalf("unmanaged path mutated/inspected: %v %v", changed, err)
				}
			} else if err == nil || changed || undo != nil {
				t.Fatalf("unexpected unsafe acceptance: %v %v", changed, err)
			}
		})
	}
}

func TestManagedMTURollbackRefusesIdentityDrift(t *testing.T) {
	ctx := context.Background()
	manager, runner, link, claims := managerFixture(t)
	undo, changed, err := manager.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Link: link}, false, claims)
	if err != nil || !changed {
		t.Fatal(err)
	}
	target := runner.ifaces[claims[0].Key]
	target.IfIndex = 92 // a replacement interface at the same name
	runner.ifaces[claims[0].Key] = target
	if err := undo(ctx); err == nil {
		t.Fatal("guarded undo modified a replacement interface")
	}
	if runner.ifaces[claims[0].Key].MTU != 1300 {
		t.Fatal("wrong MTU changed after identity drift")
	}
}

func TestManagedMTUAllNativeBackendsHaveLocalOwnershipAndOverhead(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		backend domain.Backend
		encap   domain.Encapsulation
	}{
		{"gre_native", domain.BackendGRE, domain.EncapNative},
		{"gre_fou", domain.BackendGRE, domain.EncapFOU},
		{"gre_gue", domain.BackendGRE, domain.EncapGUE},
		{"ipip_native", domain.BackendIPIP, domain.EncapNative},
		{"ipip_fou", domain.BackendIPIP, domain.EncapFOU},
		{"ipip_gue", domain.BackendIPIP, domain.EncapGUE},
		{"wireguard", domain.BackendWireGuard, domain.EncapUDP},
		{"ipsec_esp", domain.BackendIPsec, domain.EncapESP},
		{"ipsec_nat_t", domain.BackendIPsec, domain.EncapNATT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, link, _ := managerFixture(t)
			link.Backend, link.Encapsulation = tc.backend, tc.encap
			if (link.Backend == domain.BackendGRE || link.Backend == domain.BackendIPIP) &&
				(link.Encapsulation == domain.EncapFOU || link.Encapsulation == domain.EncapGUE) {
				link.GRE = domain.GREOptions{}
				if link.Backend == domain.BackendGRE {
					link.GRE.UDPPort = 35000
				}
			}
			if link.Backend == domain.BackendWireGuard {
				pub1 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
				pub2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
				link.WireGuard = domain.WireGuardOptions{
					LocalPublicKey: pub1, PeerPublicKey: pub2, ListenPort: 51820, PeerPort: 51821,
				}
			}
			if err := link.Validate(); err != nil {
				t.Fatal(err)
			}
			name, overhead, err := mtuIdentity(link)
			if err != nil || overhead <= 0 {
				t.Fatalf("backend identity/overhead: %s %d %v", name, overhead, err)
			}
			alias, _ := linux.OwnerTag(link.ID)
			runner := &managedRunner{routeMTU: 1500, ifaces: map[string]mtuInterface{
				name:   {IfIndex: 44, IfName: name, IfAlias: alias, MTU: 1500},
				"eth0": {IfIndex: 2, IfName: "eth0", MTU: 1500},
			}}
			manager := HostMTUManager{Runner: runner, SetByIndex: func(_ context.Context, idx, bytes int) error {
				if idx != 44 {
					return errors.New("wrong index")
				}
				v := runner.ifaces[name]
				v.MTU = bytes
				runner.ifaces[name] = v
				return nil
			}}
			claims := []domain.ResourceClaim{{Kind: domain.ResourceInterface, Key: name}}
			undo, changed, err := manager.Apply(ctx, backend.Request{Operation: backend.OperationEnsure, Link: link}, false, claims)
			if err != nil || !changed || undo == nil || runner.ifaces[name].MTU != 1300 {
				t.Fatalf("backend managed MTU failed: changed=%v mtu=%d err=%v", changed, runner.ifaces[name].MTU, err)
			}
			if err := undo(ctx); err != nil || runner.ifaces[name].MTU != 1500 {
				t.Fatalf("backend managed undo failed: %v", err)
			}
		})
	}
}
