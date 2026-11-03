package ipip

import (
	"context"
	"reflect"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type unreadableIPIPInventory struct {
	fakeRunner
	output []byte
	calls  []string
}

func (r *unreadableIPIPInventory) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	joined := strings.Join(args, " ")
	r.calls = append(r.calls, joined)
	if joined == "-details -json link show type ipip" {
		return linux.CommandResult{Stdout: r.output}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestIPIPSuccessfulExitMalformedInventoryFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name         string
		output       string
		moduleOnDisk bool
		wantReason   string
	}{
		{"placeholder rows with proven unloaded module", "[{},{},{}]", true, "kernel_module_not_loaded"},
		{"placeholder rows with unknown module", "[{},{},{}]", false, "ipip_kernel_inventory_unverified"},
		{"null is not a verified empty list", "null", false, "ipip_kernel_inventory_unverified"},
		{"whitespace is not a verified empty list", "  \n  ", false, "ipip_kernel_inventory_unverified"},
		{"fallback missing identity", `[{"linkinfo":{"info_kind":"ipip","info_data":{"local":"any","remote":"any"}}}]`, false, "ipip_kernel_inventory_unverified"},
		{"one-sided wildcard cannot hide a foreign device", `[{"ifindex":1,"ifname":"tunl0","linkinfo":{"info_kind":"ipip","info_data":{"local":"any","remote":"192.0.2.2"}}}]`, false, "ipip_kernel_inventory_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := testLink()
			runner := &unreadableIPIPInventory{fakeRunner: fakeRunner{link: link}, output: []byte(tc.output)}
			backend, err := New(Options{
				Runner: runner, Routes: fakeRoute{linux.Route{Peer: link.Underlay.Peer, Source: link.Underlay.Local, Device: "eth0"}},
				Firewall: &fakeFirewall{}, Collisions: fakeCollisions{},
				ModuleProbe: func(_ context.Context, module string) bool {
					if module != "ipip" {
						t.Fatalf("unexpected module %q", module)
					}
					return tc.moduleOnDisk
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = backend.Inspect(context.Background(), link)
			if err == nil {
				t.Fatal("unverified inventory accepted as free host resources")
			}
			public := stlerr.Public(err)
			if public.Code != stlerr.CodeInspect || public.ReasonCode != tc.wantReason || public.NextStep == "" ||
				strings.Contains(public.Error()+public.NextStep, tc.output) {
				t.Fatalf("unsafe/unhelpful inspection failure: %+v", public)
			}
			status, err := backend.Capability(context.Background(), link)
			if err != nil || status.Available || status.ReasonCode != tc.wantReason {
				t.Fatalf("capability disagrees with Engine inventory: %+v %v", status, err)
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "link add") || strings.Contains(call, "link del") ||
					strings.Contains(call, "modprobe") || strings.Contains(call, "fou add") {
					t.Fatalf("inspection/capability mutated the host: %s", call)
				}
			}
		})
	}
}

func TestIPIPEmptyArrayAndValidWildcardAreNotMalformed(t *testing.T) {
	for _, input := range []string{
		"[]",
		`[{"ifindex":1,"ifname":"tunl0","linkinfo":{"info_kind":"ipip","info_data":{"local":"any","remote":"any"}}}]`,
	} {
		got, err := parseIPIPLinks([]byte(input))
		if err != nil || len(got) != 0 {
			t.Fatalf("trustworthy empty/wildcard IPIP observation refused: %v %#v", err, got)
		}
	}
}

// A successful preflight does not guarantee that a later inventory is valid.
// Remove can already have released its owned firewall claim when it performs
// its final interface identity check, so low-level errors must NEVER assert
// that the enclosing operation was mutation-free.
type ipipFirewallChangeInventoryRunner struct {
	*fakeRunner
	firewall *fakeFirewall
}

func (r *ipipFirewallChangeInventoryRunner) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && strings.Join(args, " ") == "-details -json link show type ipip" && !r.firewall.present {
		return linux.CommandResult{Stdout: []byte("[{}]")}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestIPIPRemoveMalformedInventoryAfterOwnedFirewallEffectRollsBack(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapNative, domain.EncapFOU, domain.EncapGUE} {
		t.Run(string(encap), func(t *testing.T) {
			link := testLink()
			link.Encapsulation = encap
			name, _ := InterfaceName(link.ID)
			runner := &fakeRunner{link: link, name: name}
			firewall := &fakeFirewall{}
			b := newTestBackend(t, runner, firewall, fakeCollisions{})
			b.moduleProbe = func(context.Context, string) bool { return false }
			ctx := context.Background()
			ensure := core.Request{Operation: core.OperationEnsure, Link: link}
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			createPlan, err := b.Plan(ctx, ensure, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err = b.Validate(ctx, ensure, obs, createPlan); err != nil {
				t.Fatal(err)
			}
			if _, err = b.Apply(ctx, ensure, obs, createPlan); err != nil {
				t.Fatal(err)
			}
			if _, err = b.Verify(ctx, ensure); err != nil {
				t.Fatal(err)
			}
			before := runner.state
			mappingsBefore := len(runner.mappings)
			if !firewall.present || !before.Exists {
				t.Fatal("fixture create was not confirmed")
			}

			remove := core.Request{Operation: core.OperationRemove, Prior: &link, Link: link,
				OwnedResources: createPlan.Resources()}
			obs, err = b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			removePlan, err := b.Plan(ctx, remove, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err = b.Validate(ctx, remove, obs, removePlan); err != nil {
				t.Fatal(err)
			}
			b.runner = &ipipFirewallChangeInventoryRunner{fakeRunner: runner, firewall: firewall}
			undo, err := b.Apply(ctx, remove, obs, removePlan)
			if err == nil || undo == nil || firewall.present {
				t.Fatalf("invalid post-firewall inspection was accepted or firewall not removed: undo=%t err=%v fw=%t",
					undo != nil, err, firewall.present)
			}
			typed := stlerr.Public(err)
			if typed.Code != stlerr.CodeInspect || typed.ReasonCode != "ipip_kernel_inventory_unverified" ||
				strings.Contains(typed.Detail+typed.NextStep, "no host state was applied") {
				t.Fatalf("backend falsely claimed mutation-free Remove: %+v", typed)
			}
			if !runner.state.Exists || len(runner.mappings) != mappingsBefore {
				t.Fatal("an unverified Remove deleted other resources before returning rollback")
			}
			if err := undo(ctx); err != nil {
				t.Fatalf("owned firewall rollback failed: %v", err)
			}
			if !firewall.present || !reflect.DeepEqual(runner.state, before) || len(runner.mappings) != mappingsBefore {
				t.Fatal("Remove failed to restore precisely its owned firewall effect")
			}
			restored, err := b.Inspect(ctx, link)
			if err != nil || !restored.(observation).Target.matches(link, name) {
				t.Fatalf("saved Link not inspectable after rollback: %v", err)
			}
		})
	}
}

type ipipForcedInvalidInventory struct{ *fakeRunner }

func (r *ipipForcedInvalidInventory) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && strings.Join(args, " ") == "-details -json link show type ipip" {
		return linux.CommandResult{Stdout: []byte("[{}]")}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestIPIPVerifyAfterApplyDoesNotClaimMutationWasImpossible(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name}
	fw := &fakeFirewall{}
	b := newTestBackend(t, runner, fw, fakeCollisions{})
	b.moduleProbe = func(context.Context, string) bool { return false }
	ctx := context.Background()
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, err := b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Validate(ctx, req, obs, plan); err != nil {
		t.Fatal(err)
	}
	undo, err := b.Apply(ctx, req, obs, plan)
	if err != nil || undo == nil || !runner.state.Exists || !fw.present {
		t.Fatalf("apply fixture did not mutate host: %v", err)
	}
	b.runner = &ipipForcedInvalidInventory{fakeRunner: runner}
	_, err = b.Verify(ctx, req)
	if err == nil {
		t.Fatal("malformed post-Apply inventory was accepted")
	}
	typed := stlerr.Public(err)
	if typed.ReasonCode != "ipip_kernel_inventory_unverified" ||
		strings.Contains(typed.Detail+typed.NextStep, "no host state was applied") {
		t.Fatalf("post-Apply Verify misrepresented host mutation: %+v", typed)
	}
	b.runner = runner // Restore the intact test-only observation before callback.
	if err := undo(ctx); err != nil {
		t.Fatalf("test-only Apply rollback failed: %v", err)
	}
	if runner.state.Exists || fw.present {
		t.Fatal("fixture rollback did not return to the exact original state")
	}
}
