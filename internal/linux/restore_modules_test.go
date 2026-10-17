package linux

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type moduleRestoreRunner struct {
	present  map[string]bool
	commands []string
	fail     string
}

func (r *moduleRestoreRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, cmd)
	if cmd == r.fail {
		return CommandResult{}, errors.New("SECRET=should-not-leak")
	}
	if name == "/sbin/modprobe" && len(args) == 1 {
		r.present[args[0]] = true
	}
	return CommandResult{}, nil
}
func linkForModules(kind domain.Backend, enc domain.Encapsulation) domain.Link {
	return domain.Link{Backend: kind, Encapsulation: enc}
}
func TestCommittedRestoreModulesOnlyForOwnedSavedLinkType(t *testing.T) {
	cases := []struct {
		kind domain.Backend
		enc  domain.Encapsulation
		want []string
	}{
		{domain.BackendGRE, domain.EncapNative, []string{"ip_gre"}},
		{domain.BackendGRE, domain.EncapFOU, []string{"ip_gre", "fou"}},
		{domain.BackendGRE, domain.EncapGUE, []string{"ip_gre", "fou"}},
		{domain.BackendIPIP, domain.EncapNative, []string{"ipip"}},
		{domain.BackendIPIP, domain.EncapFOU, []string{"ipip", "fou"}},
		{domain.BackendIPIP, domain.EncapGUE, []string{"ipip", "fou"}},
		{domain.BackendWireGuard, domain.EncapUDP, nil},
		{domain.BackendIPsec, domain.EncapESP, nil},
		{domain.BackendGRE, domain.EncapESP, nil},
	}
	for _, tc := range cases {
		if got := CommittedLinkKernelModules(linkForModules(tc.kind, tc.enc)); !slices.Equal(got, tc.want) {
			t.Fatalf("unexpected committed module selection for %s/%s: %v", tc.kind, tc.enc, got)
		}
	}
}
func TestCommittedRestoreModulesCheckBeforeAfterAndNoSharedUnload(t *testing.T) {
	r := &moduleRestoreRunner{present: map[string]bool{"ip_gre": true}}
	restore := CommittedTunnelModuleRestorer{
		Runner: r,
		Load: func(ctx context.Context, name string) error {
			_, err := r.Run(ctx, "/sbin/modprobe", name)
			return err
		},
		Present: func(name string) (bool, error) { return r.present[name], nil },
		Observe: func(_ context.Context, name string) KernelModuleState {
			if name == "fou" {
				return KernelModuleLoadableInactive
			}
			return KernelModuleUnknown
		},
	}
	link := linkForModules(domain.BackendGRE, domain.EncapFOU)
	if err := restore.Prepare(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.commands, []string{"/sbin/modprobe fou"}) {
		t.Fatalf("existing shared module was modified or wrong argv: %v", r.commands)
	}
	if err := restore.Prepare(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	if len(r.commands) != 1 {
		t.Fatalf("idempotent restore loaded an already present module: %v", r.commands)
	}
	r.present["fou"] = false
	r.fail = "/sbin/modprobe fou"
	err := restore.Prepare(context.Background(), link)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unsafe module failure output: %v", err)
	}
	if r.present["ip_gre"] != true {
		t.Fatal("previously loaded shared driver was changed")
	}
}
func TestCommittedRestoreModulesUnknownCannotMutate(t *testing.T) {
	for _, tc := range []struct {
		label   string
		present func(string) (bool, error)
		observe func(context.Context, string) KernelModuleState
	}{
		{"unknown", func(string) (bool, error) { return false, errors.New("uncertain sysfs") }, func(context.Context, string) KernelModuleState { return KernelModuleLoadableInactive }},
		{"not loadable", func(string) (bool, error) { return false, nil }, func(context.Context, string) KernelModuleState { return KernelModuleUnknown }},
	} {
		t.Run(tc.label, func(t *testing.T) {
			r := &moduleRestoreRunner{present: map[string]bool{}}
			loader := CommittedTunnelModuleRestorer{Runner: r, Present: tc.present, Observe: tc.observe}
			if err := loader.Prepare(context.Background(), linkForModules(domain.BackendIPIP, domain.EncapNative)); err == nil || len(r.commands) != 0 {
				t.Fatalf("unknown on-disk prerequisite attempted modprobe: %v cmds=%v", err, r.commands)
			}
		})
	}
	r := &moduleRestoreRunner{present: map[string]bool{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	loader := CommittedTunnelModuleRestorer{Runner: r, Present: func(string) (bool, error) { return false, nil }, Observe: func(context.Context, string) KernelModuleState { return KernelModuleLoadableInactive }}
	if err := loader.Prepare(ctx, linkForModules(domain.BackendGRE, domain.EncapFOU)); err == nil || len(r.commands) != 0 {
		t.Fatalf("canceled restore mutated host: %v cmds=%v", err, r.commands)
	}
}

func TestCommittedRestoreBuiltInDependenciesSkipModprobe(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     domain.Backend
		mode     domain.Encapsulation
		builtIn  []string
		wantLoad []string
	}{
		{"GRE Native built-in", domain.BackendGRE, domain.EncapNative, []string{"ip_gre"}, nil},
		{"IPIP Native built-in", domain.BackendIPIP, domain.EncapNative, []string{"ipip"}, nil},
		{"GRE FOU base built-in", domain.BackendGRE, domain.EncapFOU, []string{"ip_gre"}, []string{"fou"}},
		{"GRE GUE FOU built-in", domain.BackendGRE, domain.EncapGUE, []string{"fou"}, []string{"ip_gre"}},
		{"IPIP FOU base built-in", domain.BackendIPIP, domain.EncapFOU, []string{"ipip"}, []string{"fou"}},
		{"IPIP GUE FOU built-in", domain.BackendIPIP, domain.EncapGUE, []string{"fou"}, []string{"ipip"}},
		{"IPIP GUE both built-in", domain.BackendIPIP, domain.EncapGUE, []string{"ipip", "fou"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &moduleRestoreRunner{present: map[string]bool{}}
			builtIn := map[string]bool{}
			for _, name := range tc.builtIn {
				builtIn[name] = true
			}
			restorer := CommittedTunnelModuleRestorer{
				Runner:  runner,
				Present: func(name string) (bool, error) { return runner.present[name], nil },
				Observe: func(_ context.Context, name string) KernelModuleState {
					if builtIn[name] {
						return KernelModuleBuiltin
					}
					if runner.present[name] {
						return KernelModuleLoaded
					}
					return KernelModuleLoadableInactive
				},
				Load: func(ctx context.Context, name string) error {
					_, err := runner.Run(ctx, "/sbin/modprobe", name)
					return err
				},
			}
			link := linkForModules(tc.kind, tc.mode)
			if err := restorer.Prepare(context.Background(), link); err != nil {
				t.Fatal(err)
			}
			if err := restorer.Prepare(context.Background(), link); err != nil {
				t.Fatalf("idempotent built-in restore failed: %v", err)
			}
			want := []string{}
			for _, name := range tc.wantLoad {
				want = append(want, "/sbin/modprobe "+name)
			}
			if !slices.Equal(runner.commands, want) {
				t.Fatalf("built-in dependency was loaded or a required load was missed: got=%v want=%v", runner.commands, want)
			}
		})
	}
}
