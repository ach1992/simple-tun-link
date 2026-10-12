package ipip

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type moduleFailureRunner struct {
	fakeRunner
	failureCommand string
	calls          []string
}

func (r *moduleFailureRunner) Run(ctx context.Context, command string, args ...string) (linux.CommandResult, error) {
	commandLine := strings.Join(args, " ")
	r.calls = append(r.calls, commandLine)
	if commandLine == r.failureCommand {
		return linux.CommandResult{Stderr: []byte("PSK=MUST_NEVER_LEAK")}, errors.New("failed to inspect kernel inventory")
	}
	return r.fakeRunner.Run(ctx, command, args...)
}

func TestIPIPMissingKernelModuleReasonRemainsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		module  string
		isKnown bool
	}{
		{name: "FOU module not loaded", command: "-json fou show", module: "fou", isKnown: true},
		{name: "native module not loaded", command: "-details -json link show type ipip", module: "ipip", isKnown: true},
		{name: "unknown module inventory", command: "-json fou show", module: "", isKnown: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := testLink()
			link.Encapsulation = domain.EncapFOU

			runner := &moduleFailureRunner{
				fakeRunner: fakeRunner{link: link}, failureCommand: tc.command,
			}
			backend, err := New(Options{
				Runner:   runner,
				Routes:   fakeRoute{linux.Route{Peer: link.Underlay.Peer, Source: link.Underlay.Local, Device: "eth0"}},
				Firewall: &fakeFirewall{}, Collisions: fakeCollisions{},
				ModuleProbe: func(_ context.Context, module string) bool { return module == tc.module },
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = backend.Inspect(context.Background(), link)
			if err == nil {
				t.Fatal("failed kernel inventory was accepted as empty")
			}
			public := stlerr.Public(err)
			if tc.isKnown && (public.ReasonCode != "kernel_module_not_loaded" || public.Code != stlerr.CodeInspect) {
				t.Fatalf("known unloaded module lost reason: %+v", public)
			}
			if !tc.isKnown && public.ReasonCode == "kernel_module_not_loaded" {
				t.Fatalf("unknown inventory turned into proven missing-module: %+v", public)
			}
			status, err := backend.Capability(context.Background(), link)
			if err != nil || status.Available || (status.ReasonCode == "kernel_module_not_loaded") != tc.isKnown {
				t.Fatalf("capability mismatch: %+v %v", status, err)
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "modprobe") || strings.Contains(call, "add ") ||
					strings.Contains(call, "del ") || strings.Contains(call, "set ") {
					t.Fatalf("read-only inspection mutated host: %q", call)
				}
			}
		})
	}
}
