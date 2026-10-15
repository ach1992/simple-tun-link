package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

func TestOnDemandKernelModuleTargetsUseOnlySelectedBackend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected tunnelOption
		want     []string
	}{
		{"GRE native", tunnelOption{domain.BackendGRE, domain.EncapNative, false}, []string{"ip_gre"}},
		{"GRE FOU", tunnelOption{domain.BackendGRE, domain.EncapFOU, false}, []string{"ip_gre", "fou"}},
		{"GRE GUE", tunnelOption{domain.BackendGRE, domain.EncapGUE, false}, []string{"ip_gre", "fou"}},
		{"IPIP native", tunnelOption{domain.BackendIPIP, domain.EncapNative, false}, []string{"ipip"}},
		{"IPIP FOU", tunnelOption{domain.BackendIPIP, domain.EncapFOU, false}, []string{"ipip", "fou"}},
		{"IPIP GUE", tunnelOption{domain.BackendIPIP, domain.EncapGUE, false}, []string{"ipip", "fou"}},
		{"WireGuard", tunnelOption{domain.BackendWireGuard, domain.EncapUDP, false}, nil},
		{"IPsec", tunnelOption{domain.BackendIPsec, domain.EncapESP, false}, nil},
		{"invalid", tunnelOption{domain.BackendGRE, domain.EncapESP, false}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := plainRequiredModules(tc.selected); !slices.Equal(got, tc.want) {
				t.Fatalf("%v should only require %v", got, tc.want)
			}
		})
	}
}

func TestOnDemandKernelModulePlanningRequiresObservedFailureAndOnDiskProof(t *testing.T) {
	greFOU := tunnelOption{domain.BackendGRE, domain.EncapFOU, false}
	ipipNative := tunnelOption{domain.BackendIPIP, domain.EncapNative, false}
	for _, tc := range []struct {
		name        string
		selected    tunnelOption
		report      linux.CapabilityReport
		loadable    map[string]bool
		want        []string
		shouldBlock bool
	}{
		{"FOU on disk but inactive", greFOU,
			linux.CapabilityReport{
				linux.CapabilityGRENative: {Available: true},
				linux.CapabilityGREFOU:    {ReasonCode: "fou_module_present_probe_failed"},
			}, map[string]bool{"fou": true}, []string{"fou"}, false},
		{"IPIP driver on disk but inactive", ipipNative,
			linux.CapabilityReport{
				linux.CapabilityIPIPNative: {ReasonCode: "ipip_probe_unconfirmed"},
			}, map[string]bool{"ipip": true}, []string{"ipip"}, false},
		{"IPIP FOU with two independently loadable missing drivers", tunnelOption{domain.BackendIPIP, domain.EncapFOU, false},
			linux.CapabilityReport{
				linux.CapabilityIPIPNative: {ReasonCode: "ipip_probe_unconfirmed"},
				linux.CapabilityIPIPFOU:    {ReasonCode: "base_link_probe_unconfirmed"},
				linux.CapabilityGRENative:  {Available: true},
				linux.CapabilityGREFOU:     {ReasonCode: "fou_probe_unconfirmed"},
			}, map[string]bool{"ipip": true, "fou": true}, []string{"ipip", "fou"}, false},
		{"already ready", greFOU,
			linux.CapabilityReport{
				linux.CapabilityGRENative: {Available: true},
				linux.CapabilityGREFOU:    {Available: true},
			}, map[string]bool{"fou": true}, nil, false},
		{"FOU module absent", greFOU,
			linux.CapabilityReport{
				linux.CapabilityGRENative: {Available: true},
				linux.CapabilityGREFOU:    {ReasonCode: "fou_probe_unconfirmed"},
			}, map[string]bool{}, nil, true},
		{"non-module cause", greFOU,
			linux.CapabilityReport{
				linux.CapabilityGRENative: {Available: true},
				linux.CapabilityGREFOU:    {ReasonCode: "permission_denied"},
			}, map[string]bool{"fou": true}, nil, true},
		{"unverified base probe", greFOU,
			linux.CapabilityReport{
				linux.CapabilityGREFOU: {ReasonCode: "fou_probe_unconfirmed"},
			}, map[string]bool{"fou": true}, nil, true},
		{"nil unknown report", greFOU, nil,
			map[string]bool{"fou": true}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			got, reason := plainModuleCandidates(tc.selected, tc.report, func(module string) bool {
				calls = append(calls, module)
				return tc.loadable[module]
			})
			if !slices.Equal(got, tc.want) || (reason != "") != tc.shouldBlock {
				t.Fatalf("modules=%v reason=%q loadable checked=%v; want=%v block=%t",
					got, reason, calls, tc.want, tc.shouldBlock)
			}
			if tc.report == nil && len(calls) != 0 {
				t.Fatal("unknown capability triggered module inventory")
			}
		})
	}
}

type recordedModuleRunner struct {
	calls []string
	fail  string
}

func (r *recordedModuleRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	if cmd == r.fail {
		return linux.CommandResult{}, errors.New("private root subprocess output")
	}
	return linux.CommandResult{}, nil
}

func TestOnDemandKernelLoadingUsesOnlyExactFixedArgsAndStopsAfterFailure(t *testing.T) {
	selected := tunnelOption{domain.BackendGRE, domain.EncapFOU, false}
	runner := &recordedModuleRunner{}
	ctx := context.Background()
	if err := loadSelectedKernelModules(ctx, runner, selected, []string{"ip_gre", "fou"}); err != nil ||
		!slices.Equal(runner.calls, []string{"/sbin/modprobe ip_gre", "/sbin/modprobe fou"}) {
		t.Fatalf("unexpected kernel commands: %v error=%v", runner.calls, err)
	}
	for _, targets := range [][]string{
		{"fou", "fou"}, {"fou", "ip_gre"}, {"ip_gre", "wireguard"},
		{"ipip"}, {"fou;touch /tmp/untrusted"},
	} {
		runner.calls = nil
		if err := loadSelectedKernelModules(ctx, runner, selected, targets); err == nil ||
			len(runner.calls) != 0 {
			t.Fatalf("unexpected potentially unsafe mutation accepted: %v calls=%v", targets, runner.calls)
		}
	}
	runner.calls = nil
	runner.fail = "/sbin/modprobe ip_gre"
	if err := loadSelectedKernelModules(ctx, runner, selected, []string{"ip_gre", "fou"}); err == nil ||
		strings.Contains(err.Error(), "private root subprocess") || len(runner.calls) != 1 {
		t.Fatalf("failure leaked private subprocess data or continued: %v calls=%v", err, runner.calls)
	}
	if err := loadSelectedKernelModules(ctx, runner, tunnelOption{backend: domain.BackendIPsec}, []string{"fou"}); err == nil {
		t.Fatal("IPsec unexpectedly obtained arbitrary modprobe capability")
	}
	if err := loadSelectedKernelModules(ctx, nil, selected, []string{"fou"}); err == nil {
		t.Fatal("nil subprocess runner should be rejected")
	}
}

func TestOnDemandKernelPreparationNeverRunsFromScriptsOrRedirects(t *testing.T) {
	if menuCanPrepareKernel(strings.NewReader("PREPARE\n"), &bytes.Buffer{}) {
		t.Fatal("ordinary stdin or stdout obtained privileged module-loading rights")
	}
	var out, errOut bytes.Buffer
	root := t.TempDir()
	opts := &runtimeOptions{stateRoot: root,
		probeRunner: &guidedTestRunner{capabilityFail: true},
		backends:    nil,
	}
	// This invalid/uncertain GRE native observation cannot load any module
	// without a validated Linux on-disk module AND privileged real TTY.
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader("1\n1\n0\n8\n"), &out, &errOut, opts)
	if code != 0 || !strings.Contains(out.String(), "precheck did not pass") ||
		strings.Contains(out.String(), "PREPARE") ||
		strings.Contains(errOut.String(), "private") {
		t.Fatalf("untrusted menu escaped no-change behavior: code=%d output=%q error=%q", code, out.String(), errOut.String())
	}
}
