package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

func TestMenuPositiveKernelQueryWithInactiveModulesOffersPrecisePrepare(t *testing.T) {
	report := linux.CapabilityReport{
		linux.CapabilityGRENative:  {Available: true},
		linux.CapabilityGREFOU:     {Available: true},
		linux.CapabilityGREGUE:     {Available: true},
		linux.CapabilityIPIPNative: {Available: true},
		linux.CapabilityIPIPFOU:    {Available: true},
		linux.CapabilityIPIPGUE:    {Available: true},
		linux.CapabilityWireGuard:  {Available: true},
	}
	menuRefineModuleReadiness(report, func(module string) linux.KernelModuleState {
		if module == "ipip" || module == "fou" {
			return linux.KernelModuleLoadableInactive
		}
		return linux.KernelModuleLoaded
	})
	if !report[linux.CapabilityGRENative].Available || !report[linux.CapabilityWireGuard].Available ||
		report[linux.CapabilityIPIPNative].Available || report[linux.CapabilityIPIPNative].ReasonCode != "kernel_module_not_loaded" ||
		report[linux.CapabilityGREFOU].Available || report[linux.CapabilityIPIPFOU].Available ||
		report[linux.CapabilityIPIPFOU].ReasonCode != "fou_module_present_probe_failed" {
		t.Fatalf("independent loaded-module evidence was not applied only to affected capabilities: %+v", report)
	}
	selected := tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapFOU}
	modules, reason := plainModuleCandidates(selected, report, func(module string) linux.KernelModuleState {
		if module == "ipip" || module == "fou" {
			return linux.KernelModuleLoadableInactive
		}
		return linux.KernelModuleLoaded
	})
	if reason != "" || !slices.Equal(modules, []string{"ipip", "fou"}) {
		t.Fatalf("failed to offer one scoped IPIP+FOU preparation: %v, %q", modules, reason)
	}
	if label, _ := menuCapabilityHint(report, tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapNative}); label != "[Needs setup]" {
		t.Fatalf("not-loaded module still shown as ready: %q", label)
	}
}

func TestMenuReadinessNeverTurnsUnverifiedObservationsIntoModuleProof(t *testing.T) {
	report := linux.CapabilityReport{
		linux.CapabilityGRENative:  {ReasonCode: "permission_denied"},
		linux.CapabilityIPIPNative: {Available: true},
		linux.CapabilityIPIPFOU:    {Available: true},
	}
	menuRefineModuleReadiness(report, func(string) linux.KernelModuleState { return linux.KernelModuleUnknown })
	if report[linux.CapabilityGRENative].ReasonCode != "permission_denied" ||
		report[linux.CapabilityIPIPNative].Available || report[linux.CapabilityIPIPFOU].Available ||
		report[linux.CapabilityIPIPNative].ReasonCode != "kernel_module_observation_unconfirmed" {
		t.Fatalf("inconclusive module probe changed truthful capability status: %+v", report)
	}
}

func TestMenuSixPlainModesRequireIndependentModuleEvidence(t *testing.T) {
	for _, family := range []struct {
		backend domain.Backend
		base    string
	}{
		{domain.BackendGRE, "ip_gre"},
		{domain.BackendIPIP, "ipip"},
	} {
		for _, mode := range []domain.Encapsulation{domain.EncapNative, domain.EncapFOU, domain.EncapGUE} {
			selected := tunnelOption{backend: family.backend, mode: mode}
			for _, tc := range []struct {
				name        string
				base, fou   linux.KernelModuleState
				queryFailed bool
			}{
				{"loaded and query passes", linux.KernelModuleLoaded, linux.KernelModuleLoaded, false},
				{"loaded but query fails", linux.KernelModuleLoaded, linux.KernelModuleLoaded, true},
				{"base inactive", linux.KernelModuleLoadableInactive, linux.KernelModuleLoaded, false},
				{"FOU inactive", linux.KernelModuleLoaded, linux.KernelModuleLoadableInactive, false},
				{"both inactive positive query", linux.KernelModuleLoadableInactive, linux.KernelModuleLoadableInactive, false},
				{"both inactive failed queries", linux.KernelModuleLoadableInactive, linux.KernelModuleLoadableInactive, true},
				{"base unknown", linux.KernelModuleUnknown, linux.KernelModuleLoadableInactive, false},
				{"FOU unknown", linux.KernelModuleLoadableInactive, linux.KernelModuleUnknown, false},
				{"base artifact absent", linux.KernelModuleUnavailable, linux.KernelModuleLoaded, false},
				{"FOU artifact absent", linux.KernelModuleLoaded, linux.KernelModuleUnavailable, false},
			} {
				t.Run(string(family.backend)+"/"+string(mode)+"/"+tc.name, func(t *testing.T) {
					baseCap := plainBackendCapability(family.backend, domain.EncapNative)
					modeCap := plainBackendCapability(family.backend, mode)
					report := linux.CapabilityReport{
						baseCap: {Available: !tc.queryFailed, ReasonCode: string(family.backend) + "_probe_unconfirmed"},
						modeCap: {Available: !tc.queryFailed, ReasonCode: "base_link_probe_unconfirmed"},
					}
					if mode == domain.EncapNative {
						report[baseCap] = linux.CapabilityStatus{Available: !tc.queryFailed,
							ReasonCode: string(family.backend) + "_probe_unconfirmed"}
					}
					states := map[string]linux.KernelModuleState{
						"ip_gre": linux.KernelModuleLoaded,
						"ipip":   linux.KernelModuleLoaded,
						"fou":    tc.fou,
					}
					states[family.base] = tc.base
					menuRefineModuleReadiness(report, func(name string) linux.KernelModuleState {
						return states[name]
					})
					want := []string{}
					unknown := tc.base == linux.KernelModuleUnknown || tc.base == linux.KernelModuleUnavailable
					if mode != domain.EncapNative {
						unknown = unknown || tc.fou == linux.KernelModuleUnknown || tc.fou == linux.KernelModuleUnavailable
					}
					if !unknown {
						if tc.base == linux.KernelModuleLoadableInactive {
							want = append(want, family.base)
						}
						if mode != domain.EncapNative && tc.fou == linux.KernelModuleLoadableInactive {
							want = append(want, "fou")
						}
					}
					label, _ := menuCapabilityHint(report, selected)
					expectLabel := "[Precheck OK]"
					if unknown || (len(want) == 0 && tc.queryFailed) {
						expectLabel = "[Check needed]"
					} else if len(want) > 0 {
						expectLabel = "[Needs setup]"
					}
					if label != expectLabel {
						t.Fatalf("badge=%s want=%s: report=%+v", label, expectLabel, report)
					}
					var calls []string
					got, reason := plainModuleCandidates(selected, report, func(name string) linux.KernelModuleState {
						calls = append(calls, name)
						return states[name]
					})
					if !slices.Equal(got, want) {
						t.Fatalf("planned %v want %v, reason=%s", got, want, reason)
					}
					if (len(want) > 0 && reason != "") || (label == "[Check needed]" && reason == "") {
						t.Fatalf("incorrect actionable preparation reason: planned=%v reason=%q", got, reason)
					}
				})
			}
		}
	}
}

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
			got, reason := plainModuleCandidates(tc.selected, tc.report, func(module string) linux.KernelModuleState {
				calls = append(calls, module)
				if tc.loadable[module] {
					return linux.KernelModuleLoadableInactive
				}
				return linux.KernelModuleLoaded
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
	load := func(ctx context.Context, name string) error {
		_, err := runner.Run(ctx, "/sbin/modprobe", name)
		return err
	}
	ctx := context.Background()
	if err := loadSelectedKernelModules(ctx, load, selected, []string{"ip_gre", "fou"}); err != nil ||
		!slices.Equal(runner.calls, []string{"/sbin/modprobe ip_gre", "/sbin/modprobe fou"}) {
		t.Fatalf("unexpected kernel commands: %v error=%v", runner.calls, err)
	}
	for _, targets := range [][]string{
		{"fou", "fou"}, {"fou", "ip_gre"}, {"ip_gre", "wireguard"},
		{"ipip"}, {"fou;touch /tmp/untrusted"},
	} {
		runner.calls = nil
		if err := loadSelectedKernelModules(ctx, load, selected, targets); err == nil ||
			len(runner.calls) != 0 {
			t.Fatalf("unexpected potentially unsafe mutation accepted: %v calls=%v", targets, runner.calls)
		}
	}
	runner.calls = nil
	runner.fail = "/sbin/modprobe ip_gre"
	if err := loadSelectedKernelModules(ctx, load, selected, []string{"ip_gre", "fou"}); err == nil ||
		strings.Contains(err.Error(), "private root subprocess") || len(runner.calls) != 1 {
		t.Fatalf("failure leaked private subprocess data or continued: %v calls=%v", err, runner.calls)
	}
	if err := loadSelectedKernelModules(ctx, load, tunnelOption{backend: domain.BackendIPsec}, []string{"fou"}); err == nil {
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

// Package PREPARE consent must not become a second prompt, and the
// separately required Link YES remains unread until actual Create.
func TestPackagePreparationConsentDoesNotConsumeLinkConfirmation(t *testing.T) {
	input := strings.NewReader("YES\n")
	reader := bufio.NewReader(input)
	var output bytes.Buffer
	if !menuConfirmSelectedModules(input, reader, &output, true) {
		t.Fatal("approved same-selection package PREPARE unexpectedly requested another consent")
	}
	if got, err := readMenuAnswer(reader); err != nil || got != "YES" {
		t.Fatalf("module preparation consumed Link confirmation: %q %v", got, err)
	}
	if strings.Contains(output.String(), "Type PREPARE") || !strings.Contains(output.String(), "preceding PREPARE") {
		t.Fatalf("approved module continuation had the wrong prompt: %q", output.String())
	}
	// Without a prior package PREPARE, the helper must request its own
	// exact token. Separately, the installed root-TTY gate rejects streams
	// before even reaching this helper in the real execution path.
	scripted := strings.NewReader("YES\n")
	reader = bufio.NewReader(scripted)
	output.Reset()
	if menuConfirmSelectedModules(scripted, reader, &output, false) ||
		!strings.Contains(output.String(), "Type PREPARE") ||
		menuCanPrepareKernel(scripted, &output) {
		t.Fatalf("absent prior approval bypassed module consent or root-TTY gate: %q", output.String())
	}
}
