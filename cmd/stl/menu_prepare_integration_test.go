//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// A disposable-host simulation exercises the real package and kernel
// preparation functions together. Only privileged OS effect boundaries are
// injected: the production wrappers always use actual installed root/TTY
// attestation, canonical APT planning, maintenance lease and module probes.
type combinedPrepareHost struct {
	t                *testing.T
	selected         tunnelOption
	installed        bool
	loaded           map[string]bool
	lockHeld         bool
	packages         int
	lockCount        int
	loadCalls        []string
	loadableCalls    int
	previewCalls     int
	planChanged      bool
	installError     error
	lockError        error
	invalidateAtLock bool
}

func (h *combinedPrepareHost) report() linux.CapabilityReport {
	gre := h.loaded["ip_gre"]
	ipip := h.loaded["ipip"]
	fou := h.loaded["fou"]
	// Both successful and failed native/UDP queries are independently
	// representable; a base-query failure never hides the FOU dependency.
	return linux.CapabilityReport{
		linux.CapabilityGRENative:  {Available: gre, ReasonCode: "gre_probe_unconfirmed"},
		linux.CapabilityIPIPNative: {Available: ipip, ReasonCode: "ipip_probe_unconfirmed"},
		linux.CapabilityGREFOU:     {Available: gre && fou, ReasonCode: "base_link_probe_unconfirmed"},
		linux.CapabilityGREGUE:     {Available: gre && fou, ReasonCode: "base_link_probe_unconfirmed"},
		linux.CapabilityIPIPFOU:    {Available: ipip && fou, ReasonCode: "base_link_probe_unconfirmed"},
		linux.CapabilityIPIPGUE:    {Available: ipip && fou, ReasonCode: "base_link_probe_unconfirmed"},
	}
}

func (h *combinedPrepareHost) packageOps() menuPackagePreparationOps {
	return menuPackagePreparationOps{
		preview: func(_ context.Context, selection tunnelOption) (selectedPackagePreview, error) {
			if selection != h.selected {
				h.t.Fatalf("package preview used another tunnel selection: %+v", selection)
			}
			h.previewCalls++
			plan := selectedPackagePreview{packages: "iproute2 iptables kmod",
				missing: "iproute2", aptInstall: "iproute2=6.0.0-1"}
			if h.installed {
				plan.missing, plan.aptInstall = "", ""
			}
			if h.planChanged && h.previewCalls == 2 {
				plan.aptInstall = "iproute2=6.0.0-2"
			}
			return plan, nil
		},
		canPrepare: func(io.Reader, io.Writer) bool { return true },
		install: func(_ context.Context, _, _ io.Writer, args ...string) error {
			h.packages++
			expected := []string{"prepare", "--backends", selectedPackageBackends(h.selected),
				"--expected-missing", "iproute2", "--expected-apt-plan", "iproute2=6.0.0-1"}
			if !slices.Equal(args, expected) {
				h.t.Fatalf("unscoped APT plan: %v", args)
			}
			if h.installError != nil {
				return h.installError
			}
			h.installed = true
			return nil
		},
	}
}

func (h *combinedPrepareHost) kernelOps() menuKernelPreparationOps {
	return menuKernelPreparationOps{
		snapshot: func(_ *runtimeOptions) linux.CapabilityReport {
			if !h.installed {
				h.t.Fatal("module check began before successful package verification")
			}
			return h.report()
		},
		canPrepare: func(io.Reader, io.Writer) bool { return true },
		observe: func(_ context.Context, name string) linux.KernelModuleState {
			h.loadableCalls++
			if h.invalidateAtLock && h.lockHeld {
				return linux.KernelModuleUnknown
			}
			if h.loaded[name] {
				return linux.KernelModuleLoaded
			}
			return linux.KernelModuleLoadableInactive
		},
		acquire: func(_ context.Context) (func(), error) {
			h.lockCount++
			if h.lockError != nil {
				return nil, h.lockError
			}
			h.lockHeld = true
			return func() { h.lockHeld = false }, nil
		},
		load: func(_ context.Context, name string) error {
			if !h.lockHeld || !slices.Contains(plainRequiredModules(h.selected), name) || h.loaded[name] {
				h.t.Fatalf("module mutation outside acquired selected-plan lock: %q", name)
			}
			h.loadCalls = append(h.loadCalls, name)
			h.loaded[name] = true
			return nil
		},
	}
}

func newCombinedPrepareHost(t *testing.T, selected tunnelOption) *combinedPrepareHost {
	return &combinedPrepareHost{t: t, selected: selected, loaded: map[string]bool{}}
}

func TestCombinedPackageAndKernelOnePrepareThenRealCreateYES(t *testing.T) {
	selected := tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}
	host := newCombinedPrepareHost(t, selected)
	input := strings.NewReader("PREPARE\n192.0.2.20\n\nn\nYES\nn\n")
	reader := bufio.NewReader(input)
	var stdout, stderr bytes.Buffer

	// This is the real package preview/confirmation/installer/post-install
	// orchestration with a private effect adapter, not a confirmation stub.
	approval := menuPrepareSelectedPackagesWithOps(input, reader, &stdout, &stderr,
		selected, nil, host.packageOps())
	if !approval.approvedFor(selected) || host.packages != 1 || host.previewCalls != 3 {
		t.Fatalf("selected APT PREPARE was not verified: %+v packages=%d previews=%d",
			approval, host.packages, host.previewCalls)
	}
	if !strings.Contains(stdout.String(), "Possible modules") ||
		!strings.Contains(stdout.String(), "ip_gre") {
		t.Fatalf("combined impact was not disclosed before the sole PREPARE: %q", stdout.String())
	}

	// The real module checks, allowlist, re-probe, maintenance acquisition
	// and loader coordination run with simulated host effects.
	ready, report := menuPrepareSelectedModulesWithOps(input, reader, &stdout,
		nil, selected, host.report(), approval, host.kernelOps())
	if !ready || host.lockHeld || host.lockCount != 1 || host.loadableCalls < 2 ||
		!slices.Equal(host.loadCalls, []string{"ip_gre"}) ||
		!report[linux.CapabilityGRENative].Available {
		t.Fatalf("post-APT kernel workflow was not independently attested: ready=%v host=%+v report=%+v",
			ready, host, report)
	}
	if strings.Count(stdout.String(), "Type PREPARE to") != 1 ||
		strings.Contains(stdout.String(), "Type PREPARE to load") {
		t.Fatalf("same selection required a second PREPARE: %q", stdout.String())
	}

	// Follow with the real, existing Create/Engine confirmation path on a
	// state-only fake backend; a skipped or stolen YES fails local creation.
	probe := &guidedTestRunner{}
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(t.TempDir(), probe, fake)
	result := menuCreatePlain(input, reader, &stdout, &stderr, opts,
		selected.backend, selected.mode, false, report)
	if result != 0 || stderr.Len() != 0 || !fake.present[createTestID] ||
		!strings.Contains(stdout.String(), "Type YES to confirm") {
		t.Fatalf("independent Create YES failed: result=%d err=%q out=%q", result, stderr.String(), stdout.String())
	}
}

func TestCombinedPackageAndKernelSingleConsentForEachSelectedDependencyPlan(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selected  tunnelOption
		preloaded []string
		want      []string
	}{
		{"GRE Native", tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}, nil, []string{"ip_gre"}},
		{"IPIP Native", tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapNative}, nil, []string{"ipip"}},
		{"GRE FOU both inactive", tunnelOption{backend: domain.BackendGRE, mode: domain.EncapFOU}, nil, []string{"ip_gre", "fou"}},
		{"GRE GUE both inactive", tunnelOption{backend: domain.BackendGRE, mode: domain.EncapGUE}, nil, []string{"ip_gre", "fou"}},
		{"IPIP FOU both inactive", tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapFOU}, nil, []string{"ipip", "fou"}},
		{"IPIP GUE both inactive", tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapGUE}, nil, []string{"ipip", "fou"}},
		{"GRE FOU base loaded", tunnelOption{backend: domain.BackendGRE, mode: domain.EncapFOU}, []string{"ip_gre"}, []string{"fou"}},
		{"IPIP GUE FOU loaded", tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapGUE}, []string{"fou"}, []string{"ipip"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newCombinedPrepareHost(t, tc.selected)
			for _, module := range tc.preloaded {
				host.loaded[module] = true
			}
			in := strings.NewReader("PREPARE\nYES\n")
			reader := bufio.NewReader(in)
			var out, errs bytes.Buffer
			approval := menuPrepareSelectedPackagesWithOps(in, reader, &out, &errs,
				tc.selected, nil, host.packageOps())
			ready, checked := menuPrepareSelectedModulesWithOps(in, reader, &out, nil,
				tc.selected, host.report(), approval, host.kernelOps())
			capability := plainBackendCapability(tc.selected.backend, tc.selected.mode)
			if !ready || !checked[capability].Available || !slices.Equal(host.loadCalls, tc.want) ||
				host.lockCount != 1 || host.lockHeld {
				t.Fatalf("incomplete plan: ready=%v calls=%v lock=%d report=%v",
					ready, host.loadCalls, host.lockCount, checked)
			}
			if next, err := readMenuAnswer(reader); err != nil || next != "YES" {
				t.Fatalf("kernel preparation consumed separate Create YES: %q %v", next, err)
			}
			if strings.Count(out.String(), "Type PREPARE to") != 1 ||
				!strings.Contains(out.String(), "Possible modules") ||
				strings.Contains(out.String(), "Type PREPARE to load") {
				t.Fatalf("selected plan did not use one package+kernel consent: %q", out.String())
			}
		})
	}
}

func TestCombinedPrepareRejectsPositiveQueryWithoutPostLoadDependencyProof(t *testing.T) {
	selected := tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapFOU}
	host := newCombinedPrepareHost(t, selected)
	host.installed = true
	ops := host.kernelOps()
	originalObserve := ops.observe
	ops.observe = func(ctx context.Context, name string) linux.KernelModuleState {
		if host.loaded["fou"] && name == "fou" {
			return linux.KernelModuleUnknown
		}
		return originalObserve(ctx, name)
	}
	in := strings.NewReader("PREPARE\nYES\n")
	reader := bufio.NewReader(in)
	var out bytes.Buffer
	ready, after := menuPrepareSelectedModulesWithOps(in, reader, &out, nil,
		selected, host.report(), menuPackagePreparation{}, ops)
	if ready || !after[linux.CapabilityIPIPFOU].Available ||
		!slices.Equal(host.loadCalls, []string{"ipip", "fou"}) ||
		strings.Contains(out.String(), "Continuing to tunnel setup") ||
		!strings.Contains(out.String(), "not verified loaded") {
		t.Fatalf("post-load observation was not authoritative: ready=%v loads=%v output=%q",
			ready, host.loadCalls, out.String())
	}
	if next, err := readMenuAnswer(reader); err != nil || next != "YES" {
		t.Fatalf("a failed post-check consumed Create confirmation: %q %v", next, err)
	}
}

func TestCombinedPrepareRejectsStalePlanCancellationAndFailedInstaller(t *testing.T) {
	for _, tc := range []struct {
		name, answers string
		changed       bool
		installError  bool
	}{
		{"changed APT plan", "PREPARE\nYES\n", true, false},
		{"cancelled", "\nYES\n", false, false},
		{"installer failed", "PREPARE\nYES\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}
			host := newCombinedPrepareHost(t, selected)
			host.planChanged = tc.changed
			if tc.installError {
				host.installError = errors.New("simulated APT failed")
			}
			in := strings.NewReader(tc.answers)
			reader := bufio.NewReader(in)
			var out, errs bytes.Buffer
			approval := menuPrepareSelectedPackagesWithOps(in, reader, &out, &errs, selected, nil, host.packageOps())
			wantInstallAttempts := 0
			if tc.installError {
				wantInstallAttempts = 1
			}
			if approval.canContinue || approval.approvedFor(selected) || host.installed ||
				host.packages != wantInstallAttempts {
				t.Fatalf("failed/cancelled preparation obtained authorization: %+v host=%+v", approval, host)
			}
			if strings.Contains(out.String(), "Selected prerequisites verified") ||
				strings.Contains(out.String(), "Continuing to tunnel setup") {
				t.Fatalf("failure/cancellation claimed success: %q", out.String())
			}
		})
	}
}

func TestCombinedPrepareNoCrossSelectionConsentAndReadyModes(t *testing.T) {
	selected := tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}
	host := newCombinedPrepareHost(t, selected)
	in := strings.NewReader("PREPARE\nYES\n")
	reader := bufio.NewReader(in)
	var out, errs bytes.Buffer
	approval := menuPrepareSelectedPackagesWithOps(in, reader, &out, &errs, selected, nil, host.packageOps())
	other := tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapNative}
	if approval.approvedFor(other) {
		t.Fatal("package consent authorized another tunnel selection")
	}
	// Same stream contains YES, not a second PREPARE. It must not authorize
	// module loading on the other backend, regardless of test root-admission.
	fakeOps := host.kernelOps()
	fakeOps.snapshot = func(*runtimeOptions) linux.CapabilityReport {
		return linux.CapabilityReport{linux.CapabilityIPIPNative: {ReasonCode: "ipip_probe_unconfirmed"}}
	}
	ready, _ := menuPrepareSelectedModulesWithOps(in, reader, &out, nil, other,
		fakeOps.snapshot(nil), approval, fakeOps)
	if ready || len(host.loadCalls) != 0 || host.lockCount != 0 ||
		!strings.Contains(out.String(), "Type PREPARE to load") {
		t.Fatalf("other selection reused earlier PREPARE: %q", out.String())
	}

	// Packages already present, module not: one module-only PREPARE, then YES.
	host = newCombinedPrepareHost(t, selected)
	host.installed = true
	in = strings.NewReader("PREPARE\nYES\n")
	reader = bufio.NewReader(in)
	out.Reset()
	approval = menuPrepareSelectedPackagesWithOps(in, reader, &out, &errs, selected, nil, host.packageOps())
	if approval.approvedFor(selected) || !approval.canContinue {
		t.Fatalf("read-only ready package path minted preparation consent: %+v", approval)
	}
	ready, _ = menuPrepareSelectedModulesWithOps(in, reader, &out, nil, selected,
		host.report(), approval, host.kernelOps())
	if !ready || strings.Count(out.String(), "Type PREPARE to load") != 1 {
		t.Fatalf("module-only path missing independent PREPARE: %q", out.String())
	}
	if yes, err := readMenuAnswer(reader); err != nil || yes != "YES" {
		t.Fatalf("module-only PREPARE stole Link YES: %q %v", yes, err)
	}

	// Already-ready package AND kernel: zero unnecessary PREPAREs.
	host = newCombinedPrepareHost(t, selected)
	host.installed = true
	host.loaded["ip_gre"] = true
	in = strings.NewReader("YES\n")
	reader = bufio.NewReader(in)
	out.Reset()
	approval = menuPrepareSelectedPackagesWithOps(in, reader, &out, &errs, selected, nil, host.packageOps())
	ready, _ = menuPrepareSelectedModulesWithOps(in, reader, &out, nil, selected,
		host.report(), approval, host.kernelOps())
	if !ready || strings.Contains(out.String(), "Type PREPARE") || host.lockCount != 0 {
		t.Fatalf("already-ready plan received unnecessary preparation: %q", out.String())
	}
	if yes, err := readMenuAnswer(reader); err != nil || yes != "YES" {
		t.Fatalf("already-ready path stole Link YES: %q %v", yes, err)
	}
}

func TestCombinedPrepareReadOnlyGateLockAndRevalidation(t *testing.T) {
	selected := tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}
	// The production gate cannot be replaced by scripted input.
	host := newCombinedPrepareHost(t, selected)
	ops := host.packageOps()
	ops.canPrepare = menuCanUpdateNow
	in := strings.NewReader("PREPARE\nYES\n")
	reader := bufio.NewReader(in)
	var out, errs bytes.Buffer
	approval := menuPrepareSelectedPackagesWithOps(in, reader, &out, &errs, selected, nil, ops)
	if approval.approvedFor(selected) || host.packages != 0 || host.previewCalls != 1 {
		t.Fatalf("redirected input authorized APT through real gate: %+v", approval)
	}

	for _, tc := range []struct {
		name       string
		lockFails  bool
		revalidate bool
	}{
		{"maintenance unavailable", true, false},
		{"loadability changed under lock", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newCombinedPrepareHost(t, selected)
			host.installed = true
			if tc.lockFails {
				host.lockError = fmt.Errorf("simulated lock busy")
			}
			host.invalidateAtLock = tc.revalidate
			in := strings.NewReader("PREPARE\nYES\n")
			reader := bufio.NewReader(in)
			out.Reset()
			ready, _ := menuPrepareSelectedModulesWithOps(in, reader, &out, nil,
				selected, host.report(), menuPackagePreparation{}, host.kernelOps())
			if ready || host.lockHeld || len(host.loadCalls) != 0 || host.lockCount != 1 {
				t.Fatalf("unverified conditions loaded kernel driver: ready=%v host=%+v", ready, host)
			}
			if strings.Contains(out.String(), "Continuing to tunnel setup") {
				t.Fatalf("failed module preparation claimed success: %q", out.String())
			}
		})
	}
}
