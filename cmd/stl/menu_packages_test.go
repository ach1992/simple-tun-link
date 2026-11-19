package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// The embedded script is a SOURCE-IDENTICAL snapshot, never a separately
// maintained implementation or an uncontrolled download at root TTY.
func TestCanonicalInstallerEmbeddedSourceIdentity(t *testing.T) {
	expected, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, canonicalInstaller) {
		t.Fatal("embedded package installer drifted from canonical source; resync before packaging")
	}
	if err := menuEmbeddedInstallerSanity(); err != nil {
		t.Fatal(err)
	}
}
func TestSelectedPackagePlanIsTypedAndReadOnly(t *testing.T) {
	for _, tc := range []struct {
		sel  tunnelOption
		want string
	}{
		{tunnelOption{backend: domain.BackendGRE, mode: domain.EncapFOU}, "native"},
		{tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapNative}, "native"},
		{tunnelOption{backend: domain.BackendWireGuard, mode: domain.EncapUDP}, "native,wireguard"},
		{tunnelOption{backend: domain.BackendIPsec, mode: domain.EncapESP}, "native,ipsec"},
		{tunnelOption{backend: domain.BackendMASQUE, mode: domain.EncapTLS}, "masque"},
	} {
		if got := selectedPackageBackends(tc.sel); got != tc.want {
			t.Fatalf("%s: %s", tc.want, got)
		}
		// This test verifies selector and read-only canonical plan
		// correctness, not a wall-clock SLA. On heavily loaded CI runners,
		// the distro signature/index resolver can exceed production's
		// 12-second UX budget. Do not let host load make a correctness test
		// flaky; production still fails closed at its 12-second boundary.
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		plan, err := readSelectedPackagePreview(ctx, tc.sel)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", tc.want, err)
		}
		if tc.want == "masque" {
			if plan.packages != "iproute2" {
				t.Fatalf("MASQUE must not require unrelated packages: %+v", plan)
			}
		} else if !strings.Contains(plan.packages, "iproute2 iptables kmod") {
			t.Fatalf("missing baseline requirements: %+v", plan)
		}
	}
	if selectedPackageBackends(tunnelOption{}) != "" {
		t.Fatal("invalid selector gained package provisioning")
	}
}
func TestUnprivilegedOrRedirectedPackagePreviewCannotConsumeCreateInput(t *testing.T) {
	var output, errors bytes.Buffer
	reader := strings.NewReader("PREPARE\nALLOW-IPSEC-PACKAGES\n")
	plan := tunnelOption{backend: domain.BackendIPsec, mode: domain.EncapESP}
	// A read-only inventory is permitted, but root operation is not.
	// Redirected/scripted input cannot authorize managed IPsec preparation;
	// a false return requests root-TTY PREPARE, never a privileged effect.
	result := menuPrepareSelectedPackages(reader, nil, &output, &errors, plan, nil)
	if result.canContinue || result.approvedSelectedPlan {
		t.Fatalf("redirected IPsec input obtained preparation consent: %+v", result)
	}
	if strings.Contains(output.String(), "Canonical installer verifying") ||
		strings.Contains(output.String(), "Selected packages now pass") {
		t.Fatalf("scripted package preview claimed mutation or success: %q", output.String())
	}
	if errors.Len() != 0 {
		t.Fatalf("leaked error: %q", errors.String())
	}
}

// These errors are safe authored categories, not raw APT output. Their
// guidance is advisory; a failed package preview never authorizes PREPARE.
func TestSelectedPackagePreviewErrorsAreActionableAndRedacted(t *testing.T) {
	tests := []struct {
		name, stderr, reason, check string
		ctxErr                      error
	}{
		{"timeout", "", "requirements_check_timeout", "host load", context.DeadlineExceeded},
		{"APT observed lock wait timeout", "stl installer [INFO]: Another APT process holds the lists lock; waiting 5 seconds before retry 2/12.\nE: secret private package location", "apt_lists_lock_wait_timeout", "Do not delete lock files", context.DeadlineExceeded},
		{"raw APT lock word without canonical observation", "E: another APT process holds the lists lock", "requirements_check_timeout", "host load", context.DeadlineExceeded},
		{"interrupted", "", "requirements_check_interrupted", "Reopen Create tunnel", context.Canceled},
		{"unsupported package manager", "stl installer [FAILED]: unsupported package-manager distribution: fedora 42; this installer currently integrates with Debian/Ubuntu APT", "unsupported_or_unverified_os", "/etc/os-release", nil},
		{"invalid Debian release metadata", "stl installer [FAILED]: invalid Debian version: secret", "unsupported_or_unverified_os", "/etc/os-release", nil},
		{"invalid Ubuntu release metadata", "stl installer [FAILED]: invalid Ubuntu version: secret", "unsupported_or_unverified_os", "/etc/os-release", nil},
		{"OS identity unreadable", "stl installer [FAILED]: OS release file is unreadable: secret", "unsupported_or_unverified_os", "/etc/os-release", nil},
		{"APT trust", "stl installer [FAILED]: APT candidate InRelease has no valid distribution archive signature or contains an invalid signature: secret", "apt_source_trust_unverified", "apt-cache policy", nil},
		{"missing gpgv", "stl installer [FAILED]: cannot verify distribution archive signatures; official distro gpgv is missing.", "distro_signature_verifier_missing", "gpgv", nil},
		{"APT plan", "stl installer [FAILED]: APT cannot resolve the complete selected dependency plan: secret", "apt_dependency_plan_unverified", "apt-cache policy", nil},
		{"APT lists lock", "stl installer [FAILED]: APT lists lock remained busy after bounded waiting; secret", "apt_lists_lock_busy", "Do not delete lock files", nil},
		{"APT removal proposal", "stl installer [FAILED]: APT plan would remove packages; secret", "apt_plan_would_modify_installed_packages", "do not force this plan", nil},
		{"APT upgrade proposal", "stl installer [FAILED]: APT plan would upgrade an installed package; secret", "apt_plan_would_modify_installed_packages", "do not force this plan", nil},
		{"dpkg", "stl installer [FAILED]: dpkg has unfinished package configuration: secret", "dpkg_transaction_incomplete", "dpkg --audit", nil},
		{"untrusted raw stderr", "stl installer [FAILED]: private-token-DO-NOT-PRINT", "requirements_inventory_unverified", "/etc/os-release", nil},
		{"raw APT cannot spoof OS failure", "E: failed reading invalid Debian version in private source", "requirements_inventory_unverified", "/etc/os-release", nil},
		{"raw APT cannot spoof dpkg state", "E: dpkg has unfinished package configuration hidden in a package description", "requirements_inventory_unverified", "/etc/os-release", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			failure := packageInventoryFailure(tc.stderr, tc.ctxErr)
			reason, next := packageInventoryGuidance(failure)
			if reason != tc.reason || !strings.Contains(next, tc.check) ||
				strings.Contains(failure.Error()+reason+next, "secret") ||
				strings.Contains(failure.Error()+reason+next, "private-token-DO-NOT-PRINT") {
				t.Fatalf("unsafe or inaccurate guidance: failure=%q reason=%q next=%q", failure, reason, next)
			}
		})
	}
	// Only the known authored reason may reach the menu, not an arbitrary
	// subprocess error or a hidden credential in its text.
	var out, errOut bytes.Buffer
	var installs int
	preview := func(context.Context, tunnelOption) (selectedPackagePreview, error) {
		return selectedPackagePreview{}, packageInventoryFailure("stl installer [FAILED]: APT candidate InRelease secret-private-token", nil)
	}
	ops := menuPackagePreparationOps{
		preview:    preview,
		canPrepare: func(io.Reader, io.Writer) bool { t.Fatal("preview failure attempted privilege gate"); return false },
		install: func(context.Context, io.Writer, io.Writer, ...string) error {
			installs++
			return nil
		},
	}
	result := menuPrepareSelectedPackagesWithOps(strings.NewReader("PREPARE\n"), nil, &out, &errOut,
		tunnelOption{backend: domain.BackendIPsec, mode: domain.EncapESP}, nil, ops)
	if result.canContinue || result.approvedSelectedPlan || installs != 0 ||
		!strings.Contains(out.String(), "apt_source_trust_unverified") ||
		!strings.Contains(out.String(), "apt-cache policy") ||
		!strings.Contains(out.String(), "no preparation attempted") ||
		strings.Contains(out.String()+errOut.String(), "secret-private-token") {
		t.Fatalf("failed preview was unsafe: result=%+v installs=%d out=%q err=%q", result, installs, out.String(), errOut.String())
	}
}

func TestMalformedReadOnlyInventoryShowsSafeMenuGuidanceWithoutPREPARE(t *testing.T) {
	const private = "PRIVATE_APT_REPOSITORY_AUTH_TOKEN_NEVER_PRINT"
	var out, errOut bytes.Buffer
	previewRuns := 0
	runner := func(_ context.Context, stdout, stderr io.Writer, args ...string) error {
		previewRuns++
		if !slices.Equal(args, []string{"requirements", "--backends", "native,ipsec"}) {
			t.Fatalf("read-only check executed an unexpected operation: %q", args)
		}
		_, _ = io.WriteString(stderr, "E: private APT URL with "+private+"\n")
		_, err := io.WriteString(stdout, "distribution=debian\nversion=13\n"+
			"selected_backends=native,ipsec\npackages=iproute2 iptables kmod\n"+
			"missing_packages=iproute2\napt_install=iproute2=6.0.0-1\n"+
			"apt_install_sha256=not-a-valid-hash\nnotice="+private+"\n")
		return err
	}
	ops := menuPackagePreparationOps{
		preview: func(ctx context.Context, selected tunnelOption) (selectedPackagePreview, error) {
			return readSelectedPackagePreviewWithRunner(ctx, selected, runner)
		},
		canPrepare: func(io.Reader, io.Writer) bool {
			t.Fatal("malformed read-only inventory entered privilege admission")
			return false
		},
		install: func(context.Context, io.Writer, io.Writer, ...string) error {
			t.Fatal("malformed read-only inventory reached installer PREPARE")
			return nil
		},
	}
	input := strings.NewReader("PREPARE\nYES\n")
	result := menuPrepareSelectedPackagesWithOps(input, nil, &out, &errOut,
		tunnelOption{backend: domain.BackendIPsec, mode: domain.EncapESP}, nil, ops)
	if previewRuns != 1 || result.canContinue || result.approvedSelectedPlan ||
		!strings.Contains(out.String(), "requirements_inventory_contract_invalid") ||
		!strings.Contains(out.String(), "Do not start PREPARE") ||
		!strings.Contains(out.String(), "no preparation attempted") ||
		strings.Contains(out.String()+errOut.String(), private) ||
		errOut.Len() != 0 {
		t.Fatalf("invalid inventory exposed private details or authorized PREPARE: runs=%d result=%+v out=%q stderr=%q",
			previewRuns, result, out.String(), errOut.String())
	}
	remaining, err := io.ReadAll(input)
	if err != nil || string(remaining) != "PREPARE\nYES\n" {
		t.Fatalf("read-only failure consumed a destructive confirmation: %q %v", remaining, err)
	}
}

// The live canonical installer uses stable uppercase APT stage identifiers.
// Their operator projections must remain actionable and redact raw stderr.
func TestCanonicalAPTPreviewFailuresUseCurrentInstallerReasons(t *testing.T) {
	tests := []struct {
		name, failure, reason, next string
	}{
		{"dependency resolution", "APT_DEPENDENCY_PLAN failed; missing selected packages: iptables.", "apt_dependency_plan_unverified", "apt-cache policy"},
		{"no signed index mapping", "no APT package index mapping available", "apt_dependency_plan_unverified", "apt-cache policy"},
		{"removal proposal", "APT plan would remove packages; no changes allowed", "apt_plan_would_modify_installed_packages", "apt-cache policy"},
		{"upgrade proposal", "APT plan would upgrade an installed package; review separately", "apt_plan_would_modify_installed_packages", "apt-cache policy"},
		{"lists lock busy", "APT lists lock remained busy after bounded waiting; let the other apt-get finish", "apt_lists_lock_busy", "lock files"},
		{"index refresh failure", "APT_INDEX_REFRESH failed; missing selected packages: iproute2", "apt_index_unverified", "signed APT repositories"},
		{"foreign dependency", "APT selected a dependency outside the distribution archive; no changes allowed", "apt_source_trust_unverified", "signature"},
		{"untrusted source config", "APT sources explicitly bypass signature verification", "apt_source_trust_unverified", "signature"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			failure := "stl installer [FAILED]: " + tc.failure + " " + operatorSensitiveSentinel
			reason, next := packageInventoryGuidance(packageInventoryFailure(failure, nil))
			if reason != tc.reason || !strings.Contains(next, tc.next) ||
				strings.Contains(reason+next, operatorSensitiveSentinel) {
				t.Fatalf("misclassified canonical preview failure: got reason=%q next=%q", reason, next)
			}
		})
	}
}

// The read-only preview must never confuse long APT diagnostics with an
// oversized dependency plan or hide the locally observed failure reason.
func TestSelectedPackagePreviewStreamsLongDiagnosticsAndVerifiesPlan(t *testing.T) {
	const sensitive = "temporary-private-apt-url-do-not-print"
	realPlan := "iproute2=6.0.0-1"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(realPlan)))
	inventory := "distribution=debian\nversion=13\nselected_backends=native\n" +
		"packages=iproute2 iptables kmod\nmissing_packages=iproute2\n" +
		"apt_install=" + realPlan + "\napt_install_sha256=" + digest + "\n"
	verbose := strings.Repeat(sensitive, 6000) + "\n"
	runner := func(_ context.Context, stdout, stderr io.Writer, _ ...string) error {
		if _, err := io.WriteString(stderr, verbose); err != nil {
			return err
		}
		_, err := io.WriteString(stdout, inventory)
		return err
	}
	var tty bytes.Buffer
	plan, err := readSelectedPackagePreviewWithDiagnostics(context.Background(),
		tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}, runner, &tty)
	if err != nil || plan.aptInstall != realPlan || plan.aptDigest != digest ||
		tty.String() != verbose {
		t.Fatalf("long read-only diagnostics were not retained/forwarded: plan=%+v err=%v", plan, err)
	}
	for _, tc := range []struct{ name, inventory string }{
		{"wrong digest", strings.Replace(inventory, digest, strings.Repeat("f", 64), 1)},
		{"duplicate field", inventory + "apt_install=" + realPlan + "\n"},
		{"unexpected field", inventory + "command=run me\n"},
		{"selected backend drift", strings.Replace(inventory, "selected_backends=native", "selected_backends=ipsec", 1)},
		{"missing required fields", strings.Replace(inventory, "distribution=debian\n", "", 1)},
		{"missing declared dependency", strings.Replace(inventory, "apt_install="+realPlan, "apt_install=", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := func(_ context.Context, stdout, stderr io.Writer, _ ...string) error {
				_, err := io.WriteString(stdout, tc.inventory)
				return err
			}
			if _, err := readSelectedPackagePreviewWithRunner(context.Background(),
				tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}, fake); err == nil {
				t.Fatal("malformed read-only inventory authorized PREPARE")
			} else if reason, next := packageInventoryGuidance(err); reason != "requirements_inventory_contract_invalid" ||
				!strings.Contains(next, "provenance/version") || !strings.Contains(next, "Do not start PREPARE") {
				t.Fatalf("malformed inventory lost actionable own-contract guidance: reason=%q next=%q", reason, next)
			}
		})
	}
	runnerFailed := func(_ context.Context, stdout, stderr io.Writer, _ ...string) error {
		_, _ = io.WriteString(stderr, verbose)
		_, _ = io.WriteString(stderr, "stl installer [FAILED]: APT plan would remove packages; no changes allowed\n")
		return errors.New("APT exited with sensitive cause " + sensitive)
	}
	_, err = readSelectedPackagePreviewWithRunner(context.Background(),
		tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}, runnerFailed)
	reason, next := packageInventoryGuidance(err)
	if reason != "apt_plan_would_modify_installed_packages" || strings.Contains(reason+next, sensitive) {
		t.Fatalf("failed preview lost safe typed reason: %s %s", reason, next)
	}
}

// Actual dependency lists, not arbitrary progress messages, determine the
// inventory size. Spooling must accept a plan longer than the former 32KiB.
func TestSelectedPackagePreviewLargePlanSpoolsToPrivateFile(t *testing.T) {
	terms := []string{"iproute2=6.0.0-1"}
	for i := 0; i < 3600; i++ {
		terms = append(terms, fmt.Sprintf("dep-%05d=1.0.0", i))
	}
	large := strings.Join(terms, " ")
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(large)))
	runner := func(_ context.Context, stdout, stderr io.Writer, _ ...string) error {
		_, err := io.WriteString(stdout, "distribution=debian\nversion=13\nselected_backends=native\n"+
			"packages=iproute2 iptables kmod\nmissing_packages=iproute2\n"+
			"apt_install="+large+"\napt_install_sha256="+digest+"\n")
		return err
	}
	got, err := readSelectedPackagePreviewWithRunner(context.Background(),
		tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}, runner)
	if err != nil || got.aptDigest != digest || got.aptInstall != large {
		t.Fatalf("legitimate long dependency inventory rejected: %v", err)
	}
}

// Bash inherits BASH_ENV for a noninteractive script unless its execution
// environment is sanitized. The embedded privileged invocation MUST NOT
// interpret inherited shell startup code before the canonical installer.
func TestCanonicalPackageInstallerDoesNotSourceInheritedBashEnv(t *testing.T) {
	tmp := t.TempDir()
	hook := tmp + "/injected.sh"
	if err := os.WriteFile(hook, []byte("touch "+tmp+"/WRONG\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", hook)
	t.Setenv("ENV", hook)
	t.Setenv("PATH", tmp)
	// This test checks environment isolation, not APT inventory latency.
	// Under a loaded Dev host, an otherwise successful read-only package
	// inventory can exceed five seconds without executing BASH_ENV.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := readSelectedPackagePreview(ctx, tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}); err != nil {
		t.Fatalf("sanitized canonical plan failed: %v", err)
	}
	if _, err := os.Stat(tmp + "/WRONG"); !os.IsNotExist(err) {
		t.Fatalf("untrusted shell environment executed before installer: %v", err)
	}
}

func TestMissingStrongSwanPackagePlanCannotAuthorizeAPT(t *testing.T) {
	for _, tc := range []struct {
		missing string
		manual  bool
	}{
		{"iptables charon-systemd strongswan-swanctl", true},
		{"libstrongswan-standard-plugins", true},
		{"wireguard-tools", false},
		{"iproute2 kmod", false},
		{"", false},
	} {
		if got := missingStrongSwanPackages(tc.missing); got != tc.manual {
			t.Fatalf("missing=%q manual=%t expected=%t", tc.missing, got, tc.manual)
		}
	}
}

func TestBlockedIPsecWarningPreservesEarlierPackageAndServiceEffects(t *testing.T) {
	for _, attempted := range []bool{false, true} {
		var out bytes.Buffer
		menuIPsecBlockedNotice(&out, attempted)
		body := out.String()
		if !strings.Contains(body, "may have changed") && !strings.Contains(body, "may have started or enabled") {
			t.Fatalf("unverified service/package effects were concealed: %q", body)
		}
		if strings.Contains(body, "No keys, services, packages or tunnels were changed") ||
			strings.Contains(body, "No packages or services changed") {
			t.Fatalf("false no-effect assertion after possible APT: %q", body)
		}
		if !strings.Contains(body, "No Link or keys") && !strings.Contains(body, "No IPsec Link or keys") {
			t.Fatalf("failure no-Link semantics missing: %q", body)
		}
	}
}

// A missing MASQUE dependency must direct the operator to authenticated
// installed-root PREPARE instead of generating an unusable credential pair.
func TestMASQUEMissingPackageCannotSkipPreparation(t *testing.T) {
	selected := tunnelOption{backend: domain.BackendMASQUE, mode: domain.EncapTLS}
	ops := menuPackagePreparationOps{
		preview: func(context.Context, tunnelOption) (selectedPackagePreview, error) {
			return selectedPackagePreview{packages: "iproute2", missing: "iproute2", aptInstall: "iproute2=1", aptDigest: strings.Repeat("a", 64)}, nil
		},
		canPrepare: func(io.Reader, io.Writer) bool { return false },
		install: func(context.Context, io.Writer, io.Writer, ...string) error {
			t.Fatal("attempted unattended APT")
			return nil
		},
	}
	var out, errOut bytes.Buffer
	input := strings.NewReader("")
	got := menuPrepareSelectedPackagesWithOps(input, nil, &out, &errOut, selected, nil, ops)
	if got.canContinue || !strings.Contains(out.String(), "iproute2") ||
		!strings.Contains(out.String(), "sudo stl menu") {
		t.Fatalf("missing MASQUE prerequisite was not explained: %+v, %s", got, out.String())
	}
}
