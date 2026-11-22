package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// A real runner may lack optional packages, signed APT indexes or the
	// privilege needed for a live netlink check. Those are valid operator
	// outcomes, not failures of selection and inventory parsing. Use the
	// REAL embedded canonical installer with its read-only OS fixture,
	// then add an explicitly empty APT inventory as a test-only contract.
	// Separate selected-APT guest E2E verifies live resolver behavior.
	osFixture := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(osFixture, []byte("ID=debian\nVERSION_ID=\"13\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := func(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
		var inventory bytes.Buffer
		exactArgs := append(append([]string(nil), args...), "--os-release-file", osFixture)
		if err := runEmbeddedInstaller(ctx, &inventory, stderr, exactArgs...); err != nil {
			return err
		}
		_, err := io.WriteString(stdout, inventory.String()+"missing_packages=\napt_install=\napt_install_sha256="+
			fmt.Sprintf("%x", sha256.Sum256(nil))+"\n")
		return err
	}
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
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		plan, err := readSelectedPackagePreviewWithRunner(ctx, tc.sel, runner)
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
		{"interrupted", "", "requirements_check_interrupted", "Reopen Create tunnel", context.Canceled},
		{"unsupported package manager", "stl installer [FAILED]: unsupported package-manager distribution: fedora 42; this installer currently integrates with Debian/Ubuntu APT", "unsupported_or_unverified_os", "/etc/os-release", nil},
		{"invalid Debian release metadata", "stl installer [FAILED]: invalid Debian version: secret", "unsupported_or_unverified_os", "/etc/os-release", nil},
		{"invalid Ubuntu release metadata", "stl installer [FAILED]: invalid Ubuntu version: secret", "unsupported_or_unverified_os", "/etc/os-release", nil},
		{"OS identity unreadable", "stl installer [FAILED]: OS release file is unreadable: secret", "unsupported_or_unverified_os", "/etc/os-release", nil},
		{"APT trust", "stl installer [FAILED]: APT candidate InRelease has no valid distribution archive signature or contains an invalid signature: secret", "apt_source_trust_unverified", "apt-cache policy", nil},
		{"installed broken dependency", "stl installer [FAILED]: installed selected prerequisite iproute2 is unusable; inspect/repair its actual tool or package without automatic reinstall/upgrade. No APT attempted.", "installed_prerequisite_unusable", "will not reinstall or upgrade", nil},
		{"missing gpgv", "stl installer [FAILED]: cannot verify distribution archive signatures; official distro gpgv is missing.", "distro_signature_verifier_missing", "gpgv", nil},
		{"APT plan", "stl installer [FAILED]: APT cannot resolve the complete selected dependency plan: secret", "apt_dependency_plan_unverified", "apt-cache policy", nil},
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

func TestMASQUEPackagePreviewFailureBlocksGuidedContinuation(t *testing.T) {
	const secret = "PRIVATE_SOURCE_URL_DO_NOT_DISPLAY"
	selected := tunnelOption{backend: domain.BackendMASQUE, mode: domain.EncapTLS}
	for _, tc := range []struct {
		name, reason string
		failure      func(context.Context) error
	}{
		{"invalid inventory", "requirements_inventory_contract_invalid", func(context.Context) error {
			return invalidPackageInventory()
		}},
		{"timeout", "requirements_check_timeout", func(context.Context) error {
			return packageInventoryFailure("", context.DeadlineExceeded)
		}},
		{"source trust", "apt_source_trust_unverified", func(context.Context) error {
			return packageInventoryFailure("stl installer [FAILED]: APT candidate InRelease is missing or untrusted: "+secret, nil)
		}},
		{"unknown failure", "requirements_inventory_unverified", func(context.Context) error {
			return errors.New("unknown private APT failure " + secret)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previews, preparations := 0, 0
			ops := menuPackagePreparationOps{
				preview: func(ctx context.Context, got tunnelOption) (selectedPackagePreview, error) {
					if got != selected {
						t.Fatalf("unexpected package selection: %+v", got)
					}
					previews++
					return selectedPackagePreview{}, tc.failure(ctx)
				},
				canPrepare: func(io.Reader, io.Writer) bool {
					t.Fatal("invalid MASQUE preview requested privilege admission")
					return false
				},
				install: func(context.Context, io.Writer, io.Writer, ...string) error {
					preparations++
					t.Fatal("invalid MASQUE preview attempted package installation")
					return nil
				},
			}
			input := strings.NewReader("PREPARE\nYES\n")
			reader := bufio.NewReader(input)
			var out, errOut bytes.Buffer
			result := menuPrepareSelectedPackagesWithOps(input, reader, &out, &errOut,
				selected, nil, ops)
			if result.canContinue || result.approvedSelectedPlan ||
				previews != 1 || preparations != 0 ||
				!strings.Contains(out.String(), tc.reason) ||
				!strings.Contains(out.String(), "no preparation attempted") ||
				strings.Contains(out.String()+errOut.String(), secret) {
				t.Fatalf("failed MASQUE preview passed Create/Import gate: result=%+v previews=%d preparations=%d out=%q err=%q",
					result, previews, preparations, out.String(), errOut.String())
			}
			remaining, err := io.ReadAll(reader)
			if err != nil || string(remaining) != "PREPARE\nYES\n" {
				t.Fatalf("failed preview consumed Create/Import consent: %q %v", remaining, err)
			}
		})
	}
	// The established advisory behavior of non-IPsec/non-MASQUE
	// backends remains unchanged; they do not gain PREPARE authority.
	for _, backend := range []domain.Backend{domain.BackendGRE, domain.BackendWireGuard} {
		var out, errOut bytes.Buffer
		ops := menuPackagePreparationOps{
			preview: func(context.Context, tunnelOption) (selectedPackagePreview, error) {
				return selectedPackagePreview{}, invalidPackageInventory()
			},
			canPrepare: func(io.Reader, io.Writer) bool {
				t.Fatal("ordinary failed preview attempted privilege admission")
				return false
			},
			install: func(context.Context, io.Writer, io.Writer, ...string) error {
				t.Fatal("ordinary failed preview attempted installer")
				return nil
			},
		}
		result := menuPrepareSelectedPackagesWithOps(strings.NewReader("PREPARE\nYES\n"), nil,
			&out, &errOut, tunnelOption{backend: backend, mode: domain.EncapNative}, nil, ops)
		if !result.canContinue || result.approvedSelectedPlan {
			t.Fatalf("ordinary backend %s advisory policy changed: %+v", backend, result)
		}
	}
}

func TestMASQUEGuidedCreateStopsBeforeIdentityAfterPreviewFailure(t *testing.T) {
	root := t.TempDir()
	probe := &guidedTestRunner{}
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, probe, fake)
	calls := 0
	opts.packagePreview = func(_ context.Context, selected tunnelOption) (selectedPackagePreview, error) {
		if selected.backend != domain.BackendMASQUE {
			t.Fatalf("wrong guided choice: %+v", selected)
		}
		calls++
		return selectedPackagePreview{}, invalidPackageInventory()
	}
	input := strings.NewReader("9\n0\n")
	var out, errOut bytes.Buffer
	if code := menuCreate(input, bufio.NewReader(input), &out, &errOut, opts); code != 0 ||
		calls != 1 || strings.Contains(out.String(), "Create / MASQUE CONNECT-IP") ||
		!strings.Contains(out.String(), "requirements_inventory_contract_invalid") {
		t.Fatalf("guided MASQUE Create bypassed failed requirements: code=%d calls=%d out=%q err=%q",
			code, calls, out.String(), errOut.String())
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("failed preview staged MASQUE Link/credential files: %v %v", entries, err)
	}
}

func TestSelectedPackagePreviewDigestContractAndMASQUEPreparation(t *testing.T) {
	const selectedPlan = "iproute2=6.0.0-1"
	selected := tunnelOption{backend: domain.BackendMASQUE, mode: domain.EncapTLS}
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(selectedPlan)))
	emptySHA := fmt.Sprintf("%x", sha256.Sum256(nil))
	ready := "distribution=debian\nversion=13\nselected_backends=masque\npackages=iproute2\nmissing_packages=\napt_install=\napt_install_sha256=" + emptySHA + "\n"
	missing := "distribution=debian\nversion=13\nselected_backends=masque\npackages=iproute2\nmissing_packages=iproute2\napt_install=" + selectedPlan + "\napt_install_sha256=" + sha + "\n"
	read := func(ctx context.Context, raw string) (selectedPackagePreview, error) {
		return readSelectedPackagePreviewWithRunner(ctx, selected, func(_ context.Context, stdout, _ io.Writer, args ...string) error {
			if !slices.Equal(args, []string{"requirements", "--backends", "masque"}) {
				t.Fatalf("incorrect producer action: %q", args)
			}
			_, err := io.WriteString(stdout, raw)
			return err
		})
	}
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"complete empty plan", ready, true},
		{"complete nonempty plan", missing, true},
		{"missing digest empty plan", strings.Replace(ready, "apt_install_sha256="+emptySHA+"\n", "", 1), false},
		{"missing digest nonempty plan", strings.Replace(missing, "apt_install_sha256="+sha+"\n", "", 1), false},
		{"empty digest", strings.Replace(missing, sha, "", 1), false},
		{"incorrect digest", strings.Replace(missing, sha, strings.Repeat("f", 64), 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := read(context.Background(), tc.raw)
			if tc.valid {
				if err != nil || (plan.aptDigest != sha && plan.aptDigest != emptySHA) {
					t.Fatalf("valid canonical digest contract rejected: %+v %v", plan, err)
				}
			} else if reason, _ := packageInventoryGuidance(err); reason != "requirements_inventory_contract_invalid" {
				t.Fatalf("accepted incomplete/different digest: plan=%+v err=%v", plan, err)
			}
		})
	}
	// Already-ready MASQUE must not require privilege admission or consume YES.
	t.Run("ready no transaction", func(t *testing.T) {
		input := strings.NewReader("YES\n")
		reader := bufio.NewReader(input)
		calls := 0
		ops := menuPackagePreparationOps{
			preview: func(ctx context.Context, got tunnelOption) (selectedPackagePreview, error) {
				calls++
				return read(ctx, ready)
			},
			canPrepare: func(io.Reader, io.Writer) bool {
				t.Fatal("ready MASQUE unexpectedly needs PREPARE")
				return false
			},
			install: func(context.Context, io.Writer, io.Writer, ...string) error {
				t.Fatal("ready MASQUE unexpectedly installed packages")
				return nil
			},
		}
		var out, errOut bytes.Buffer
		got := menuPrepareSelectedPackagesWithOps(input, reader, &out, &errOut, selected, nil, ops)
		next, err := readMenuAnswer(reader)
		if !got.canContinue || got.approvedSelectedPlan || calls != 1 || err != nil || next != "YES" {
			t.Fatalf("ready MASQUE lost Create consent boundary: %+v calls=%d next=%q err=%v", got, calls, next, err)
		}
	})
	// PREPARE consent applies only to the same fully attested digest and
	// post-transaction inventory. YES for Link creation remains separate.
	t.Run("consented missing package", func(t *testing.T) {
		input := strings.NewReader("PREPARE\nYES\n")
		reader := bufio.NewReader(input)
		calls, installs := 0, 0
		ops := menuPackagePreparationOps{
			preview: func(ctx context.Context, got tunnelOption) (selectedPackagePreview, error) {
				calls++
				if calls == 3 {
					return read(ctx, ready)
				}
				return read(ctx, missing)
			},
			canPrepare: func(io.Reader, io.Writer) bool { return true },
			install: func(_ context.Context, _, _ io.Writer, args ...string) error {
				installs++
				if !slices.Equal(args, []string{"prepare", "--backends", "masque",
					"--expected-missing", "iproute2", "--expected-apt-plan", selectedPlan}) {
					t.Fatalf("unexpected package PREPARE plan: %q", args)
				}
				return nil
			},
		}
		var out, errOut bytes.Buffer
		got := menuPrepareSelectedPackagesWithOps(input, reader, &out, &errOut, selected, nil, ops)
		next, err := readMenuAnswer(reader)
		if !got.approvedFor(selected) || calls != 3 || installs != 1 || next != "YES" || err != nil {
			t.Fatalf("consented MASQUE package flow failed: %+v calls=%d installs=%d next=%q err=%v out=%q", got, calls, installs, next, err, out.String())
		}
	})
	// The second read-only preview MUST demand the producer's digest,
	// even if an initial valid one and an explicit PREPARE were observed.
	for _, bad := range []struct{ name, raw string }{
		{"missing digest", strings.Replace(missing, "apt_install_sha256="+sha+"\n", "", 1)},
		{"empty digest", strings.Replace(missing, sha, "", 1)},
		{"wrong digest", strings.Replace(missing, sha, strings.Repeat("f", 64), 1)},
	} {
		t.Run("repreview "+bad.name, func(t *testing.T) {
			input := strings.NewReader("PREPARE\nYES\n")
			reader := bufio.NewReader(input)
			calls := 0
			ops := menuPackagePreparationOps{
				preview: func(ctx context.Context, got tunnelOption) (selectedPackagePreview, error) {
					calls++
					if calls == 1 {
						return read(ctx, missing)
					}
					return read(ctx, bad.raw)
				},
				canPrepare: func(io.Reader, io.Writer) bool { return true },
				install: func(context.Context, io.Writer, io.Writer, ...string) error {
					t.Fatal("invalid post-consent re-preview authorized APT mutation")
					return nil
				},
			}
			var out, errOut bytes.Buffer
			got := menuPrepareSelectedPackagesWithOps(input, reader, &out, &errOut, selected, nil, ops)
			next, err := readMenuAnswer(reader)
			if got.canContinue || got.approvedSelectedPlan || calls != 2 ||
				!strings.Contains(out.String(), "requirements_inventory_contract_invalid") ||
				next != "YES" || err != nil {
				t.Fatalf("invalid post-consent digest was admitted: %+v calls=%d next=%q err=%v out=%q",
					got, calls, next, err, out.String())
			}
		})
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
		{"missing digest", strings.Replace(inventory, "apt_install_sha256="+digest+"\n", "", 1)},
		{"empty digest", strings.Replace(inventory, digest, "", 1)},
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
	// Exercise the ACTUAL embedded Bash entrypoint with an OS fixture.
	// Shell startup injection would execute before parsing the fixture;
	// unrelated host APT/package availability must not decide this test.
	osFixture := filepath.Join(tmp, "os-release")
	if err := os.WriteFile(osFixture, []byte("ID=debian\nVERSION_ID=\"13\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out, errOut bytes.Buffer
	if err := runEmbeddedInstaller(ctx, &out, &errOut,
		"requirements", "--backends", "native", "--os-release-file", osFixture); err != nil ||
		!strings.Contains(out.String(), "selected_backends=native") ||
		!strings.Contains(out.String(), "packages=iproute2 iptables kmod") || errOut.Len() != 0 {
		t.Fatalf("sanitized canonical source-only inventory failed: err=%v output=%q", err, out.String())
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
