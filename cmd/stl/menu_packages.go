package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

//go:embed canonical-installer.sh
var canonicalInstaller []byte

// The generated embedded shell is byte-identical to scripts/install.sh,
// the ONE canonical APT/ownership/locking implementation. CI enforces cmp.
// Neither a mutable GitHub tag nor caller-controlled PATH/source is executed.
func selectedPackageBackends(selected tunnelOption) string {
	switch selected.backend {
	case domain.BackendGRE, domain.BackendIPIP:
		return "native"
	case domain.BackendWireGuard:
		return "native,wireguard"
	case domain.BackendIPsec:
		return "native,ipsec"
	default:
		return ""
	}
}

type selectedPackagePreview struct {
	missing    string
	packages   string
	aptInstall string
}

func missingStrongSwanPackages(missing string) bool {
	for _, pkg := range strings.Fields(missing) {
		switch pkg {
		case "charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins":
			return true
		}
	}
	return false
}

func runEmbeddedInstaller(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	if ctx == nil || len(canonicalInstaller) == 0 {
		return errors.New("canonical installer unavailable")
	}
	cmd := exec.CommandContext(ctx, "/bin/bash", append([]string{"-s", "--"}, args...)...)
	cmd.Stdin = bytes.NewReader(canonicalInstaller)
	// Noninteractive root Bash must not inherit BASH_ENV, arbitrary PATH,
	// injected env hooks or user-controlled loader variables.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "HOME=/root"}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return errors.New("canonical installer action failed or was interrupted")
	}
	return nil
}

func readSelectedPackagePreview(ctx context.Context, selected tunnelOption) (selectedPackagePreview, error) {
	choice := selectedPackageBackends(selected)
	if choice == "" {
		return selectedPackagePreview{}, errors.New("unrecognized tunnel package selection")
	}
	var stdout, stderr bytes.Buffer
	if err := runEmbeddedInstaller(ctx, &stdout, &stderr, "requirements", "--backends", choice); err != nil || stdout.Len() > 32768 {
		return selectedPackagePreview{}, errors.New("read-only package inventory incomplete")
	}
	var plan selectedPackagePreview
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return selectedPackagePreview{}, errors.New("invalid canonical package inventory")
		}
		seen[key] = true
		switch key {
		case "distribution", "version", "selected_backends", "packages", "missing_packages", "apt_install", "notice":
		default:
			return selectedPackagePreview{}, errors.New("unexpected package inventory field")
		}
		if key == "selected_backends" && value != choice {
			return selectedPackagePreview{}, errors.New("package selector drift")
		}
		if key == "packages" {
			plan.packages = value
		}
		if key == "missing_packages" {
			plan.missing = value
		}
		if key == "apt_install" {
			plan.aptInstall = value
		}
	}
	if !seen["selected_backends"] || !seen["packages"] || !seen["missing_packages"] || !seen["apt_install"] || !seen["distribution"] || !seen["version"] {
		return selectedPackagePreview{}, errors.New("canonical package inventory missing required fields")
	}
	// Strings must be the canonical installer literal package vocabulary.
	// This parser must never emit arbitrary package names as shell arguments.
	allowed := map[string]bool{"iproute2": true, "iptables": true, "kmod": true,
		"wireguard-tools": true, "charon-systemd": true, "strongswan-swanctl": true,
		"libstrongswan-standard-plugins": true}
	for _, name := range strings.Fields(plan.packages) {
		if !allowed[name] {
			return selectedPackagePreview{}, errors.New("unknown canonical package identity")
		}
	}
	for _, name := range strings.Fields(plan.missing) {
		if !allowed[name] || !strings.Contains(" "+plan.packages+" ", " "+name+" ") {
			return selectedPackagePreview{}, errors.New("unknown or unselected missing package")
		}
	}
	// The APT resolver may add transitive packages. Treat its complete
	// package=version set as opaque, bounded data; never form shell code.
	identity := regexp.MustCompile("^[a-z0-9][a-z0-9.+:-]*=[0-9][a-zA-Z0-9:.+~_-]*$")
	seenAPT := map[string]bool{}
	for _, term := range strings.Fields(plan.aptInstall) {
		if !identity.MatchString(term) || seenAPT[strings.SplitN(term, "=", 2)[0]] {
			return selectedPackagePreview{}, errors.New("invalid APT resolver identity")
		}
		seenAPT[strings.SplitN(term, "=", 2)[0]] = true
	}
	if (plan.missing == "") != (plan.aptInstall == "") {
		return selectedPackagePreview{}, errors.New("APT resolver omitted missing dependencies")
	}
	for _, term := range strings.Fields(plan.missing) {
		if !seenAPT[term] {
			return selectedPackagePreview{}, errors.New("APT resolver omitted selected package")
		}
	}
	return plan, nil
}

// One explicit PREPARE covers the selected package/dependency plan AND, for
// IPsec, qualified private-service admission. Actual Link Create has its own
// separate YES. Inspecting or cancelling always remains read-only.
func menuPrepareSelectedPackages(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	selected tunnelOption, options *runtimeOptions) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	plan, err := readSelectedPackagePreview(ctx, selected)
	cancel()
	if err != nil {
		menuSection(out, "Selected tunnel / package check")
		menuField(out, "STATUS", "Unverified")
		menuField(out, "NEXT ACTION", "Inspect supported OS and APT metadata; no changes attempted")
		return selected.backend != domain.BackendIPsec
	}

	// Independent service admission is a live root ownership check, not a
	// guarantee derived from installed packages or a generic capability hint.
	needsService := false
	if selected.backend == domain.BackendIPsec {
		if options == nil {
			options, _ = productionRuntimeOptions()
		}
		checkCtx, stop := context.WithTimeout(context.Background(), 12*time.Second)
		_, admitted := activeIPsecBackend(checkCtx, options)
		stop()
		needsService = admitted != nil
	}
	if plan.missing == "" && !needsService {
		return true
	}
	if !menuCanUpdateNow(input, out) {
		menuNotice(out, "WARNING", "Selected prerequisites need an installed root terminal for preparation.")
		menuField(out, "Packages", plan.missing)
		menuField(out, "NEXT ACTION", "Run sudo stl menu on the selected server")
		if selected.backend == domain.BackendIPsec {
			menuField(out, "Read-only check", "stl doctor ipsec --json")
		}
		return selected.backend != domain.BackendIPsec
	}
	menuScreen(out, "Selected tunnel / PREPARE")
	menuField(out, "Type", fmt.Sprintf("%s / %s", selected.backend, selected.mode))
	if plan.missing != "" {
		menuField(out, "Missing packages", plan.missing)
		menuField(out, "APT install plan", plan.aptInstall)
	}
	if needsService {
		menuField(out, "Private service", "Inspect ownership; publish and start STL-exclusive IPsec unit if qualified")
		menuNotice(out, "WARNING", "Signed APT package hooks may briefly enable/start a NEW vendor strongSwan service. STL will stop/disable ONLY that proven transaction-created unit; it never changes a pre-existing service.")
	}
	menuField(out, "NEXT ACTION", "Review selected changes; type PREPARE to continue")
	menuProse(out, "APT packages may persist after an interruption. No Link, keys, or peer connection will be created during preparation.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Fresh consent unavailable; no preparation attempted.")
		return false
	}
	fmt.Fprintf(out, "Type %s to prepare selected prerequisites (Enter cancels): ", menuPaint(out, menuYellow, "PREPARE"))
	confirmation, e := readMenuAnswer(reader)
	if e != nil || confirmation != "PREPARE" {
		menuNotice(out, "INFO", "Preparation cancelled before any changes.")
		return false
	}
	if plan.missing != "" {
		verifyCtx, stop := context.WithTimeout(context.Background(), 12*time.Second)
		refreshed, e := readSelectedPackagePreview(verifyCtx, selected)
		stop()
		if e != nil || refreshed.missing != plan.missing ||
			refreshed.packages != plan.packages || refreshed.aptInstall != plan.aptInstall {
			menuNotice(out, "WARNING", "Package/dependency plan changed since consent; no packages installed.")
			return false
		}
		prepCtx, done := context.WithTimeout(context.Background(), 15*time.Minute)
		defer done()
		menuNotice(out, "INFO", "Canonical installer checking exact plan and host ownership")
		if err := runEmbeddedInstaller(prepCtx, out, errOut, "prepare",
			"--backends", selectedPackageBackends(selected), "--expected-missing", refreshed.missing,
			"--expected-apt-plan", refreshed.aptInstall); err != nil {
			menuNotice(out, "FAILED", "Package preparation incomplete or denied. APT/vendor changes may persist after an attempted transaction; inspect and reconcile before retry.")
			return false
		}
		afterCtx, afterDone := context.WithTimeout(context.Background(), 12*time.Second)
		after, e := readSelectedPackagePreview(afterCtx, selected)
		afterDone()
		if e != nil || after.missing != "" {
			menuNotice(out, "FAILED", "Selected packages are not verified after APT; private service was not started.")
			return false
		}
	}
	if needsService {
		original := options
		probeCtx, probeDone := context.WithTimeout(context.Background(), 12*time.Second)
		err := ipsecbackend.NativeProvisionReadiness(probeCtx)
		probeDone()
		if err != nil {
			menuNotice(out, "FAILED", "Private IPsec admission is not qualified. Vendor/foreign identity or incomplete sources must be reconciled; no Link created.")
			return false
		}
		provisionCtx, done := context.WithTimeout(context.Background(), 75*time.Second)
		err = ipsecbackend.ProvisionNativeExclusive(provisionCtx)
		done()
		if err != nil {
			menuNotice(out, "FAILED", "STL-private service publication/start is incomplete or uncertain. Preserve protected artifacts for diagnosis; no Link created.")
			return false
		}
		// Rebuild registration and require actual admitted runtime; provision
		// success is not itself proof of a ready backend.
		options, err = productionRuntimeOptions()
		if err != nil {
			menuNotice(out, "FAILED", "Cannot rebuild IPsec backend after service preparation.")
			return false
		}
		verifyCtx, end := context.WithTimeout(context.Background(), 15*time.Second)
		_, err = activeIPsecBackend(verifyCtx, options)
		end()
		if err != nil {
			menuNotice(out, "FAILED", "Prepared private service has not passed runtime admission.")
			return false
		}
		// The selected Create must receive the refreshed admitted backend,
		// not the pre-APT runtime snapshot that lacked strongSwan packages.
		if original != nil {
			*original = *options
		}
	}
	menuNotice(out, "OK", "Selected prerequisites verified; continuing the same tunnel Create (Link confirmation is separate).")
	return true
}

// Embedded script must not drift from its canonical file. Package-level tests
// also exercise the installer's real shell planner, not a Go copy of it.
func menuEmbeddedInstallerSanity() error {
	if len(canonicalInstaller) == 0 || !bytes.HasPrefix(canonicalInstaller, []byte("#!/usr/bin/env bash\n")) {
		return errors.New("embedded installer identity unavailable")
	}
	return nil
}
