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
	"strings"
	"time"

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
	missing  string
	packages string
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
	if err := runEmbeddedInstaller(ctx, &stdout, &stderr, "requirements", "--backends", choice); err != nil || stdout.Len() > 8192 {
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
		case "distribution", "version", "selected_backends", "packages", "missing_packages", "notice":
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
	}
	if !seen["selected_backends"] || !seen["packages"] || !seen["missing_packages"] || !seen["distribution"] || !seen["version"] {
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
	return plan, nil
}

// Creating any tunnel may require optional distro packages. Missing
// strongSwan packages are administrator-managed because APT may trigger
// foreign systemd service hooks; other selected packages remain automatic.
// The preview is read-only for every selection; only an installed root terminal and a fresh
// explicit confirmation delegate to the binary-embedded CANONICAL installer.
// This never downloads/executes shell from a release tag or carries an APT
// implementation into Go. Installer rechecks identity + missing set under lock.
func menuPrepareSelectedPackages(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, selected tunnelOption) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	plan, err := readSelectedPackagePreview(ctx, selected)
	cancel()
	if err != nil {
		menuSection(out, "Selected tunnel / package check")
		menuField(out, "STATUS", "Unverified")
		menuField(out, "REASON", "Cannot safely inspect canonical distro prerequisites")
		menuField(out, "NEXT ACTION", "Check OS/package manager; no change made")
		// The normal Engine remains responsible for final capability admission.
		// No package mutation is ever attempted on an uncertain snapshot.
		return true
	}
	if plan.missing == "" {
		return true
	}
	if selected.backend == domain.BackendIPsec && missingStrongSwanPackages(plan.missing) {
		menuScreen(out, "IPsec / administrator-managed packages")
		menuField(out, "STATUS", "Missing protected strongSwan dependencies")
		menuField(out, "Missing packages", plan.missing)
		menuField(out, "NEXT ACTION", "Inspect effective vendor systemd unit/drop-ins; install IPsec packages manually, then re-enter Create")
		menuField(out, "Read-only verification", "stl doctor ipsec --json")
		menuNotice(out, "WARNING", "APT package hooks may start a foreign strongSwan service. STL refuses automatic IPsec APT because foreign effective service ownership is not safely established.")
		menuProse(out, "No APT or STL Link change was attempted here. Other selected backends retain normal on-demand Prepare. Installing packages alone does not provision the STL-exclusive IPsec service.")
		return false
	}
	// Non-canonical, redirected and unprivileged sessions cannot consent to
	// privileged package changes. Keep the chosen backend and defer final
	// admission to the canonical Engine rather than eating scripted input.
	if !menuCanUpdateNow(input, out) {
		menuNotice(out, "WARNING", "Selected packages missing: "+plan.missing)
		menuField(out, "NEXT ACTION", "Install prerequisites using the verified installer, or open sudo stl menu to Prepare")
		return true
	}
	menuScreen(out, "Selected tunnel / prepare missing packages")
	menuField(out, "Type", fmt.Sprintf("%s / %s", selected.backend, selected.mode))
	menuField(out, "STATUS", "Needs package preparation")
	menuField(out, "Missing packages", plan.missing)
	menuField(out, "REASON", "Selected distro dependencies are not installed")
	menuField(out, "NEXT ACTION", "Review changes, type PREPARE, then continue Create")
	menuProse(out, "Canonical installer installs missing selected packages only. APT repository metadata may be refreshed. Packages persist after cancellation/failure and are not part of binary rollback.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Could not establish fresh input; no packages changed.")
		return false
	}
	fmt.Fprintf(out, "Type %s to install the listed missing packages (Enter cancels): ", menuPaint(out, menuYellow, "PREPARE"))
	confirmation, e := readMenuAnswer(reader)
	if e != nil || confirmation != "PREPARE" {
		menuNotice(out, "INFO", "Package preparation cancelled; no packages installed.")
		return false
	}
	verifyCtx, stop := context.WithTimeout(context.Background(), 8*time.Second)
	refreshed, e := readSelectedPackagePreview(verifyCtx, selected)
	stop()
	if e != nil || refreshed.missing != plan.missing || refreshed.packages != plan.packages {
		menuNotice(out, "WARNING", "Package inventory changed since consent; no packages installed.")
		return false
	}
	prepCtx, done := context.WithTimeout(context.Background(), 15*time.Minute)
	defer done()
	menuNotice(out, "INFO", "Canonical installer verifying ownership/lock and preparing packages")
	if err := runEmbeddedInstaller(prepCtx, out, errOut, "prepare", "--backends", selectedPackageBackends(selected), "--expected-missing", refreshed.missing); err != nil {
		menuNotice(out, "FAILED", "Package operation incomplete. Inspect apt/dpkg and strongSwan service state before retrying. No STL Link created.")
		return false
	}
	afterCtx, afterDone := context.WithTimeout(context.Background(), 8*time.Second)
	defer afterDone()
	after, err := readSelectedPackagePreview(afterCtx, selected)
	if err != nil || after.missing != "" {
		menuNotice(out, "WARNING", "Canonical package operation ended, but selected package readiness is unverified.")
		return false
	}
	menuNotice(out, "OK", "Selected packages now pass; continuing with independent backend/runtime checks.")
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
