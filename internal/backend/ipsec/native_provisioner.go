package ipsec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/maintenance"
	"golang.org/x/sys/unix"
)

// NativeProvisionReadiness is a restrictive, read-only eligibility check.
// The only operational caller is explicit, fresh root-TTY menu consent, and
// the producer repeats the same check under the installed maintenance lock.
// It never changes foreign strongSwan process/service/policy identity.
func NativeProvisionReadiness(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return errors.New("root systemd host inspection unavailable")
	}
	if err := verifyTrustedNativeExecutable(nativeStrongSwanExecutable, nativeStrongSwanExecutable); err != nil {
		return errors.New("root-owned strongSwan executable not verified")
	}
	if InspectNativeExclusiveConfig() != NativeConfigMissing ||
		InspectNativeExclusiveConfigOrigin() != NativeOriginMissing ||
		InspectNativeExclusiveServiceUnit() != NativeServiceUnitMissing ||
		InspectNativeExclusiveServiceUnitOrigin() != NativeOriginMissing {
		return errors.New("STL private IPsec publication already exists or is uncertain; never adopt/replace")
	}
	// Refuse an already listed same-name systemd service including stale
	// loaded/generator/transient state. The backend's runtime ownership
	// admission independently rejects unapproved effective unit overrides.
	r := BoundedExecRunner{Timeout: 4 * time.Second}
	listed, e := r.RunBounded(ctx, CaptureLimits{Stdout: 16 << 10, Stderr: 1024},
		"/usr/bin/systemctl", "--system", "--no-pager", "--no-legend", "--plain", "--full",
		"--all", "--type=service", "list-units", "simple-tun-link-ipsec.servic?")
	if e != nil || len(listed.Stderr) != 0 || len(listed.Stdout) != 0 {
		return errors.New("native systemd loaded identity unavailable or occupied")
	}
	if err := verifyNoForeignStrongSwanProcess(0); err != nil {
		return errors.New("foreign strongSwan process present or unverified")
	}
	if err := nativeIKEPortsVacant(); err != nil {
		return errors.New("existing or unverified IKE UDP 500/4500 owner")
	}
	// Native service cannot coexist with an enabled distro service; never
	// stop, disable, mask, adopt, reset or modify such a service automatically.
	for _, vendor := range []string{"strongswan.service", "strongswan-starter.service", "charon-systemd.service", "ipsec.service"} {
		active, e := readNativeVendorUnitState(ctx, "is-active", vendor)
		if e != nil || active != "inactive" && active != "unknown" {
			return errors.New("vendor strongSwan service active or ambiguous")
		}
		enabled, e := readNativeVendorUnitState(ctx, "is-enabled", vendor)
		if e != nil || enabled != "disabled" && enabled != "masked" && enabled != "not-found" {
			return errors.New("vendor strongSwan service enabled or ambiguous")
		}
	}
	if _, e := os.Lstat(NativeExclusiveVICIPath); e == nil || !errors.Is(e, os.ErrNotExist) {
		return errors.New("private VICI socket already present or cannot be inspected")
	}
	return nil
}

func readNativeVendorUnitState(ctx context.Context, action, name string) (string, error) {
	if ctx == nil || (action != "is-active" && action != "is-enabled") ||
		!strings.HasSuffix(name, ".service") {
		return "", errors.New("invalid native service observation")
	}
	// systemctl is-enabled deliberately exits nonzero for a confirmed
	// disabled/missing vendor unit. The normal bounded runner erases stdout
	// on nonzero exit and cannot establish safe negative evidence.
	// Capture bounded stdout, independently validate exit status, and reject
	// stderr/unknown content. Never infer absence from generic command error.
	bound, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out := &privateCapture{max: 128}
	errOut := &privateCapture{max: 128}
	cmd := exec.CommandContext(bound, "/usr/bin/systemctl",
		"--system", "--no-pager", action, name)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "HOME=/root"}
	cmd.Stdout, cmd.Stderr = out, errOut
	runErr := cmd.Run()
	if bound.Err() != nil || out.overflow || errOut.overflow || errOut.output.Len() != 0 {
		return "", errors.New("unverified systemd state")
	}
	code := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return "", errors.New("unverified systemd exit")
		}
		code = exitErr.ExitCode()
	}
	return parseNativeVendorStatus(action, out.output.Bytes(), errOut.output.Bytes(), code)
}

// parseNativeVendorStatus is a strict independent interpreter of systemctl's
// printed state AND its expected nonzero exit code. Failure alone cannot prove
// that a foreign unit is disabled or missing.
func parseNativeVendorStatus(action string, stdout, stderr []byte, code int) (string, error) {
	if len(stderr) != 0 {
		return "", errors.New("unverified systemd diagnostic output")
	}
	answer := string(stdout)
	if !strings.HasSuffix(answer, "\n") || strings.Count(answer, "\n") != 1 {
		return "", errors.New("unverified systemd output shape")
	}
	answer = strings.TrimSuffix(answer, "\n")
	switch action {
	case "is-active":
		if (answer == "inactive" && (code == 3 || code == 4)) ||
			(answer == "unknown" && code == 4) {
			return answer, nil
		}
		if answer == "active" && code == 0 {
			return answer, nil
		}
	case "is-enabled":
		if ((answer == "disabled" || answer == "masked") && code == 1) ||
			(answer == "not-found" && code == 4) {
			return answer, nil
		}
		if answer == "enabled" && code == 0 {
			return answer, nil
		}
	}
	return "", errors.New("unrecognized systemd status/exit combination")
}

// nativeIKEPortsVacant reads only namespace-local kernel socket inventories;
// listening on test ports as a preflight would itself race/mutate the host.
func nativeIKEPortsVacant() error {
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		f, e := os.Open(path)
		if e != nil {
			return errors.New("cannot inspect IKE UDP inventory")
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 4<<20)
		if !scanner.Scan() {
			f.Close()
			return errors.New("empty IKE UDP inventory")
		}
		seen := 0
		for scanner.Scan() {
			seen++
			if seen > 8192 {
				f.Close()
				return errors.New("IKE UDP inventory too large")
			}
			cols := strings.Fields(scanner.Text())
			if len(cols) < 10 {
				f.Close()
				return errors.New("malformed IKE UDP inventory")
			}
			addr := cols[1]
			sep := strings.LastIndexByte(addr, ':')
			if sep < 0 || len(addr)-sep-1 != 4 {
				f.Close()
				return errors.New("malformed IKE UDP endpoint")
			}
			if strings.EqualFold(addr[sep+1:], "01F4") || strings.EqualFold(addr[sep+1:], "1194") {
				f.Close()
				return errors.New("IKE UDP port already occupied")
			}
		}
		err := scanner.Err()
		if closeErr := f.Close(); closeErr != nil || err != nil {
			return errors.New("IKE UDP inventory incomplete")
		}
	}
	return nil
}

// publishNativeBootEdgeAt adds only the exact canonical root-owned
// multi-user.target.wants reference. It cannot overwrite any existing edge.
// A foreign directory, symlink, unexpected unit or partial fsync fails closed.
func publishNativeBootEdgeAt(root string, owner uint32) error {
	chain, err := openNativeUnitChain(root, owner)
	if err != nil {
		return errNativePublicationUnknown
	}
	defer chain.close()
	dir := chain.parent()
	const wantsName = "multi-user.target.wants"
	wants, err := unix.Openat(dir, wantsName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		if err = unix.Mkdirat(dir, wantsName, 0o755); err != nil {
			return errNativePublicationUnknown
		}
		if unix.Fsync(dir) != nil {
			return errNativePublicationPending
		}
		wants, err = unix.Openat(dir, wantsName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return errNativePublicationConflict
	}
	defer unix.Close(wants)
	if !trustedNativeDirectory(wants, owner, false) || !trustedNativeUnitChain(chain, owner) {
		return errNativePublicationConflict
	}
	if err := nativeMustBeAbsent(wants, nativeUnitName); err != nil {
		return err
	}
	if err := unix.Symlinkat(NativeExclusiveServiceUnitPath, wants, nativeUnitName); err != nil {
		return errNativePublicationPending
	}
	if unix.Fsync(wants) != nil {
		return errNativePublicationPending
	}
	if !trustedNativeBootEnablementAt(root, owner) {
		return errNativePublicationPending
	}
	return nil
}

// ProvisionNativeExclusive is deliberately narrow: fresh source files are
// published using the ALREADY reviewed protected, no-replace receipt writers,
// then a single verified native service is started. It NEVER installs packages,
// stops/changes a distro service, blindly rekeys, or adopts existing state.
// Any ambiguous publication/startup keeps exact on-disk evidence for manual
// reconciliation rather than deleting a possibly foreign object.
func ProvisionNativeExclusive(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return errors.New("native IPsec provision requires root")
	}
	release, err := maintenance.NewInstalledGate().AcquireExclusive(ctx)
	if err != nil {
		return errors.New("exclusive installed STL ownership gate unavailable")
	}
	defer release()
	if err := NativeProvisionReadiness(ctx); err != nil {
		return err
	}
	if err := publishNativeConfigAt("/", 0, nativePublishHooks{}); err != nil {
		return fmt.Errorf("IPsec configuration publication did not complete: %w; inspect private evidence before retry", err)
	}
	if err := publishNativeUnitAt("/", 0, nativeUnitPublishHooks{}); err != nil {
		return fmt.Errorf("IPsec unit publication incomplete: %w; private config remains for owner reconciliation", err)
	}
	runner := BoundedExecRunner{Timeout: 25 * time.Second}
	transition := func(action string) error {
		args := []string{action}
		if action == "start" {
			args = append(args, nativeServiceName)
		}
		result, e := runner.RunBounded(ctx, CaptureLimits{Stdout: 1024, Stderr: 1024}, "/usr/bin/systemctl", args...)
		clear(result.Stdout)
		clear(result.Stderr)
		if e != nil {
			return errors.New("native IPsec systemd transition incomplete; inspect source and loaded daemon before retry")
		}
		return nil
	}
	if err := transition("daemon-reload"); err != nil {
		return err
	}
	// Attest the EFFECTIVE loaded unit and all executable directives BEFORE
	// starting anything. A dormant foreign drop-in/generator can become
	// effective when daemon-reload discovers our just-published unit.
	admission := NewNativeRuntimeAdmission()
	if err := admission.attestPreStartUnit(ctx); err != nil {
		return errors.New("native IPsec loaded unit fails PRE-START admission; unit not started and boot edge not enabled; reconcile published sources")
	}
	if err := transition("start"); err != nil {
		return err
	}
	// First prove actual process, socket and foreign-owner exclusion.
	// Do not create any boot activation edge for an unverified first start.
	if err := admission.Authorize(ctx); err != nil {
		return errors.New("native IPsec first start remains unverified; boot edge NOT enabled; manual reconciliation required")
	}
	if err := publishNativeBootEdgeAt("/", 0); err != nil {
		return fmt.Errorf("IPsec boot enablement incomplete: %w; published files retained for reconciliation", err)
	}
	if err := admission.Authorize(ctx); err != nil {
		return errors.New("native IPsec boot-edge final attestation failed; reconcile retained private artifacts before further activation")
	}
	return nil
}
