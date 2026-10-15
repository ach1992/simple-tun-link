package ipsec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
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
	if (action != "is-active" && action != "is-enabled") || !strings.HasSuffix(name, ".service") {
		return "", errors.New("invalid native service observation")
	}
	runner := BoundedExecRunner{Timeout: 4 * time.Second}
	result, _ := runner.RunBounded(ctx, CaptureLimits{Stdout: 128, Stderr: 128},
		"/usr/bin/systemctl", "--system", "--no-pager", action, name)
	// No exit status alone establishes a negative result, and unknown
	// future output is never normalized into safe vacancy.
	if ctx.Err() != nil || len(result.Stdout) == 0 || len(result.Stderr) > 0 {
		return "", errors.New("unverified systemd state")
	}
	answer := string(result.Stdout)
	if !strings.HasSuffix(answer, "\n") || strings.Count(answer, "\n") != 1 {
		return "", errors.New("unverified systemd output shape")
	}
	answer = strings.TrimSuffix(answer, "\n")
	switch answer {
	case "inactive", "unknown", "disabled", "masked", "not-found", "enabled", "static", "active", "activating", "failed", "alias", "indirect", "generated", "linked", "linked-runtime":
		return answer, nil
	default:
		return "", errors.New("unrecognized systemd state")
	}
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
	if err := publishNativeBootEdgeAt("/", 0); err != nil {
		return fmt.Errorf("IPsec boot enablement incomplete: %w; published files retained for reconciliation", err)
	}
	runner := BoundedExecRunner{Timeout: 25 * time.Second}
	for _, args := range [][]string{{"daemon-reload"}, {"start", nativeServiceName}} {
		result, e := runner.RunBounded(ctx, CaptureLimits{Stdout: 1024, Stderr: 1024}, "/usr/bin/systemctl", args...)
		clear(result.Stdout)
		clear(result.Stderr)
		if e != nil {
			return errors.New("native IPsec systemd transition incomplete; inspect source and loaded daemon before further action")
		}
	}
	if err := NewNativeRuntimeAdmission().Authorize(ctx); err != nil {
		return errors.New("native IPsec service started but exclusive runtime attestation failed; manual reconciliation required")
	}
	return nil
}
