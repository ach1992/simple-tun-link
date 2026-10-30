package quichelper

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/systemdunit"
	"golang.org/x/sys/unix"
)

// Unit-local Restart=no does not exclude another unit's Upholds= edge.
// StartTransientUnit can reuse a not-found unit whose dependency graph is
// already populated. Require effective graph evidence before dispatch and
// again while retaining the original process for its birth receipt.
func verifyEffectiveUnitDependencies(ctx context.Context, s unitSpec, values map[string]string, vacant bool) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("QUIC dependency inspection canceled")
	}
	fallback, err := unitDependencyFallbackRequired(values)
	if err != nil || !fallback {
		return err
	}
	raw, err := managerCommand(ctx, "systemctl", "--system", "show", "--property=Version", "--no-pager", "--all")
	if err != nil {
		return fmt.Errorf("QUIC dependency property capability is unverified")
	}
	version, err := legacyDependencyVersion(raw)
	if err != nil {
		return err
	}
	snapshot, err := readLegacyUnitGraph(ctx, s.Name, version)
	if err != nil {
		return err
	}
	return verifyLegacyUnitGraph(snapshot, s, vacant)
}

func unitDependencyFallbackRequired(values map[string]string) (bool, error) {
	if err := noForeignHooks(values); err != nil {
		return false, err
	}
	_, hasIncoming := values["UpheldBy"]
	_, hasOutgoing := values["Upholds"]
	return !hasIncoming || !hasOutgoing, nil
}

func legacyDependencyVersion(raw []byte) (int, error) {
	version, ok := systemdunit.ParseVersion(raw)
	if !ok || (version != 249 && version != 250) {
		return 0, fmt.Errorf("QUIC effective dependency properties are missing or unsupported")
	}
	return version, nil
}

// The v249/v250 dump is a diagnostic format, not a stable protocol. Both
// strict parsing and successful completion of the fixed local reader are
// necessary. Do not retain the full host dump or expose other units'
// commands/environment in diagnostics. Bounds apply per line and through
// the command deadline, never to the number of managed Links.
func readLegacyUnitGraph(ctx context.Context, name string, version int) (systemdunit.LegacyUnitSnapshot, error) {
	var empty systemdunit.LegacyUnitSnapshot
	if ctx == nil || ctx.Err() != nil || (version != 249 && version != 250) ||
		!safeArgument(name) || !strings.HasSuffix(name, ".service") || strings.Contains(name, "/") {
		return empty, fmt.Errorf("legacy QUIC dependency snapshot request invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	host, err := currentHostIdentity()
	if err != nil {
		return empty, err
	}
	cmd, release, err := localManagerCommand(ctx, "systemd-analyze", "--system", "--no-pager", "dump")
	if err != nil {
		return empty, err
	}
	defer release()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return empty, fmt.Errorf("legacy QUIC dependency snapshot stream unavailable")
	}
	// Closing the pipe on timeout also bounds parsing if the reader exits
	// while another process unexpectedly retains its write end.
	stopClose := context.AfterFunc(ctx, func() { _ = stdout.Close() })
	defer stopClose()
	var stderr boundedOutput
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return empty, fmt.Errorf("legacy QUIC dependency snapshot reader failed")
	}
	snapshot, parseErr := systemdunit.ParseLegacyManagerDump(stdout, version, name)
	if parseErr != nil {
		// This cancels only our read-only reader subprocess. It never sends
		// a signal or lifecycle request to a helper or another system unit.
		release()
	}
	waitErr := cmd.Wait()
	if parseErr != nil || waitErr != nil || stderr.Len() != 0 || stderr.overflow || ctx.Err() != nil {
		return empty, fmt.Errorf("legacy QUIC dependency snapshot incomplete or unverified")
	}
	again, err := currentHostIdentity()
	if err != nil || again != host {
		return empty, fmt.Errorf("system manager changed during QUIC dependency inspection")
	}
	return snapshot, nil
}

func verifyLegacyUnitGraph(snapshot systemdunit.LegacyUnitSnapshot, s unitSpec, vacant bool) error {
	if snapshot.IncomingUpholds || snapshot.OutgoingUpholds {
		return fmt.Errorf("foreign effective QUIC Upholds relationship")
	}
	if !snapshot.Present {
		if vacant {
			// A clean not-found stub can be garbage-collected between show
			// and Dump. The complete dump still proves no targeting edge.
			return nil
		}
		return fmt.Errorf("original QUIC unit missing from manager snapshot")
	}
	expected := map[string]string{
		"Unit Load State": "loaded", "Unit Active State": "active",
		"Need Daemon Reload": "no", "Transient": "yes",
		"Fragment Path": "/run/systemd/transient/" + s.Name, "StopWhenUnneeded": "no",
	}
	if vacant {
		expected["Unit Load State"] = "not-found"
		expected["Unit Active State"] = "inactive"
		expected["Transient"] = "no"
		delete(expected, "Fragment Path")
		delete(expected, "StopWhenUnneeded")
		// unit_dump prints Fragment Path only when one exists, and prints
		// StopWhenUnneeded only for UNIT_LOADED. A not-found unit has neither.
		// https://github.com/systemd/systemd/blob/v249/src/core/unit-serialize.c
		for _, field := range []string{"Fragment Path", "StopWhenUnneeded"} {
			if _, present := snapshot.Fields[field]; present {
				return fmt.Errorf("QUIC vacancy contradicts manager snapshot")
			}
		}
	}
	for field, want := range expected {
		if got, present := snapshot.Fields[field]; !present || got != want {
			return fmt.Errorf("QUIC unit identity differs in manager snapshot: %s", field)
		}
	}
	return nil
}

// The caller has already checked the complete UnitPath directory chain.
// Retain this root-owned directory while inspecting aliases and installed
// reverse edges. An edge directory symlink is never a trusted inventory.
func checkUnitReverseReferences(ctx context.Context, path, name string) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("QUIC reverse dependency inspection canceled")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("QUIC unit directory cannot be retained")
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	return inspectUnitReferenceDirectory(ctx, directory, name, true, 0)
}

// Reads a bounded chunk at a time and checks cancellation between entries.
// owner is fixed to root by production; tests can exercise inventory logic
// with an unprivileged isolated directory without relaxing that caller.
func inspectUnitReferenceDirectory(ctx context.Context, directory *os.File, name string, inspectEdges bool, owner uint32) error {
	if ctx == nil || ctx.Err() != nil || directory == nil {
		return fmt.Errorf("QUIC reverse dependency inspection canceled or unavailable")
	}
	var st unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != owner || st.Mode&0o022 != 0 {
		return fmt.Errorf("QUIC reverse dependency directory is untrusted")
	}
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("QUIC reverse dependency inspection canceled")
		}
		entries, readErr := directory.ReadDir(64)
		for _, entry := range entries {
			if ctx.Err() != nil {
				return fmt.Errorf("QUIC reverse dependency inspection canceled")
			}
			if entry.Name() == name {
				return fmt.Errorf("foreign QUIC unit or reverse dependency exists")
			}
			if strings.HasSuffix(entry.Name(), ".service") {
				if err := rejectUnitAlias(directory, entry.Name(), name); err != nil {
					return err
				}
			}
			if !inspectEdges || !(strings.HasSuffix(entry.Name(), ".wants") || strings.HasSuffix(entry.Name(), ".requires") || strings.HasSuffix(entry.Name(), ".upholds")) {
				continue
			}
			fd, err := unix.Openat(int(directory.Fd()), entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("QUIC reverse dependency directory cannot be verified")
			}
			edges := os.NewFile(uintptr(fd), entry.Name())
			err = inspectUnitReferenceDirectory(ctx, edges, name, false, owner)
			closeErr := edges.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return fmt.Errorf("QUIC reverse dependency directory observation incomplete")
			}
		}
		if readErr == io.EOF {
			if ctx.Err() != nil {
				return fmt.Errorf("QUIC reverse dependency inspection canceled")
			}
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("QUIC reverse dependency inventory incomplete")
		}
	}
}

func rejectUnitAlias(directory *os.File, entry, selected string) error {
	var st unix.Stat_t
	if unix.Fstatat(int(directory.Fd()), entry, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return fmt.Errorf("QUIC unit alias cannot be inspected")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return nil
	}
	var target [4096]byte
	n, err := unix.Readlinkat(int(directory.Fd()), entry, target[:])
	if err != nil || n == len(target) {
		return fmt.Errorf("QUIC unit alias target is unverified")
	}
	if filepath.Base(string(target[:n])) == selected {
		return fmt.Errorf("foreign alias targets the QUIC helper")
	}
	return nil
}
