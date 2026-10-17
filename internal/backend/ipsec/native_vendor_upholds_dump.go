package ipsec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// The systemd 249/250 manager implements Upholds= but does not export
// UpheldBy through the unit D-Bus property interface (added in 251).
// Those two releases DO print the effective in-memory dependency graph in
// the PID1 Manager.Dump snapshot, including the reverse UpheldBy edge.
//
// This fallback is intentionally narrow: it is not an arbitrary unit-file
// parser, and it does not trust a missing D-Bus property as absence. It
// accepts only the attested v249/v250 manager dump format and fails closed
// if that format, command, version or selected unit identity changes.
//
// Source contract: upstream v249.11 src/core/manager-dump.c manager_dump()
// and src/core/unit-serialize.c unit_dump(). The diagnostic format is not
// a stable public API, so any unrecognized shape refuses STOP, not silently
// weakening the vendor ownership boundary.
func vendorStopParseLegacyManagerDump(r io.Reader, version int) error {
	if version != 249 && version != 250 {
		return errors.New("unsupported manager dump version")
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // stream output; bounded per line, not a total-output limit
	header := false
	selected := false
	targetSeen := false
	seen := map[string]bool{}
	const targetHeader = "-> Unit strongswan.service:"
	for scanner.Scan() {
		line := scanner.Text()
		if strings.ContainsAny(line, "\x00\r") {
			return errors.New("invalid bytes in systemd manager snapshot")
		}
		if !header {
			if !strings.HasPrefix(line, fmt.Sprintf("Manager: systemd %d (", version)) || !strings.HasSuffix(line, ")") {
				return errors.New("systemd manager dump version/identity unverified")
			}
			header = true
			continue
		}
		if line == targetHeader {
			if targetSeen {
				return errors.New("duplicate selected vendor unit in manager snapshot")
			}
			targetSeen = true
			selected = true
			continue
		}
		if strings.HasPrefix(line, "-> Unit ") || strings.HasPrefix(line, "-> Job ") {
			selected = false
			continue
		}
		// Both forward and reverse references are checked; a direct
		// Upholds= on an active external unit has no .upholds symlink.
		if strings.HasPrefix(line, "\tUpholds: strongswan.service (") ||
			strings.HasPrefix(line, "\tUpholds: strongswan-swanctl.service (") {
			return errors.New("effective direct Upholds dependency prevents vendor STOP")
		}
		if !selected {
			continue
		}
		if strings.HasPrefix(line, "\tUpheldBy:") {
			return errors.New("effective reverse UpheldBy dependency prevents vendor STOP")
		}
		for _, field := range []string{
			"Unit Load State", "Unit Active State",
			"Need Daemon Reload", "Fragment Path", "StopWhenUnneeded",
		} {
			if !strings.HasPrefix(line, "\t"+field+":") {
				continue
			}
			if seen[field] {
				return errors.New("duplicated selected vendor unit field in manager dump")
			}
			seen[field] = true
			value := strings.TrimPrefix(line, "\t"+field+": ")
			switch field {
			case "Unit Load State":
				if value != "loaded" {
					return errors.New("vendor unit was not loaded in manager snapshot")
				}
			case "Unit Active State":
				if value != "active" && value != "inactive" {
					return errors.New("vendor state unverified in manager snapshot")
				}
			case "Need Daemon Reload":
				if value != "no" {
					return errors.New("vendor unit has pending manager reload")
				}
			case "Fragment Path":
				if value != "/usr/lib/systemd/system/strongswan.service" &&
					value != "/lib/systemd/system/strongswan.service" {
					return errors.New("unexpected vendor fragment in manager snapshot")
				}
			case "StopWhenUnneeded":
				if value != "yes" && value != "no" {
					return errors.New("invalid vendor unit dump terminator")
				}
			}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.New("systemd manager snapshot truncated or unreadable")
	}
	if !header || !targetSeen || len(seen) != 5 {
		return errors.New("systemd manager snapshot missing complete vendor identity")
	}
	return nil
}

func vendorStopSystemd249Dump(ctx context.Context, version int) error {
	if ctx == nil || ctx.Err() != nil || (version != 249 && version != 250) {
		return errors.New("legacy systemd manager inspection unavailable")
	}
	bound, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// systemd-analyze dump retrieves PID1's actual in-memory dependency
	// snapshot over the local manager D-Bus method DumpByFileDescriptor.
	// No inherited DBUS_*, SYSTEMCTL_*, loader, pager, host or remote setting.
	// Consume it as a stream: do not materialize the entire host's dump.
	cmd := exec.CommandContext(bound, "/usr/bin/systemd-analyze", "--system", "--no-pager", "dump")
	cmd.Env = nativeSystemdFixedEnvironment()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errors.New("systemd dependency snapshot stream unavailable")
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return errors.New("systemd dependency snapshot failed to start")
	}
	parsed := vendorStopParseLegacyManagerDump(stdout, version)
	if parsed != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if parsed != nil {
		return parsed
	}
	if waitErr != nil || stderr.Len() != 0 || bound.Err() != nil {
		return errors.New("systemd dependency snapshot incomplete; no STOP allowed")
	}
	return nil
}
