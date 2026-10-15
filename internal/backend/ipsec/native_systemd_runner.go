package ipsec

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Root systemctl uses the local manager's private socket. Inspect that same
// manager directly, not the caller-configurable system bus (including its
// DBUS_SYSTEM_BUS_ADDRESS override). This socket path is fixed for the
// supported systemd 249+ system manager; unavailable means fail closed.
const nativeSystemdManagerAddress = "--address=unix:path=/run/systemd/private"
const nativeSystemctlBinary = "/usr/bin/systemctl"

// No inherited DBUS_*, SYSTEMCTL_*, LD_*, GCONV_PATH, environment-based
// loaders, remote transports or pager/helper settings cross this boundary.
// This is a new independent slice on every invocation, not os.Environ().
func nativeSystemdFixedEnvironment() []string {
	return []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"LANG=C",
		"HOME=/root",
	}
}

// nativeSystemdRunner is reserved for the fixed, security-sensitive systemd
// observations and root transitions. BoundedExecRunner retains its separate
// ordinary backend behavior. Tests may inject BoundedCommandRunner fakes.
type nativeSystemdRunner struct{ Timeout time.Duration }

func (r nativeSystemdRunner) RunBounded(ctx context.Context, limits CaptureLimits, command string, args ...string) (CommandResult, error) {
	switch command {
	case nativeBusctl:
		if len(args) < 2 || args[0] != nativeSystemdManagerAddress ||
			(args[1] != "get-property" && args[1] != "call") {
			return CommandResult{}, fmt.Errorf("invalid native systemd manager observation")
		}
	case nativeSystemctlBinary:
		if len(args) < 2 || args[0] != "--system" {
			return CommandResult{}, fmt.Errorf("invalid local systemd transition")
		}
		for _, arg := range args[1:] {
			if arg == "--user" || arg == "--host" || arg == "--machine" ||
				strings.HasPrefix(arg, "--host=") || strings.HasPrefix(arg, "--machine=") ||
				strings.HasPrefix(arg, "--address=") {
				return CommandResult{}, fmt.Errorf("native systemd remote/user transport denied")
			}
		}
	default:
		return CommandResult{}, fmt.Errorf("untrusted native systemd executable")
	}
	return (BoundedExecRunner{
		Timeout: r.Timeout,
		env:     nativeSystemdFixedEnvironment(),
	}).RunBounded(ctx, limits, command, args...)
}
