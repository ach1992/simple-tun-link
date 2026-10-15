package ipsec

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// systemctl runs against the local system manager. busctl uses the normal
// system bus (the private systemd socket is NOT a general D-Bus busctl
// endpoint); its caller environment is fixed, and the service-name owner
// must independently attest PID 1 before any trust-sensitive observation.
const nativeSystemdBusSelector = "--system"
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
		if len(args) < 2 || args[0] != nativeSystemdBusSelector {
			return CommandResult{}, fmt.Errorf("invalid native systemd manager observation")
		}
		switch args[1] {
		case "status":
			if len(args) != 3 || args[2] != "org.freedesktop.systemd1" {
				return CommandResult{}, fmt.Errorf("invalid native systemd manager identity request")
			}
		case "get-property", "call":
			if len(args) < 6 {
				return CommandResult{}, fmt.Errorf("invalid native systemd manager property request")
			}
		default:
			return CommandResult{}, fmt.Errorf("unsupported native systemd observation")
		}
		for _, arg := range args[2:] {
			if strings.HasPrefix(arg, "-") {
				return CommandResult{}, fmt.Errorf("native D-Bus transport option denied")
			}
		}
	case nativeSystemctlBinary:
		if len(args) < 2 || args[0] != "--system" {
			return CommandResult{}, fmt.Errorf("invalid local systemd transition")
		}
		for _, arg := range args[1:] {
			if arg == "--user" || arg == "--host" || arg == "--machine" ||
				arg == "-H" || arg == "-M" ||
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
