package ipsec

import (
	"context"
	"errors"
	"strings"
)

// The well-known systemd bus name must belong to local PID1, not an
// independently selected D-Bus service. busctl status reports kernel-sourced
// peer credentials; this observation is safe and read-only. A fixed executor
// environment prevents DBUS_SYSTEM_BUS_ADDRESS from redirecting the bus.
// PID1's own process identity is independently checked by the kernel /proc
// name inspection already used by systemctl on supported systemd hosts.
func (a NativeRuntimeAdmission) attestSystemdManagerIdentity(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || a.Runner == nil {
		return errors.New("native systemd manager identity unavailable")
	}
	result, err := a.Runner.RunBounded(ctx, CaptureLimits{Stdout: 4096, Stderr: 1024},
		nativeBusctl, nativeSystemdBusSelector, "status", "org.freedesktop.systemd1")
	defer clear(result.Stdout)
	defer clear(result.Stderr)
	if err != nil || len(result.Stdout) == 0 || len(result.Stdout) > 4096 ||
		len(result.Stderr) != 0 || result.Stdout[len(result.Stdout)-1] != '\n' ||
		strings.IndexByte(string(result.Stdout), 0) >= 0 {
		return errors.New("native systemd manager bus owner unverified")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(result.Stdout), "\n"), "\n") {
		for _, kv := range [][2]string{{"PID", "1"}, {"UID", "0"}, {"Comm", "systemd"}} {
			if strings.HasPrefix(line, kv[0]+"=") {
				if seen[kv[0]] || line != kv[0]+"="+kv[1] {
					return errors.New("native systemd bus owner differs from local PID1")
				}
				seen[kv[0]] = true
			}
		}
	}
	if !seen["PID"] || !seen["UID"] || !seen["Comm"] {
		return errors.New("native systemd bus owner identity incomplete")
	}
	return nil
}
