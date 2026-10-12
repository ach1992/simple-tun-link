package ipsec

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"time"
)

// HostRoute is the minimal underlay fact required by the IPsec data plane.
// Concrete distro resolver and netlink effects are assembled by the caller,
// keeping this independent of Linux's high-level shared backend package.
type HostRoute struct {
	Source netip.Addr
	Device string
}

type HostRouteResolver interface {
	Resolve(context.Context, netip.Addr) (HostRoute, error)
}

type HostRouteResolveFunc func(context.Context, netip.Addr) (HostRoute, error)

func (f HostRouteResolveFunc) Resolve(ctx context.Context, dst netip.Addr) (HostRoute, error) {
	if f == nil {
		return HostRoute{}, fmt.Errorf("underlay route resolver unavailable")
	}
	return f(ctx, dst)
}

type CaptureLimits struct{ Stdout, Stderr int }
type CommandResult struct{ Stdout, Stderr []byte }
type BoundedCommandRunner interface {
	RunBounded(context.Context, CaptureLimits, string, ...string) (CommandResult, error)
}

// BoundedExecRunner is an explicit, no-shell and never-secret-logging Linux
// command boundary. The injected runner is distinct from the main Linux
// backend package so app.Engine can import ipsec without import cycles.
type BoundedExecRunner struct{ Timeout time.Duration }

type privateCapture struct {
	output   bytes.Buffer
	max      int
	overflow bool
}

func (w *privateCapture) Write(p []byte) (int, error) {
	if len(p) > w.max-w.output.Len() {
		w.overflow = true
		return 0, fmt.Errorf("bounded command output exceeded")
	}
	return w.output.Write(p)
}

func (r BoundedExecRunner) RunBounded(ctx context.Context, limits CaptureLimits, command string, args ...string) (CommandResult, error) {
	if ctx == nil || ctx.Err() != nil || limits.Stdout <= 0 || limits.Stderr <= 0 ||
		limits.Stdout > 4<<20 || limits.Stderr > 64<<10 ||
		len(command) == 0 || command[0] == '-' {
		return CommandResult{}, fmt.Errorf("invalid bounded IPsec execution request")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	bound, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := &privateCapture{max: limits.Stdout}
	errOut := &privateCapture{max: limits.Stderr}
	cmd := exec.CommandContext(bound, command, args...)
	cmd.Stdout = out
	cmd.Stderr = errOut
	err := cmd.Run()
	if err != nil || out.overflow || errOut.overflow || bound.Err() != nil {
		out.output.Reset()
		errOut.output.Reset()
		return CommandResult{}, fmt.Errorf("bounded IPsec command did not complete successfully")
	}
	return CommandResult{Stdout: bytes.Clone(out.output.Bytes()), Stderr: bytes.Clone(errOut.output.Bytes())}, nil
}
