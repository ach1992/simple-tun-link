package linux

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/ach1992/simple-tun-link/internal/hostaddress"
)

// LocalIPv4Endpoint is shared with the admitted IPsec reader without
// creating an app/backend import cycle.
type LocalIPv4Endpoint = hostaddress.Endpoint

func ParseLocalIPv4Endpoints(raw []byte) ([]LocalIPv4Endpoint, error) { return hostaddress.Parse(raw) }
func BoundLocalIPv4(endpoints []LocalIPv4Endpoint, local netip.Addr, device string) (LocalIPv4Endpoint, error) {
	return hostaddress.Unique(endpoints, local, device)
}
func validLocalUnderlayIPv4(ip netip.Addr) bool { return hostaddress.ValidIPv4(ip) }

// The inventory can be unexpectedly large or malformed. Both streams must be
// capped *during* capture, not after a Runner has already buffered the output.
const localIPv4StdoutLimit = 256 << 10
const localIPv4StderrLimit = 1024

func ListLocalIPv4Endpoints(ctx context.Context, runner Runner) ([]LocalIPv4Endpoint, error) {
	if ctx == nil || runner == nil {
		return nil, fmt.Errorf("local IPv4 inventory context or runner unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("local IPv4 inventory canceled: %w", err)
	}
	bounded, ok := runner.(BoundedRunner)
	if !ok {
		return nil, fmt.Errorf("local IPv4 inventory requires capture-bounded execution")
	}
	result, err := bounded.RunBounded(ctx, CaptureLimits{
		Stdout: localIPv4StdoutLimit, Stderr: localIPv4StderrLimit,
	}, "ip", "-json", "address", "show")
	if err != nil || ctx.Err() != nil {
		// Keep cancellation/timeout and overflow classifications inspectable
		// without exposing arbitrary process text or host inventory.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("local IPv4 inventory canceled: %w", ctx.Err())
		}
		if errors.Is(err, ErrOutputLimit) {
			return nil, fmt.Errorf("local IPv4 inventory exceeded capture limit: %w", ErrOutputLimit)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("local IPv4 inventory timed out: %w", context.DeadlineExceeded)
		}
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("local IPv4 inventory canceled: %w", context.Canceled)
		}
		return nil, fmt.Errorf("cannot inspect this host's assigned IPv4 interfaces")
	}
	if len(result.Stderr) != 0 || len(result.Stdout) > localIPv4StdoutLimit {
		return nil, fmt.Errorf("local IPv4 inventory is incomplete or exceeds read limit")
	}
	return ParseLocalIPv4Endpoints(result.Stdout)
}

// ErrUnderlaySourceMismatch means the kernel-selected source differed from the
// committed local endpoint, and no uniquely assigned local alternative could
// be proven. It is only used to select safe, local operator guidance.
var (
	ErrUnderlaySourceMismatch = errors.New("kernel route selected another local source")
	// These diagnoses require a successfully parsed, bounded local inventory:
	// failed captures cannot establish the recipient's identity.
	ErrUnderlayLocalNotAssigned = hostaddress.ErrNotAssigned
	ErrUnderlayLocalAmbiguous   = hostaddress.ErrAmbiguous
)

// ResolveConfiguredUnderlay chooses a locally assigned IPv4/interface for
// Create/Import/Ensure. A route-to-peer lookup may suggest the outbound
// source and device, but it is never a substitute for an independent local
// address inventory. A missing peer route, wrong route source, or wrong route
// device can fall back to the uniquely assigned local endpoint. This grants
// no foreign interface adoption or remote connectivity guarantee.
func ResolveConfiguredUnderlay(ctx context.Context, routes interface {
	Resolve(context.Context, netip.Addr) (Route, error)
}, runner Runner, local, peer netip.Addr) (Route, error) {
	if !validLocalUnderlayIPv4(local) || !peer.Is4() || !peer.IsGlobalUnicast() || peer.IsLinkLocalUnicast() || local == peer {
		return Route{}, fmt.Errorf("underlay must use two distinct usable IPv4 endpoints")
	}
	var suggested Route
	var routeErr error
	if routes != nil {
		suggested, routeErr = routes.Resolve(ctx, peer)
	}
	endpoints, err := ListLocalIPv4Endpoints(ctx, runner)
	if err != nil {
		// Local inventory is authoritative; a conflicting route hint is
		// only advisory. Preserve capture overflow/cancellation/deadline
		// identity rather than replacing the actual failure with mismatch.
		return Route{}, err
	}
	assigned, err := BoundLocalIPv4(endpoints, local, "")
	if err != nil {
		// The shared, verified local binding classifier owns absence vs
		// ambiguity. A kernel route hint is secondary, never host identity.
		if routeErr == nil && suggested.Source != local {
			return Route{}, fmt.Errorf("%w: %w", ErrUnderlaySourceMismatch, err)
		}
		return Route{}, err
	}
	if routeErr == nil && suggested.Source == local && suggested.Device == assigned.Interface &&
		validateFirewallInterface(suggested.Device) == nil {
		return suggested, nil
	}
	// Never retain an unverified kernel-suggested device/gateway/PMTU.
	// Saved Link intent stores the assigned IPv4, not a route hint.
	return Route{Peer: peer, Source: local, Device: assigned.Interface}, nil
}
