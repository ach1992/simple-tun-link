package wireguard

import (
	"context"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Overhead is the data-packet overhead for the currently supported IPv4
// WireGuard/UDP backend: outer IPv4 (20), UDP (8), WG data header/tag (32).
// It is not a presumed MTU and never modifies the link's configured MTU.
func Overhead(link domain.Link) (int, error) {
	if err := validateLink(link); err != nil {
		return 0, err
	}
	return 20 + 8 + 32, nil
}

// Capability is observational. wg show interfaces inspects the userspace
// tool and active kernel interface visibility without reading private keys.
func (b *Backend) Capability(ctx context.Context, link domain.Link) (linux.CapabilityStatus, error) {
	if err := validateLink(link); err != nil {
		return linux.CapabilityStatus{}, err
	}
	if ctx == nil {
		return linux.CapabilityStatus{Reason: "WireGuard diagnostic context unavailable"}, nil
	}
	if err := ctx.Err(); err != nil {
		return linux.CapabilityStatus{}, err
	}
	if _, err := b.runner.Run(ctx, b.wgBinary, "show", "interfaces"); err != nil {
		if ctx.Err() != nil {
			return linux.CapabilityStatus{}, ctx.Err()
		}
		return linux.CapabilityStatus{Reason: "WireGuard tool/kernel observation unavailable"}, nil
	}
	return linux.CapabilityStatus{Available: true}, nil
}
