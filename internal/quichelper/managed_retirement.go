package quichelper

import (
	"context"
	"fmt"
	"runtime"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// VerifyRetirementHostAbsent is a fixed read-only host gate for the existing
// credential retirement adapter. The Engine must separately hold locks and
// require its exact positive original-termination receipt. Current vacancy
// alone is never proof that a missing/moved original WireGuard was deleted.
// This method opens no material and cannot delete, stop or adopt any object.
func (h *Host) VerifyRetirementHostAbsent(ctx context.Context, link domain.Link, g state.QUICGeneration) error {
	if h == nil || ctx == nil || g.Validate(link) != nil {
		return fmt.Errorf("managed QUIC original retirement identity invalid")
	}
	ctx = core.WithQUICGeneration(ctx, g)
	return h.verifyVacantHost(ctx, link, g.OriginNonce, "")
}

func (h *Host) verifyVacantHost(ctx context.Context, link domain.Link, origin, extinctBoot string) error {
	ctx, err := core.WithQUICOrigin(ctx, origin)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	host, err := h.ops.host()
	if err != nil {
		return err
	}
	if extinctBoot != "" && host.BootID == extinctBoot {
		return fmt.Errorf("managed QUIC original kernel lifetime has not ended")
	}
	spec, err := h.spec(ctx, link)
	if err != nil {
		return err
	}
	obs, err := h.ops.inspect(ctx, spec)
	if obs.Process != nil {
		_ = obs.Process.Close()
	}
	if err != nil || obs.Loaded || obs.Host != host {
		return managedError(link, "retire", "helper_not_absent", "QUIC helper is still loaded or its absence is unverified", err, false)
	}
	present, err := h.guard.GuardPresent(ctx, link)
	if err != nil || present {
		return managedError(link, "retire", "guard_not_absent", "QUIC ingress guard remains or its absence is unverified", err, false)
	}
	runner := linux.ExecRunner{}
	vacant, err := linux.WSSGlobalWGKernelVacant(ctx, runner, "wg", link.WireGuard.LocalPublicKey, link.WireGuard.ListenPort)
	if err != nil || !vacant {
		return managedError(link, "retire", "wireguard_not_absent", "WireGuard key or UDP socket is present or unverified", err, false)
	}
	plan, err := quic.PlanFromLink(link)
	if err != nil {
		return err
	}
	helperPort := plan.Underlay.Port()
	if plan.Role == quic.Dial {
		helperPort = plan.LocalForwardUDPPort
	}
	for _, port := range []uint16{link.WireGuard.ListenPort, helperPort} {
		vacant, err := linux.QUICWGAllStateUDPPortVacant(ctx, runner, port)
		if err != nil || !vacant {
			return managedError(link, "retire", "udp_not_absent", "a selected QUIC or WireGuard UDP port is occupied or unverified", err, false)
		}
	}
	again, err := h.ops.host()
	if err != nil || again != host {
		return fmt.Errorf("QUIC host changed during retirement vacancy inspection")
	}
	return ctx.Err()
}
