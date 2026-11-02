package managedmtu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/gre"
	"github.com/ach1992/simple-tun-link/internal/backend/ipip"
	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/backend/l2tpv3"
	"github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// HostMTUManager uses the same inspected, ifindex-pinned ownership boundary as
// Link creation. It is NOT used by read-only diagnostics or Quick Link pairing.
type HostMTUManager struct {
	Runner     linux.Runner
	SetByIndex func(context.Context, int, int) error
}

type mtuInterface struct {
	IfIndex int    `json:"ifindex"`
	IfName  string `json:"ifname"`
	IfAlias string `json:"ifalias"`
	MTU     int    `json:"mtu"`
}

func (m HostMTUManager) inspect(ctx context.Context, name string) (mtuInterface, error) {
	if m.Runner == nil {
		return mtuInterface{}, fmt.Errorf("MTU observer unavailable")
	}
	result, err := m.Runner.Run(ctx, "ip", "-json", "link", "show", "dev", name)
	if err != nil {
		return mtuInterface{}, fmt.Errorf("MTU link inspection failed")
	}
	var rows []mtuInterface
	if err := json.Unmarshal(result.Stdout, &rows); err != nil || len(rows) != 1 ||
		rows[0].IfIndex <= 0 || rows[0].IfName != name ||
		rows[0].MTU < 68 || rows[0].MTU > 65535 {
		return mtuInterface{}, fmt.Errorf("MTU interface identity or value is invalid")
	}
	return rows[0], nil
}

func mtuIdentity(link domain.Link) (string, int, error) {
	switch link.Backend {
	case domain.BackendGRE:
		name, err := gre.InterfaceName(link.ID)
		if err != nil {
			return "", 0, err
		}
		n, err := gre.Overhead(link)
		return name, n, err
	case domain.BackendL2TPv3:
		name, err := l2tpv3.InterfaceName(link.ID)
		if err != nil {
			return "", 0, err
		}
		n, err := l2tpv3.Overhead(link)
		return name, n, err
	case domain.BackendIPIP:
		name, err := ipip.InterfaceName(link.ID)
		if err != nil {
			return "", 0, err
		}
		n, err := ipip.Overhead(link)
		return name, n, err
	case domain.BackendWireGuard:
		name, err := wireguard.InterfaceName(link.ID)
		if err != nil {
			return "", 0, err
		}
		n, err := wireguard.Overhead(link)
		return name, n, err
	case domain.BackendWireGuardQUIC:
		name, err := wireguard.InterfaceName(link.ID)
		// QUIC fragments the forwarded datagram; it has no fixed native-WG
		// overhead to subtract from the physical device MTU.
		return name, 0, err
	case domain.BackendIPsec:
		profile, err := ipsec.NewProfile(link)
		if err != nil {
			return "", 0, err
		}
		n, err := ipsec.DiagnosticOverhead(link)
		return profile.InterfaceName, n, err
	default:
		return "", 0, fmt.Errorf("managed MTU backend is unsupported")
	}
}

func (m HostMTUManager) desired(ctx context.Context, link domain.Link, overhead int) (int, error) {
	if overhead <= 0 && link.Backend != domain.BackendWireGuardQUIC {
		return 0, fmt.Errorf("MTU backend overhead unavailable")
	}
	route, err := (linux.RouteResolver{Runner: m.Runner}).Resolve(ctx, link.Underlay.Peer)
	if err != nil || route.Source != link.Underlay.Local {
		return 0, fmt.Errorf("MTU underlay route/source is unverified")
	}
	dev, err := m.inspect(ctx, route.Device)
	if err != nil {
		return 0, err
	}
	underlay := dev.MTU
	if route.MTU > 0 && route.MTU < underlay {
		underlay = route.MTU
	}
	ceiling := underlay - overhead
	if link.Backend == domain.BackendWireGuardQUIC {
		minimum, err := quic.MinimumIPv4UnderlayMTU(link.QUIC.Obfuscation)
		if err != nil {
			return 0, err
		}
		if underlay < minimum {
			return 0, fmt.Errorf("QUIC local underlay cannot carry the required datagram for the selected obfuscation mode")
		}
		plan, err := quic.PlanFromLink(link)
		if err != nil {
			return 0, err
		}
		ceiling, err = quic.MaximumWireGuardMTU(plan)
		if err != nil {
			return 0, err
		}
	}
	if ceiling < 68 {
		return 0, fmt.Errorf("MTU underlay cannot carry supported inner IPv4 datagrams")
	}
	switch link.MTU.Mode {
	case domain.MTUAuto:
		// PMTU probes are observational and may be unavailable before both
		// peers complete pairing. Do not pretend this is a measured path MTU.
		// The explicit conservative startup setting is durable and replayable.
		return min(1280, ceiling), nil
	case domain.MTUManual:
		if link.MTU.Bytes < 68 || link.MTU.Bytes > ceiling {
			if link.Backend == domain.BackendWireGuardQUIC {
				return 0, fmt.Errorf("manual MTU exceeds the pinned QUIC helper's datagram capacity")
			}
			return 0, fmt.Errorf("manual MTU exceeds the verified local route/device ceiling")
		}
		return link.MTU.Bytes, nil
	default:
		return 0, fmt.Errorf("managed MTU mode is unsupported")
	}
}

func claimsHaveInterface(claims []domain.ResourceClaim, name string) bool {
	for _, claim := range claims {
		if claim.Kind == domain.ResourceInterface && claim.Key == name {
			return true
		}
	}
	return false
}

// CaptureL2TPRemove pins the actual pre-Remove MTU while Engine holds the
// existing Link and resource locks. Its compensation is called only AFTER the
// backend positively proves restoration of the owned tunnel/session/interface;
// the verified current ifindex is supplied by that fresh kernel observation.
// No MTU policy is recomputed on the failure path.
func (m HostMTUManager) CaptureL2TPRemove(ctx context.Context, link domain.Link, originalIndex int, claims []domain.ResourceClaim) (func(context.Context, int) error, error) {
	if link.Backend != domain.BackendL2TPv3 ||
		(link.MTU.Mode != domain.MTUManual && link.MTU.Mode != domain.MTUAuto) ||
		originalIndex <= 0 || m.SetByIndex == nil {
		return nil, fmt.Errorf("managed L2TPv3 Remove MTU restoration is unavailable")
	}
	name, _, err := mtuIdentity(link)
	if err != nil || !claimsHaveInterface(claims, name) {
		return nil, errors.Join(errors.New("managed L2TPv3 Remove has no exact owned interface claim"), err)
	}
	alias, err := linux.OwnerTag(link.ID)
	if err != nil {
		return nil, err
	}
	original, err := m.inspect(ctx, name)
	if err != nil || original.IfIndex != originalIndex || original.IfAlias != alias {
		return nil, errors.Join(errors.New("cannot capture owned L2TPv3 interface MTU before Remove"), err)
	}
	return func(undoCtx context.Context, verifiedIndex int) error {
		current, readErr := m.inspect(undoCtx, name)
		if readErr != nil || verifiedIndex <= 0 || current.IfIndex != verifiedIndex || current.IfAlias != alias {
			return errors.Join(errors.New("cannot restore L2TPv3 MTU: restored interface identity is unverified"), readErr)
		}
		if verifiedIndex == originalIndex {
			// The original kernel ifindex survived, or was reused. Do not
			// overwrite an unexpected MTU on an unproved generation.
			if current.MTU != original.MTU {
				return fmt.Errorf("cannot restore L2TPv3 MTU: original interface changed unexpectedly")
			}
			return nil
		}
		if current.MTU == original.MTU {
			return nil
		}
		// Guard against an intervening interface replacement immediately
		// before the ifindex-bound netlink mutation.
		before, checkErr := m.inspect(undoCtx, name)
		if checkErr != nil || before != current {
			return errors.Join(errors.New("cannot restore L2TPv3 MTU: interface changed before mutation"), checkErr)
		}
		if err := m.SetByIndex(undoCtx, verifiedIndex, original.MTU); err != nil {
			return fmt.Errorf("L2TPv3 compensating MTU write failed or took uncertain effect: %w", err)
		}
		after, checkErr := m.inspect(undoCtx, name)
		if checkErr != nil || after.IfIndex != verifiedIndex || after.IfAlias != alias ||
			after.MTU != original.MTU {
			return errors.Join(errors.New("L2TPv3 compensating MTU readback is unverified"), checkErr)
		}
		return nil
	}, nil
}

func (m HostMTUManager) Apply(ctx context.Context, req backend.Request, observedBefore bool, claims []domain.ResourceClaim) (backend.Rollback, bool, error) {
	if req.Operation != backend.OperationEnsure ||
		(req.Link.MTU.Mode != domain.MTUAuto && req.Link.MTU.Mode != domain.MTUManual) {
		return nil, false, nil
	}
	if err := req.Link.MTU.Validate(); err != nil {
		return nil, false, err
	}
	if m.SetByIndex == nil {
		return nil, false, fmt.Errorf("MTU mutation facility is unavailable")
	}
	name, overhead, err := mtuIdentity(req.Link)
	if err != nil {
		return nil, false, err
	}
	if !claimsHaveInterface(claims, name) {
		return nil, false, fmt.Errorf("MTU Link interface is not part of the exact resource plan")
	}
	// A first Ensure must not treat an already-existing, not-yet-committed
	// interface as its own simply because a marker/name matches.
	if req.Prior == nil && observedBefore {
		return nil, false, fmt.Errorf("MTU cannot adopt an uncommitted interface")
	}
	wanted, err := m.desired(ctx, req.Link, overhead)
	if err != nil {
		return nil, false, err
	}
	old, err := m.inspect(ctx, name)
	if err != nil {
		return nil, false, err
	}
	alias, err := linux.OwnerTag(req.Link.ID)
	if req.Link.Backend == domain.BackendWireGuardQUIC {
		alias, err = linux.QUICWGOwnerTag(req.Link.ID, backend.QUICOrigin(ctx))
	}
	if err != nil || old.IfAlias != alias {
		return nil, false, fmt.Errorf("MTU target is not an exactly owner-marked STL Link")
	}
	if old.MTU == wanted {
		return nil, false, nil
	}
	// Recheck both the captured ifindex and owner immediately before writing.
	before, err := m.inspect(ctx, name)
	if err != nil || before != old {
		return nil, false, fmt.Errorf("MTU target changed before mutation")
	}
	undo := func(undoCtx context.Context) error {
		now, readErr := m.inspect(undoCtx, name)
		if readErr != nil || now.IfIndex != old.IfIndex || now.IfAlias != alias || now.MTU != wanted {
			return fmt.Errorf("cannot roll back MTU: original owner/index or exact applied value is not proven")
		}
		if err := m.SetByIndex(undoCtx, old.IfIndex, old.MTU); err != nil {
			return fmt.Errorf("MTU rollback netlink operation failed: %w", err)
		}
		reverted, err := m.inspect(undoCtx, name)
		if err != nil || reverted.IfIndex != old.IfIndex || reverted.IfAlias != alias || reverted.MTU != old.MTU {
			return fmt.Errorf("MTU rollback outcome is unverified")
		}
		return nil
	}
	if err := m.SetByIndex(ctx, old.IfIndex, wanted); err != nil {
		// A failed netlink call may still have reached the kernel. Return a
		// guarded undo and explicitly uncertain mutation to the Engine.
		return undo, true, fmt.Errorf("MTU mutation failed or may have taken effect: %w", err)
	}
	after, err := m.inspect(ctx, name)
	if err != nil || after.IfIndex != old.IfIndex || after.IfAlias != alias || after.MTU != wanted {
		return undo, true, errors.New("MTU post-apply verification failed; guarded rollback required")
	}
	return undo, true, nil
}
