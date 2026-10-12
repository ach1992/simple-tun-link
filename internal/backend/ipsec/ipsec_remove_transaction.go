package ipsec

import (
	"context"
	"fmt"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// applyJournalledRemove is the only effectful per-Link IPsec teardown path.
// A VICI timeout is not a rollback signal: return without compensating and
// preserve the durable journal, so a later explicitly requested reconciliation
// can read back the exact objects under the same exclusive daemon boundary.
func (b *OperationalBackend) applyJournalledRemove(ctx context.Context, p operationalPlan) (core.Rollback, error) {
	if b.removeJournal == nil || b.advanceRemove == nil {
		return nil, fmt.Errorf("IPsec durable Remove journal unavailable")
	}
	profile := p.Profile
	checkpoint, err := b.removeJournal(ctx, profile)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect durable IPsec Remove transaction")
	}
	advance := func(to string) error {
		if err := b.advanceRemove(ctx, profile, checkpoint.Phase, to); err != nil {
			return fmt.Errorf("IPsec Remove transaction phase not durably verified")
		}
		checkpoint.Phase = to
		return nil
	}
	for {
		if err := b.authorize(ctx); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("interrupted IPsec Remove requires journal reconciliation")
		}
		// No destructive phase may rely on a name-only device. If an interface
		// still exists it must be exactly the committed original ifindex.
		device, err := b.inspectDevice(ctx, profile)
		if err != nil {
			return nil, err
		}
		if device.Exists && (checkpoint.IfIndex <= 0 || device.Index != checkpoint.IfIndex ||
			!device.matches(profile)) {
			return nil, fmt.Errorf("IPsec interface is not the journal's original owned device")
		}
		if !device.Exists && checkpoint.IfIndex > 0 &&
			checkpoint.Phase != state.IPsecRemoveIssuingDevice &&
			checkpoint.Phase != state.IPsecRemoveDeviceAbsent {
			return nil, fmt.Errorf("IPsec owned device disappeared before its journaled deletion")
		}
		switch checkpoint.Phase {
		case state.IPsecRemovePrepared:
			if err := advance(state.IPsecRemoveIssuingTerminate); err != nil {
				return nil, err
			}
		case state.IPsecRemoveIssuingTerminate:
			sa, err := b.hasIPsecSA(ctx, profile)
			if err != nil {
				return nil, fmt.Errorf("cannot inspect scoped IPsec SA before termination")
			}
			if sa {
				observation, err := b.Writer.Inspect(ctx, profile)
				if err != nil || !observation.ConnectionNamePresent {
					return nil, fmt.Errorf("active IPsec SA lacks proven owned connection")
				}
				if err = b.Writer.Terminate(ctx, profile); err != nil {
					return nil, fmt.Errorf("IPsec SA termination uncertain; explicit reconciliation required")
				}
				// An acknowledged VICI termination may precede the kernel's
				// final XFRM readback. Do not reissue a VICI mutation.
				if err := waitForIPsecSAAbsence(ctx, func(ctx context.Context) (bool, error) {
					return b.hasIPsecSA(ctx, profile)
				}); err != nil {
					return nil, err
				}
			}
			if err := advance(state.IPsecRemoveTerminated); err != nil {
				return nil, err
			}
		case state.IPsecRemoveTerminated:
			if err := advance(state.IPsecRemoveIssuingConnection); err != nil {
				return nil, err
			}
		case state.IPsecRemoveIssuingConnection:
			objects, err := b.Writer.Inspect(ctx, profile)
			if err != nil {
				return nil, fmt.Errorf("unverifiable scoped connection before unload")
			}
			if objects.ConnectionNamePresent {
				if !objects.SecretNamePresent {
					return nil, fmt.Errorf("unowned partial IPsec credential state")
				}
				if err = b.Writer.UnloadConnection(ctx, profile); err != nil {
					return nil, fmt.Errorf("IPsec connection unload uncertain; explicit reconciliation required")
				}
			}
			objects, err = b.Writer.Inspect(ctx, profile)
			if err != nil || objects.ConnectionNamePresent {
				return nil, fmt.Errorf("scoped IPsec connection absence not observed")
			}
			if err := advance(state.IPsecRemoveConnectionAbsent); err != nil {
				return nil, err
			}
		case state.IPsecRemoveConnectionAbsent:
			if err := advance(state.IPsecRemoveIssuingShared); err != nil {
				return nil, err
			}
		case state.IPsecRemoveIssuingShared:
			objects, err := b.Writer.Inspect(ctx, profile)
			if err != nil || objects.ConnectionNamePresent {
				return nil, fmt.Errorf("connection reappeared during scoped credential unload")
			}
			if objects.SecretNamePresent {
				if err = b.Writer.UnloadShared(ctx, profile); err != nil {
					return nil, fmt.Errorf("IPsec shared credential unload uncertain; explicit reconciliation required")
				}
			}
			objects, err = b.Writer.Inspect(ctx, profile)
			if err != nil || objects.ConnectionNamePresent || objects.SecretNamePresent {
				return nil, fmt.Errorf("scoped IPsec credential absence not observed")
			}
			if err := advance(state.IPsecRemoveSharedAbsent); err != nil {
				return nil, err
			}
		case state.IPsecRemoveSharedAbsent:
			// A failed IKE termination may leave a policy or SA even after a VICI
			// object disappears. Never delete the XFRM interface until both are gone.
			if err := b.requireIPsecKernelEffectsVacant(ctx, profile); err != nil {
				return nil, err
			}
			if err := advance(state.IPsecRemoveIssuingDevice); err != nil {
				return nil, err
			}
		case state.IPsecRemoveIssuingDevice:
			if err := b.requireIPsecKernelEffectsVacant(ctx, profile); err != nil {
				return nil, err
			}
			if device.Exists {
				if err = b.Delete(ctx, device.Index); err != nil {
					return nil, fmt.Errorf("scoped IPsec interface deletion uncertain; explicit reconciliation required")
				}
			}
			if err = b.XFRM.RequireVacant(ctx, profile); err != nil {
				return nil, fmt.Errorf("owned IPsec kernel cleanup not verifiably complete")
			}
			if err := advance(state.IPsecRemoveDeviceAbsent); err != nil {
				return nil, err
			}
		case state.IPsecRemoveDeviceAbsent:
			objects, err := b.Writer.Inspect(ctx, profile)
			if err != nil || objects.ConnectionNamePresent || objects.SecretNamePresent {
				return nil, fmt.Errorf("removed IPsec daemon objects reappeared")
			}
			if err = b.XFRM.RequireVacant(ctx, profile); err != nil {
				return nil, fmt.Errorf("removed IPsec kernel resources not vacant")
			}
			// Successful state commit deletes the journal and the committed Link in
			// one fsynced state transaction. Never automatically reload a removed
			// connection/PSK during rollback of a partially issued Remove.
			return func(context.Context) error {
				return fmt.Errorf("IPsec Remove is journaled; use explicit scoped reconciliation instead of rollback")
			}, nil
		default:
			return nil, fmt.Errorf("unknown IPsec Remove journal phase")
		}
	}
}

func (b *OperationalBackend) requireIPsecKernelEffectsVacant(ctx context.Context, p Profile) error {
	ip := b.XFRM.IPBinary
	if ip == "" {
		ip = b.IPBinary
	}
	for _, kind := range []string{"policy", "state"} {
		raw, err := b.XFRM.read(ctx, ip, true, "-json", "xfrm", kind)
		if err != nil {
			return fmt.Errorf("IPsec kernel state uninspectable")
		}
		collision, inspectErr := xfrmInventoryUsesIDContext(ctx, raw, p.InterfaceID, kind)
		clear(raw)
		if inspectErr != nil || collision {
			return fmt.Errorf("scoped IPsec policy/SA not proven absent")
		}
	}
	return nil
}
