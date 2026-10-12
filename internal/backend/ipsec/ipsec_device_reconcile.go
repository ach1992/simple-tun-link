package ipsec

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type DeviceCheckpoint struct {
	Phase   string
	IfIndex int
}

// AbortJournalledDevice may run only from the Engine's explicit, locked
// reconciliation. The durable pre-alias ifindex is mandatory whenever a
// created device exists; an issuing-create record cannot prove ownership.
// No kernel policy/SA or matching foreign interface is ever adopted.
func (b *OperationalBackend) AbortJournalledDevice(ctx context.Context, p Profile,
	checkpoint DeviceCheckpoint, advance func(string, string, int) error) error {
	if err := b.authorize(ctx); err != nil {
		return err
	}
	if b.advanceDevice == nil {
		return fmt.Errorf("durable device writer unavailable")
	}
	if err := b.requireIPsecKernelEffectsVacant(ctx, p); err != nil {
		return err
	}
	device, err := b.inspectDevice(ctx, p)
	if err != nil {
		return err
	}
	switch checkpoint.Phase {
	case state.IPsecXFRMPrepared, state.IPsecXFRMIssuingCreate:
		// No original ifindex was ever durably recorded. A foreign same-name
		// device may be present; inspect only. If the ENTIRE identity is vacant,
		// it is safe to clear a pre-effect or failed-issuance journal without
		// issuing any delete.
		if checkpoint.IfIndex != 0 || b.XFRM.RequireVacant(ctx, p) != nil {
			return fmt.Errorf("pre-index XFRM creation is ambiguous; manual host reconciliation required")
		}
		return nil
	case state.IPsecXFRMIndexed, state.IPsecXFRMAliased,
		state.IPsecXFRMConfigured, state.IPsecXFRMIssuingAbort:
		if checkpoint.IfIndex <= 0 {
			return fmt.Errorf("durable XFRM ifindex missing")
		}
	default:
		return fmt.Errorf("invalid XFRM recovery phase")
	}
	if device.Exists {
		// A trusted journal+original ifindex+exact XFRM interface ID and owner
		// state are required. Even if the derived name matches, a replaced device
		// with a different ifindex is never deleted.
		if device.Index != checkpoint.IfIndex || device.ID != p.InterfaceID {
			return fmt.Errorf("XFRM recovery device identity differs from journal")
		}
		expectedTag, err := domain.OwnerTag(p.Link.ID)
		if err != nil {
			return fmt.Errorf("invalid XFRM owner tag")
		}
		if checkpoint.Phase == state.IPsecXFRMIndexed {
			if device.Alias != "" && device.Alias != expectedTag {
				return fmt.Errorf("untrusted pre-alias XFRM replacement")
			}
		} else if checkpoint.Phase == state.IPsecXFRMAliased || checkpoint.Phase == state.IPsecXFRMConfigured {
			if device.Alias != expectedTag {
				return fmt.Errorf("XFRM verified owner alias missing or replaced")
			}
		} else if device.Alias != "" && device.Alias != expectedTag {
			return fmt.Errorf("XFRM alias differs from recorded owner")
		}
		// An indexed but not-yet-aliased device may not have Link Address or UP.
		// The journal, original kernel ifindex and matched if_id jointly prove
		// the exact object; name/if_id/alias alone never do.
	}
	if checkpoint.Phase != state.IPsecXFRMIssuingAbort {
		if err := advance(checkpoint.Phase, state.IPsecXFRMIssuingAbort, checkpoint.IfIndex); err != nil {
			return fmt.Errorf("XFRM recovery deletion intent not durable")
		}
	}
	if device.Exists {
		if err := b.Delete(ctx, device.Index); err != nil {
			return fmt.Errorf("XFRM recovery delete uncertain; journal retained")
		}
	}
	if err := b.XFRM.RequireVacant(ctx, p); err != nil {
		return fmt.Errorf("XFRM recovery cleanup not verifiably vacant")
	}
	return nil
}
