package spoof

import (
	"errors"
	"net/netip"
)

// DiscoveryCursor bounds packets *per cycle* rather than rejecting large
// operator-provided inventories. Each call can re-read sources.txt; removed
// or reordered entries are naturally reflected without re-pairing.
type DiscoveryCursor struct {
	Preferred netip.Addr
	next      int
}

func (c *DiscoveryCursor) NextBatch(inventory Inventory, perCycle int) ([]netip.Addr, error) {
	if perCycle <= 0 {
		return nil, errors.New("spoof discovery per-cycle packet budget must be positive")
	}
	if len(inventory.Addresses) == 0 {
		return nil, errors.New("spoof discovery has no source candidates; Recheck local source file")
	}
	ordered := make([]netip.Addr, 0, len(inventory.Addresses))
	if c.Preferred.IsValid() {
		for _, a := range inventory.Addresses {
			if a == c.Preferred {
				ordered = append(ordered, a)
				break
			}
		}
	}
	for _, a := range inventory.Addresses {
		if len(ordered) > 0 && a == ordered[0] && a == c.Preferred {
			continue
		}
		ordered = append(ordered, a)
	}
	if c.next >= len(ordered) {
		c.next = 0
	}
	limit := min(perCycle, len(ordered)-c.next)
	result := append([]netip.Addr(nil), ordered[c.next:c.next+limit]...)
	c.next += limit
	if c.next == len(ordered) {
		c.next = 0
	}
	return result, nil
}

func (c *DiscoveryCursor) PreferredSucceeded(addr netip.Addr) {
	if addr.Is4() {
		c.Preferred = addr
		c.next = 0
	}
}
