// Package spoof provides range-diverse, exhaustive discovery over exactly
// the operator's local IPv4 inventory, without treating a prefix as policy.
package spoof

import (
	"errors"
	"net/netip"
)

// DiscoveryCursor is prepared only when the local inventory changes. Batches
// then cost O(batch), not O(total source count). This matters when a Link must
// eventually try tens of thousands of different IPv4 sources.
type DiscoveryCursor struct {
	Preferred netip.Addr
	ordered   []netip.Addr
	positions map[netip.Addr]int
	next      int
	passes    uint64
}

// interleavePrefix schedules one member from each distinct IPv4 prefix before
// the next member of that prefix. A queue of non-exhausted buckets guarantees
// O(n) construction even for very skewed inventory distributions.
func interleavePrefix(addresses []netip.Addr, octets int) []netip.Addr {
	type bucket struct {
		values []netip.Addr
		next   int
	}
	index := make(map[uint32]int)
	groups := make([]bucket, 0)
	for _, addr := range addresses {
		raw := addr.As4()
		key := uint32(raw[0])<<8 | uint32(raw[1])
		if octets == 3 {
			key = key<<8 | uint32(raw[2])
		}
		i, exists := index[key]
		if !exists {
			i = len(groups)
			index[key] = i
			groups = append(groups, bucket{})
		}
		groups[i].values = append(groups[i].values, addr)
	}
	queue := make([]int, len(groups))
	for i := range queue {
		queue[i] = i
	}
	result := make([]netip.Addr, 0, len(addresses))
	for head := 0; head < len(queue); head++ {
		i := queue[head]
		group := &groups[i]
		result = append(result, group.values[group.next])
		group.next++
		if group.next < len(group.values) {
			queue = append(queue, i)
		}
	}
	return result
}

// ReplaceInventory is called only after the owning Agent confirms a changed
// local file and successfully replaces its exact-peer RawSender. First spread
// attempts across /24s, then across /16s, then eventually exhaust every IP.
// These groupings are scheduling heuristics: a failed address never blacklists
// the rest of its prefix and no ASN/country/ownership rule is inferred.
func (c *DiscoveryCursor) ReplaceInventory(inventory Inventory) error {
	c.ordered = nil
	c.positions = nil
	c.next = 0
	c.passes = 0
	if len(inventory.Addresses) == 0 {
		return errors.New("spoof discovery has no source candidates; Recheck local source file")
	}
	for _, a := range inventory.Addresses {
		if !a.Is4() {
			return errors.New("spoof discovery only accepts literal IPv4 candidates")
		}
	}
	c.ordered = interleavePrefix(interleavePrefix(inventory.Addresses, 3), 2)
	c.positions = make(map[netip.Addr]int, len(c.ordered))
	for i, addr := range c.ordered {
		c.positions[addr] = i
	}
	if index, found := c.positions[c.Preferred]; found && index > 0 {
		// Restore the last working Source without changing the relative
		// order of the remaining candidates in this new inventory.
		preferred := c.ordered[index]
		copy(c.ordered[1:index+1], c.ordered[:index])
		c.ordered[0] = preferred
		for i := 0; i <= index; i++ {
			c.positions[c.ordered[i]] = i
		}
	}
	return nil
}

// NextBatch returns at most perCycle distinct candidates, cycling through all
// loaded addresses without a hard inventory cap. It never reorders or copies
// the full inventory during steady-state retries.
func (c *DiscoveryCursor) NextBatch(perCycle int) ([]netip.Addr, error) {
	if perCycle <= 0 {
		return nil, errors.New("spoof discovery per-cycle packet budget must be positive")
	}
	if len(c.ordered) == 0 {
		return nil, errors.New("spoof discovery has no source candidates; Recheck local source file")
	}
	size := min(perCycle, len(c.ordered))
	result := make([]netip.Addr, 0, size)
	for len(result) < size {
		end := min(len(c.ordered), c.next+size-len(result))
		result = append(result, c.ordered[c.next:end]...)
		c.next = end
		if c.next == len(c.ordered) {
			c.next = 0
			c.passes++
		}
	}
	return result, nil
}

// PreferredSucceeded brings an authenticated, bilaterally working source to
// the front in O(1); it does not permit sources missing from this inventory.
func (c *DiscoveryCursor) PreferredSucceeded(addr netip.Addr) {
	if !addr.Is4() {
		return
	}
	c.Preferred = addr
	if index, found := c.positions[addr]; found && index != 0 {
		first := c.ordered[0]
		c.ordered[0], c.ordered[index] = c.ordered[index], c.ordered[0]
		c.positions[first] = index
		c.positions[addr] = 0
	}
	c.next = 0
}

// DiscoveryBatchSize scales the per-tick work toward a bounded complete pass,
// preserving small-inventory behavior while limiting receiver bursts. It is a
// packet rate budget, not a limit on how many supplied sources may be tried.
func DiscoveryBatchSize(candidates int) int {
	if candidates <= 0 {
		return 0
	}
	// At the current 700ms helper tick, this is at most ~23
	// discovery datagrams/second per Link. Large inventories can take
	// tens of minutes or hours to exhaust: complete coverage and stable
	// operation matter more than probing quickly.
	return min(16, max(4, 1+(candidates-1)/700))
}

// Progress describes the deterministic candidate schedule, NOT confirmed
// delivery of probes or a remote connection. Position resets on each complete
// pass and when a new source file snapshot replaces the prior inventory.
func (c *DiscoveryCursor) Progress() (position int, passes uint64) {
	return c.next, c.passes
}
