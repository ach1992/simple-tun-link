package spoof

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestDiscoveryPacesButDoesNotTruncateSourceInventory(t *testing.T) {
	var inv Inventory
	for i := 1; i <= 301; i++ {
		inv.Addresses = append(inv.Addresses, netip.MustParseAddr(fmt.Sprintf("10.1.%d.%d", i/256, i%256)))
	}
	c := DiscoveryCursor{}
	all := map[netip.Addr]bool{}
	for cycle := 0; cycle < 61; cycle++ {
		batch, err := c.NextBatch(inv, 5)
		if err != nil || len(batch) == 0 || len(batch) > 5 {
			t.Fatalf("invalid batch: %d %v", len(batch), err)
		}
		for _, ip := range batch {
			all[ip] = true
		}
	}
	if len(all) != 301 {
		t.Fatalf("discovery truncated inventory to %d/301", len(all))
	}
}

func TestDiscoveryPrefersLastWorkingButRespectsFileChange(t *testing.T) {
	original := Inventory{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("192.0.2.12")}}
	c := DiscoveryCursor{}
	c.PreferredSucceeded(netip.MustParseAddr("192.0.2.12"))
	b, err := c.NextBatch(original, 1)
	if err != nil || b[0] != c.Preferred {
		t.Fatalf("did not prioritize known-working source %v %v", b, err)
	}
	b, err = c.NextBatch(original, 1)
	if err != nil || b[0] != original.Addresses[0] {
		t.Fatalf("round skipped other source %v %v", b, err)
	}
	changed := Inventory{Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.30")}}
	b, err = c.NextBatch(changed, 1)
	if err != nil || len(b) != 1 || b[0] != changed.Addresses[0] {
		t.Fatalf("source removal not applied %v %v", b, err)
	}
	if _, err = c.NextBatch(Inventory{}, 1); err == nil {
		t.Fatal("empty new source file ignored")
	}
}
