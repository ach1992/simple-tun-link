package spoof

import (
	"net/netip"
	"testing"
)

func TestSourceProtocolDestinationExhaustiveNoRepeat(t *testing.T) {
	var inv Inventory
	for i := 1; i <= 37; i++ {
		inv.Addresses = append(inv.Addresses, netip.AddrFrom4([4]byte{198, 18, 0, byte(i)}))
	}
	dst := []netip.AddrPort{netip.MustParseAddrPort("10.244.62.198:48002"), netip.MustParseAddrPort("10.244.62.212:48012")}
	var c DiscoveryCursor
	if err := c.ReplaceInventory(inv); err != nil {
		t.Fatal(err)
	}
	total := len(inv.Addresses) * len(AllProfiles()) * len(dst)
	seen := make(map[SourcePath]bool, total)
	for len(seen) < total {
		batch, err := c.NextRouteBatch(AllProfiles(), dst, 7)
		if err != nil || len(batch) > 7 || len(batch) == 0 {
			t.Fatalf("batch=%d err=%v", len(batch), err)
		}
		for _, p := range batch {
			if seen[p] {
				t.Fatalf("duplicate combination prior to complete pass: %v", p)
			}
			seen[p] = true
		}
	}
	if len(seen) != total {
		t.Fatalf("missed path %d/%d", len(seen), total)
	}
	_, _, passes := c.PathProgress()
	if passes != 1 {
		t.Fatalf("expected complete Cartesian scan got %d", passes)
	}
}
