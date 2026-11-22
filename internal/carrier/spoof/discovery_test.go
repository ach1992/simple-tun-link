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
	if err := c.ReplaceInventory(inv); err != nil {
		t.Fatal(err)
	}
	all := map[netip.Addr]bool{}
	for cycle := 0; cycle < 61; cycle++ {
		batch, err := c.NextBatch(5)
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
	if err := c.ReplaceInventory(original); err != nil {
		t.Fatal(err)
	}
	b, err := c.NextBatch(1)
	if err != nil || b[0] != c.Preferred {
		t.Fatalf("did not prioritize known-working source %v %v", b, err)
	}
	b, err = c.NextBatch(1)
	if err != nil || b[0] != original.Addresses[0] {
		t.Fatalf("round skipped other source %v %v", b, err)
	}
	changed := Inventory{Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.30")}}
	if err := c.ReplaceInventory(changed); err != nil {
		t.Fatal(err)
	}
	b, err = c.NextBatch(1)
	if err != nil || len(b) != 1 || b[0] != changed.Addresses[0] {
		t.Fatalf("source removal not applied %v %v", b, err)
	}
	if err := c.ReplaceInventory(Inventory{}); err == nil {
		t.Fatal("empty source inventory accepted")
	}
	if _, err := c.NextBatch(1); err == nil {
		t.Fatal("stale candidates retained after inventory was removed")
	}
}

func BenchmarkDiscoveryBatch50k(b *testing.B) {
	inventory := Inventory{Addresses: make([]netip.Addr, 50_000)}
	for i := range inventory.Addresses {
		inventory.Addresses[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	cursor := DiscoveryCursor{}
	if err := cursor.ReplaceInventory(inventory); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch, err := cursor.NextBatch(64)
		if err != nil || len(batch) == 0 {
			b.Fatal(err)
		}
	}
}

// Sampling is deliberately prefix-diverse, not a prefix permit/deny decision:
// a miss from one /24 must not prevent eventual tests of its other members.
func TestDiscoveryStratifiesPrefixesWithoutSkippingAnySource(t *testing.T) {
	addresses := make([]netip.Addr, 0, 54)
	for i := 1; i <= 50; i++ {
		addresses = append(addresses, netip.AddrFrom4([4]byte{10, 1, 2, byte(i)}))
	}
	addresses = append(addresses,
		netip.MustParseAddr("10.2.3.1"),
		netip.MustParseAddr("11.0.4.1"),
		netip.MustParseAddr("10.1.3.1"),
		netip.MustParseAddr("10.2.5.1"),
	)
	cursor := DiscoveryCursor{}
	if err := cursor.ReplaceInventory(Inventory{Addresses: addresses}); err != nil {
		t.Fatal(err)
	}
	first, err := cursor.NextBatch(3)
	if err != nil {
		t.Fatal(err)
	}
	ranges := map[string]bool{}
	for _, addr := range first {
		raw := addr.As4()
		ranges[fmt.Sprintf("%d.%d", raw[0], raw[1])] = true
	}
	if len(ranges) != 3 {
		t.Fatalf("first batch did not sample distinct /16 ranges: %v", first)
	}
	all := map[netip.Addr]bool{}
	for _, addr := range first {
		all[addr] = true
	}
	for len(all) < len(addresses) {
		batch, err := cursor.NextBatch(min(3, len(addresses)-len(all)))
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range batch {
			if all[addr] {
				t.Fatalf("repeated %v before exhausting inventory", addr)
			}
			all[addr] = true
		}
	}
	if len(all) != len(addresses) {
		t.Fatalf("lost supplied sources: %d/%d", len(all), len(addresses))
	}
}

func TestDiscoveryExhaustsFiftyThousandWithoutDuplicatesOrCap(t *testing.T) {
	const count = 50_000
	inv := Inventory{Addresses: make([]netip.Addr, count)}
	for i := range inv.Addresses {
		inv.Addresses[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	cursor := DiscoveryCursor{}
	if err := cursor.ReplaceInventory(inv); err != nil {
		t.Fatal(err)
	}
	seen := make(map[netip.Addr]bool, count)
	for len(seen) < count {
		batch, err := cursor.NextBatch(min(64, count-len(seen)))
		if err != nil || len(batch) > 64 {
			t.Fatalf("batch=%d err=%v", len(batch), err)
		}
		for _, address := range batch {
			if seen[address] {
				t.Fatalf("source tested twice before first complete pass: %v", address)
			}
			seen[address] = true
		}
	}
	if got := DiscoveryBatchSize(count); got != 16 {
		t.Fatalf("unexpected capacity-based packet budget: %d", got)
	}
	if got := DiscoveryBatchSize(2); got != 4 {
		t.Fatalf("small inventory must retain modest packet budget: %d", got)
	}
	if got := DiscoveryBatchSize(200_000); got != 16 {
		t.Fatalf("packet bursts must remain bounded: %d", got)
	}
	position, passes := cursor.Progress()
	if position != 0 || passes != 1 {
		t.Fatalf("exhaustion progress must report one complete pass, got position=%d passes=%d", position, passes)
	}
	if next, err := cursor.NextBatch(2); err != nil || next[0] == next[1] {
		t.Fatalf("new pass must cycle without duplicates within a batch: %v %v", next, err)
	}
	// Once a valid preferred Source wins, it should be first on retry.
	winner := inv.Addresses[count-1]
	cursor.PreferredSucceeded(winner)
	batch, err := cursor.NextBatch(1)
	if err != nil || batch[0] != winner {
		t.Fatalf("preferred not first: %v %v", batch, err)
	}
	// If the file later drops that preferred Source, no stale entry is sent.
	replacement := Inventory{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.90")}}
	if err := cursor.ReplaceInventory(replacement); err != nil {
		t.Fatal(err)
	}
	batch, err = cursor.NextBatch(1)
	if err != nil || batch[0] != replacement.Addresses[0] {
		t.Fatalf("removed source remained cached: %v %v", batch, err)
	}
}
