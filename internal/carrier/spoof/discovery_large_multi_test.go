package spoof

import (
	"net/netip"
	"testing"
)

func largeSpoofInventory() Inventory {
	out := Inventory{Addresses: make([]netip.Addr, 50000)}
	for i := range out.Addresses {
		out.Addresses[i] = netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
	}
	return out
}
func TestFiftyThousandSourcesEveryProfileAndTwoRealDestinations(t *testing.T) {
	inv := largeSpoofInventory()
	destinations := []netip.AddrPort{netip.MustParseAddrPort("10.244.62.222:48002"), netip.MustParseAddrPort("10.244.62.224:48012")}
	var cursor DiscoveryCursor
	if err := cursor.ReplaceInventory(inv); err != nil {
		t.Fatal(err)
	}
	total := len(inv.Addresses) * len(AllProfiles()) * len(destinations)
	seen := make(map[SourcePath]bool, total)
	for count := 0; count < total; {
		batch, err := cursor.NextRouteBatch(AllProfiles(), destinations, 128)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range batch {
			if seen[path] {
				t.Fatalf("repeated route before complete 50K scan: %v, index=%d", path, count)
			}
			seen[path] = true
			count++
		}
	}
	if len(seen) != total {
		t.Fatalf("only covered %d/%d routes", len(seen), total)
	}
	if _, _, passes := cursor.PathProgress(); passes != 1 {
		t.Fatalf("expected one complete pass, got %d", passes)
	}
}
func BenchmarkFiftyThousandSourceProfileDestinationScan(b *testing.B) {
	inv := largeSpoofInventory()
	destinations := []netip.AddrPort{netip.MustParseAddrPort("10.244.62.222:48002"), netip.MustParseAddrPort("10.244.62.224:48012")}
	var cursor DiscoveryCursor
	if err := cursor.ReplaceInventory(inv); err != nil {
		b.Fatal(err)
	}
	profiles := AllProfiles()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		routes, err := cursor.NextRouteBatch(profiles, destinations, 64)
		if err != nil || len(routes) == 0 {
			b.Fatalf("lazy route scan: %v", err)
		}
	}
}
