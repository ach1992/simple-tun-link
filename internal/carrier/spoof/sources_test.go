package spoof

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSourcesLocalInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.txt")
	if err := os.WriteFile(path, []byte("# no restrictions on ranges\n203.0.113.17\n192.0.2.8 # local candidate\n203.0.113.17\n\n10.1.2.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inventory, err := ReadSources(path)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Duplicates != 1 || len(inventory.Addresses) != 3 ||
		inventory.Addresses[0] != netip.MustParseAddr("203.0.113.17") ||
		inventory.Addresses[1] != netip.MustParseAddr("192.0.2.8") ||
		inventory.Addresses[2] != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("unexpected local inventory: %+v", inventory)
	}
	if err := os.WriteFile(path, []byte("198.51.100.27\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := ReadSources(path)
	if err != nil || len(changed.Addresses) != 1 || changed.Addresses[0].String() != "198.51.100.27" {
		t.Fatalf("source replacement requires no Link recreation: %+v %v", changed, err)
	}
}

func TestReadSourcesErrorsAreActionable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sources.txt")
	for _, tc := range []struct {
		data string
		want string
	}{
		{"\n# empty\n", "no IPv4"},
		{"1.2.3.4\nnot-an-ip\n", "line 2"},
		{"fe80::1\n", "line 1"},
		{"1.2.3.999\n", "line 1"},
	} {
		if err := os.WriteFile(p, []byte(tc.data), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadSources(p)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q: got %v, want %s", tc.data, err, tc.want)
		}
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSources(p)
	if err == nil || !strings.Contains(err.Error(), "Recheck") {
		t.Fatalf("missing sources must say Recheck: %v", err)
	}
	if err := os.Symlink("/etc/hosts", p); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSources(p); err == nil {
		t.Fatal("symlink source must not be followed by privileged reader")
	}
}

func TestReadSourcesHasNoArbitraryCountCap(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sources.txt")
	var b strings.Builder
	for i := 1; i <= 1200; i++ {
		fmt.Fprintf(&b, "10.%d.%d.%d\n", (i>>16)&255, (i>>8)&255, i&255)
	}
	if err := os.WriteFile(p, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSources(p)
	if err != nil || len(got.Addresses) != 1200 {
		t.Fatalf("inventory truncated: %d, %v", len(got.Addresses), err)
	}
}
