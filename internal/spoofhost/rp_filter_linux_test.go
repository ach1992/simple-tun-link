//go:build linux

package spoofhost

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestRPFilterActualEffectiveModeAndReadOnlyBehavior(t *testing.T) {
	root := t.TempDir()
	link := domain.Link{Spoof: domain.SpoofOptions{IngressInterface: "in0", Interface: "out0"}}
	write := func(name, value string) {
		t.Helper()
		path := filepath.Join(root, "net", "ipv4", "conf", name, "rp_filter")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		all, iface, mode string
		effective        int
	}{
		{"1", "0", "STRICT", 1}, {"1", "2", "LOOSE", 2}, {"0", "2", "LOOSE", 2}, {"0", "0", "OFF", 0},
	} {
		write("all", tc.all)
		write("in0", tc.iface)
		status := readRPFilterAt(root, link)
		if status.Mode != tc.mode || status.Effective != tc.effective || status.ReadError != "" {
			t.Fatalf("effective rp_filter mismatch %+v", status)
		}
		got, err := os.ReadFile(filepath.Join(root, "net", "ipv4", "conf", "in0", "rp_filter"))
		if err != nil || string(got) != tc.iface+"\n" {
			t.Fatal("read-only observer changed sysctl")
		}
	}
	link.Spoof.IngressInterface = ""
	if status := readRPFilterAt(root, link); status.Mode != "UNVERIFIED" || status.ReadError != "" {
		t.Fatal("guessed unspecified ingress interface")
	}
}
