package wireguard

import (
	"context"
	"testing"
)

func TestWireGuardDiagnosticCapabilityAndIPv4Overhead(t *testing.T) {
	impl, link, _, kernel, _ := fixture(t)
	overhead, err := Overhead(link)
	if err != nil || overhead != 60 {
		t.Fatalf("invalid IPv4 WireGuard overhead %d: %v", overhead, err)
	}
	available, err := impl.Capability(context.Background(), link)
	if err != nil || !available.Available {
		t.Fatalf("safe WireGuard capability observation failed: %+v %v", available, err)
	}
	for _, args := range kernel.calls {
		for _, arg := range args {
			if arg == "private-key" || arg == "dump" || arg == "set" {
				t.Fatalf("capability accessed private or mutating command: %v", args)
			}
		}
	}
	kernel.fail = "wg-observation"
	available, err = impl.Capability(context.Background(), link)
	if err != nil || available.Available {
		t.Fatalf("missing WireGuard inspection was accepted: %+v %v", available, err)
	}
}
