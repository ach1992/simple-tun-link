package linux

import (
	"fmt"
	"net"
	"testing"
)

func TestVacantFOUDeviceOnlyAcceptsExactUnusedKernelIfIndex(t *testing.T) {
	for _, name := range []string{"", "eth0", "if", "if0", "if-1", "if01", "if9999999999999999999999999999", "if1;rm -rf /"} {
		vacant, err := VacantFOUDevice(name)
		if err != nil || vacant {
			t.Fatalf("invalid or normal FOU device %q: vacant=%t err=%v", name, vacant, err)
		}
	}
	live, err := net.Interfaces()
	if err != nil || len(live) == 0 {
		t.Fatalf("cannot inspect live loopback/interface inventory: %v", err)
	}
	name := fmt.Sprintf("if%d", live[0].Index)
	vacant, err := VacantFOUDevice(name)
	if err != nil || vacant {
		t.Fatalf("live numeric interface was admitted as stale: %q %t %v", name, vacant, err)
	}
	// Linux kernel interface indices fit signed 32-bit. This exact positive
	// integer cannot identify a currently allocated interface on this host.
	vacant, err = VacantFOUDevice("if2147483647")
	if err != nil || !vacant {
		t.Fatalf("confirmed unallocated index not recognized: %t %v", vacant, err)
	}
}
