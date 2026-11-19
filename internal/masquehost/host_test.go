package masquehost

import (
	"testing"

	masquebackend "github.com/ach1992/simple-tun-link/internal/backend/masque"
)

func TestProvisionalMASQUEAgentTunCannotAdoptForeignResource(t *testing.T) {
	cases := []struct {
		name     string
		observed masquebackend.HostObservation
		mayWait  bool
	}{
		{"expected unit running, new TUN alias not yet set",
			masquebackend.HostObservation{UnitExists: true, UnitOwned: true, UnitActive: true, InterfaceExists: true, InterfaceOwned: false}, true},
		{"untrusted foreign unit", masquebackend.HostObservation{UnitExists: true, UnitOwned: false, UnitActive: true, InterfaceExists: true}, false},
		{"owner service stopped", masquebackend.HostObservation{UnitExists: true, UnitOwned: true, UnitActive: false, InterfaceExists: true}, false},
		{"interface exists without original service", masquebackend.HostObservation{InterfaceExists: true}, false},
		{"already owned interface", masquebackend.HostObservation{UnitExists: true, UnitOwned: true, UnitActive: true, InterfaceExists: true, InterfaceOwned: true}, false},
		{"no interface yet", masquebackend.HostObservation{UnitExists: true, UnitOwned: true, UnitActive: true}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := provisionalMASQUEAgentTun(test.observed); got != test.mayWait {
				t.Fatalf("provisional TUN owner classification = %t; want %t", got, test.mayWait)
			}
		})
	}
}
