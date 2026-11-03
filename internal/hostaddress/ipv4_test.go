package hostaddress

import (
	"errors"
	"net/netip"
	"testing"
)

func TestUniqueLocalHostAddressClassifiesOnlyVerifiedAssignments(t *testing.T) {
	target := netip.MustParseAddr("192.0.2.20")
	other := netip.MustParseAddr("203.0.113.197")
	for _, tc := range []struct {
		name          string
		endpoints     []Endpoint
		device        string
		want          error
		wantInterface string
	}{
		{"assigned", []Endpoint{{Address: target, Interface: "eth0"}}, "", nil, "eth0"},
		{"wrong receiver", []Endpoint{{Address: other, Interface: "eth0"}}, "", ErrNotAssigned, ""},
		{"ambiguous receiver", []Endpoint{{Address: target, Interface: "eth0"}, {Address: target, Interface: "eth1"}}, "", ErrAmbiguous, ""},
		{"specified interface exists", []Endpoint{{Address: target, Interface: "eth0"}, {Address: target, Interface: "eth1"}}, "eth1", nil, "eth1"},
		{"wrong interface is not wrong host", []Endpoint{{Address: target, Interface: "eth0"}}, "eth1", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Unique(tc.endpoints, target, tc.device)
			if tc.want != nil {
				if !errors.Is(err, tc.want) || got != (Endpoint{}) {
					t.Fatalf("wrong typed local assignment: result=%+v err=%v", got, err)
				}
			} else if tc.wantInterface != "" {
				if err != nil || got.Interface != tc.wantInterface || got.Address != target {
					t.Fatalf("lost exact local address: %+v %v", got, err)
				}
			} else if err == nil || errors.Is(err, ErrNotAssigned) || errors.Is(err, ErrAmbiguous) {
				t.Fatalf("wrong interface incorrectly classified as wrong host: %+v %v", got, err)
			}
		})
	}
}
