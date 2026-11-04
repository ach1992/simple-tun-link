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

// A plausible but partial iproute2 response must not become proof of
// absence or unique assignment on a receiving host.
func TestParseLocalHostInventoryRequiresCompleteRecords(t *testing.T) {
	for _, tc := range []struct {
		name, raw     string
		usable, valid bool
	}{
		{"missing ifname", `[{"addr_info":[{"family":"inet","local":"192.0.2.20"}]}]`, false, false},
		{"missing addr_info", `[{"ifname":"eth0"}]`, false, false},
		{"null addr_info", `[{"ifname":"eth0","addr_info":null}]`, false, false},
		{"mixed records", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.20"}]},{"ifname":"eth1"}]`, false, false},
		{"missing family", `[{"ifname":"eth0","addr_info":[{"local":"192.0.2.20"}]}]`, false, false},
		{"missing local", `[{"ifname":"eth0","addr_info":[{"family":"inet"}]}]`, false, false},
		{"null local", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":null}]}]`, false, false},
		{"duplicate interface", `[{"ifname":"eth0","addr_info":[]},{"ifname":"eth0","addr_info":[]}]`, false, false},
		{"malformed IPv6", `[{"ifname":"eth0","addr_info":[{"family":"inet6","local":"UNTRUSTED-MALFORMED"}]}]`, false, false},
		{"wrong family", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"2001:db8::1"}]}]`, false, false},
		{"malformed object", `[{"ifname":"eth0","addr_info":{}}]`, false, false},
		{"malformed JSON", `[{"ifname":"eth0","addr_info":[`, false, false},
		{"valid complete inventory", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.20"}]},{"ifname":"eth1","addr_info":[{"family":"inet6","local":"2001:db8::1"}]}]`, true, true},
		{"valid empty interface inventory", `[{"ifname":"eth0","addr_info":[]}]`, false, true},
		{"valid empty host inventory", `[]`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, err := Parse([]byte(tc.raw))
			if (err == nil) != tc.valid {
				t.Fatalf("accepted incomplete inventory: err=%v endpoints=%v", err, found)
			}
			if !tc.valid {
				if len(found) != 0 {
					t.Fatalf("parser returned authoritative endpoints from incomplete evidence: %v", found)
				}
				return
			}
			if tc.usable {
				if len(found) != 1 || found[0].Address.String() != "192.0.2.20" {
					t.Fatalf("lost valid assigned address: %v", found)
				}
			} else if len(found) != 0 {
				t.Fatalf("invented usable IPv4 from empty inventory: %v", found)
			}
		})
	}
}
