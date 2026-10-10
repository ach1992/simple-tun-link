package diagnostics

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const udpHeader = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
const udp6Header = "   sl  local_address remote_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func ipsecInventoryReader(files map[string]string, failures map[string]error) ipsecPortReader {
	return func(_ context.Context, path string) ([]byte, error) {
		if err := failures[path]; err != nil {
			return nil, err
		}
		content, ok := files[path]
		if !ok {
			return nil, errors.New("private_key=DO_NOT_PRINT")
		}
		return []byte(content), nil
	}
}

func TestIPsecPortObservationFailsClosedAndStaysSecretSafe(t *testing.T) {
	ctx := context.Background()
	clean4 := udpHeader + " 0: 0100007F:C350 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 0\n"
	conflict4 := udpHeader + " 1: 00000000:01F4 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 0\n"
	clean6 := udp6Header + " 0: 00000000000000000000000000000000:C350 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 0\n"
	conflict6 := udp6Header + " 0: 00000000000000000000000000000000:1194 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 0\n"
	cases := []struct {
		name           string
		v4, v6         string
		missing        string
		status, reason string
	}{
		{"clean in both inventories", clean4, clean6, "", "observed", "ike_udp_ports_not_observed"},
		{"occupied IKE UDP4", conflict4, clean6, "", "blocked", "ike_udp_ports_observed"},
		{"occupied NAT-T UDP6", clean4, conflict6, "", "blocked", "ike_udp_ports_observed"},
		{"missing IPv6 cannot certify", clean4, "", "/proc/net/udp6", "unknown", "ike_udp_inventory_unverified"},
		{"malformed UDP row", udpHeader + " 0: INVALID:01F4\n", clean6, "", "unknown", "ike_udp_inventory_unverified"},
		{"malformed IPv6 after occupied IPv4", conflict4, "untrusted\n", "", "blocked", "ike_udp_ports_observed"},
		{"malformed IPv4 before occupied IPv6", "untrusted\n", conflict6, "", "blocked", "ike_udp_ports_observed"},
		{"missing IPv6 but occupied IPv4", conflict4, "", "/proc/net/udp6", "blocked", "ike_udp_ports_observed"},
		{"malformed header", "untrusted\n", clean6, "", "unknown", "ike_udp_inventory_unverified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"/proc/net/udp": tc.v4, "/proc/net/udp6": tc.v6}
			if tc.missing != "" {
				delete(files, tc.missing)
			}
			check := inspectIPsecIKEPorts(ctx, ipsecInventoryReader(files, nil))
			if check.Status != tc.status || check.ReasonCode != tc.reason {
				t.Fatalf("wrong port inspection: %+v", check)
			}
			if check.Name != "ike_udp_ports" || check.NextStep == "" || strings.Contains(check.Summary, "DO_NOT_PRINT") {
				t.Fatalf("unhelpful or unsafe port diagnostic: %+v", check)
			}
		})
	}
	check := inspectIPsecIKEPorts(ctx, ipsecInventoryReader(nil, map[string]error{"/proc/net/udp": errors.New("PSK=DO_NOT_PRINT")}))
	if check.Status != "unknown" || strings.Contains(check.Summary+check.NextStep, "DO_NOT_PRINT") {
		t.Fatalf("unsafe inspection error: %+v", check)
	}
}

func TestIPsecPortInventoryCannotPromoteIncompleteOutputToVacancy(t *testing.T) {
	for _, data := range []string{
		"", udpHeader + "0: 00000000:01F4 00000000:0000 07\n0: broken\n",
		udpHeader + strings.Repeat("X", 100000) + "\n",
		udpHeader + "0: 00000000:1FFF 00000000:0000 07\n",
	} {
		_, err := parseIPsecPortInventory([]byte(data), 8)
		if err == nil {
			t.Fatalf("accepted incomplete inventory of size %d", len(data))
		}
	}
}
