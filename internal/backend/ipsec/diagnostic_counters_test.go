package ipsec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func ipsecCounterRecord(name string, index int, id uint32, stats string) string {
	return fmt.Sprintf(`[{"ifindex":%d,"ifname":%q,"ifalias":"stl:lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":%d}}%s}]`,
		index, name, id, stats)
}

func TestIPsecDiagnosticPacketCountersRequireMeasuredOwnedStats(t *testing.T) {
	p := Profile{InterfaceName: "stl-xfrm-test", InterfaceID: 42,
		Link: domain.Link{ID: "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	valid := ipsecCounterRecord(p.InterfaceName, 21, p.InterfaceID,
		`,"stats64":{"rx":{"packets":0,"bytes":0},"tx":{"packets":17,"bytes":2412}}`)
	tests := []struct {
		name string
		raw  string
		ok   bool
		rx   uint64
		tx   uint64
	}{
		{"actual zero and nonzero", valid, true, 0, 17},
		{"both actual zero", ipsecCounterRecord(p.InterfaceName, 21, 42,
			`,"stats64":{"rx":{"packets":0},"tx":{"packets":0}}`), true, 0, 0},
		{"no stats", ipsecCounterRecord(p.InterfaceName, 21, 42, ""), false, 0, 0},
		{"no rx", ipsecCounterRecord(p.InterfaceName, 21, 42,
			`,"stats64":{"tx":{"packets":4}}`), false, 0, 0},
		{"no tx", ipsecCounterRecord(p.InterfaceName, 21, 42,
			`,"stats64":{"rx":{"packets":4}}`), false, 0, 0},
		{"negative count", ipsecCounterRecord(p.InterfaceName, 21, 42,
			`,"stats64":{"rx":{"packets":-1},"tx":{"packets":0}}`), false, 0, 0},
		{"string count", ipsecCounterRecord(p.InterfaceName, 21, 42,
			`,"stats64":{"rx":{"packets":"0"},"tx":{"packets":0}}`), false, 0, 0},
		{"duplicate packets", ipsecCounterRecord(p.InterfaceName, 21, 42,
			`,"stats64":{"rx":{"packets":1,"packets":2},"tx":{"packets":0}}`), false, 0, 0},
		{"duplicate rx", ipsecCounterRecord(p.InterfaceName, 21, 42,
			`,"stats64":{"rx":{"packets":1},"rx":{"packets":2},"tx":{"packets":0}}`), false, 0, 0},
		{"duplicate stats", ipsecCounterRecord(p.InterfaceName, 21, 42,
			`,"stats64":{"rx":{"packets":1},"tx":{"packets":2}},"stats64":{"rx":{"packets":3},"tx":{"packets":4}}`), false, 0, 0},
		{"wrong name", ipsecCounterRecord("foreign", 21, 42,
			`,"stats64":{"rx":{"packets":1},"tx":{"packets":2}}`), false, 0, 0},
		{"missing alias", strings.Replace(valid, `"ifalias":"stl:lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",`, "", 1), false, 0, 0},
		{"foreign alias", strings.Replace(valid, "stl:lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "stl:lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1), false, 0, 0},
		{"wrong ifid", ipsecCounterRecord(p.InterfaceName, 21, 43,
			`,"stats64":{"rx":{"packets":1},"tx":{"packets":2}}`), false, 0, 0},
		{"non xfrm", `[{"ifindex":21,"ifname":"stl-xfrm-test","linkinfo":{"info_kind":"dummy"},"stats64":{"rx":{"packets":1},"tx":{"packets":2}}}]`, false, 0, 0},
		{"two links", valid[:len(valid)-1] + "," + valid[1:], false, 0, 0},
		{"malformed", `[{bad`, false, 0, 0},
		{"null", `null`, false, 0, 0},
		{"empty", `[]`, false, 0, 0},
		{"overflow", strings.Repeat("X", 32<<10+1), false, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rx, tx, err := parseIPsecPacketCounters([]byte(tc.raw), p, 21)
			if (err == nil) != tc.ok || (tc.ok && (rx != tc.rx || tx != tc.tx)) {
				t.Fatalf("packet counters: rx=%d tx=%d err=%v", rx, tx, err)
			}
		})
	}
	if _, _, err := parseIPsecPacketCounters([]byte(valid), p, 22); err == nil {
		t.Fatal("changed ifindex must not supply traffic")
	}
}

type ipsecCounterRunner struct {
	output   []byte
	fail     bool
	commands []string
}

func (r *ipsecCounterRunner) RunBounded(_ context.Context, limits CaptureLimits, binary string, args ...string) (CommandResult, error) {
	r.commands = append(r.commands, binary+" "+strings.Join(args, " "))
	if binary != "/usr/sbin/ip" || strings.Join(args, " ") != "-s -details -json link show dev stl-xfrm-test" ||
		limits.Stdout > 32<<10 || limits.Stderr > 1024 {
		return CommandResult{}, errors.New("unsafe command")
	}
	if r.fail {
		return CommandResult{}, errors.New("possibly secret stderr must not propagate")
	}
	return CommandResult{Stdout: append([]byte(nil), r.output...)}, nil
}

func TestIPsecDiagnosticPacketCounterFailuresOmitRatherThanInvent(t *testing.T) {
	p := Profile{InterfaceName: "stl-xfrm-test", InterfaceID: 42,
		Link: domain.Link{ID: "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	runner := &ipsecCounterRunner{output: []byte(ipsecCounterRecord(p.InterfaceName, 21, 42,
		`,"stats64":{"rx":{"packets":0},"tx":{"packets":7}}`))}
	b := &OperationalBackend{OperationalOptions: OperationalOptions{Runner: runner, IPBinary: "/usr/sbin/ip"}}
	rx, tx := b.diagnosticPacketCounters(context.Background(), p, 21)
	if rx == nil || tx == nil || *rx != 0 || *tx != 7 {
		t.Fatalf("verified counters missing: rx=%v tx=%v", rx, tx)
	}
	runner.fail = true
	rx, tx = b.diagnosticPacketCounters(context.Background(), p, 21)
	if rx != nil || tx != nil {
		t.Fatal("failed count read was presented as measured")
	}
	runner.fail = false
	runner.output = []byte(`[{"ifindex":22,"ifname":"foreign"}]`)
	rx, tx = b.diagnosticPacketCounters(context.Background(), p, 21)
	if rx != nil || tx != nil {
		t.Fatal("foreign interface traffic was attributed to local IPsec Link")
	}
	if len(runner.commands) != 3 {
		t.Fatalf("unexpected probe count: %v", runner.commands)
	}
}
