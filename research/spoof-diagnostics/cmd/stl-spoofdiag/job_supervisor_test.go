package main

import "testing"

// Pure validation tests; never launch systemd, sockets, processes or packets.
func TestOnlyFiniteExplicitJobsAreDetachable(t *testing.T) {
	cases := []struct {
		args []string
		max  int
		pass bool
	}{
		{[]string{"field", "observe", "--window-seconds", "120", "--out", "/private/capture.json"}, 240, true},
		{[]string{"field", "observe", "--window-seconds=14400"}, 14520, true},
		{[]string{"field", "observe", "--window-seconds", "0"}, 0, false},
		{[]string{"field", "observe", "--window-seconds", "14401"}, 0, false},
		{[]string{"field", "observe"}, 0, false},
		{[]string{"field", "send"}, 1200, true},
		{[]string{"campaign", "send"}, 1200, true},
		{[]string{"field", "listen"}, 1200, true},
		{[]string{"campaign", "receive"}, 1200, true},
		{[]string{"exchange", "analyze"}, 86400, true},
		{[]string{"field", "challenge"}, 0, false},
		{[]string{"campaign", "next"}, 0, false},
		{[]string{"sources", "add"}, 0, false},
		{[]string{"field", "observe", "--window-seconds", "not-number"}, 0, false},
	}
	for _, tc := range cases {
		got, err := jobOperationLimits(tc.args)
		if (err == nil) != tc.pass || (tc.pass && got != tc.max) {
			t.Errorf("command %v: max=%d err=%v, want allowed=%v max=%d", tc.args, got, err, tc.pass, tc.max)
		}
	}
}

func TestUnitIdCannotSelectOtherSystemdServices(t *testing.T) {
	for _, v := range []string{"sdx-0000000000000000.service", "sdx-1234567890abcdef.service"} {
		if !finiteUnitID.MatchString(v) {
			t.Fatal("valid service ID refused", v)
		}
	}
	for _, v := range []string{"ssh.service", "stl.service", "sdx-../../ssh.service", "sdx-1234.service", "sdx-1234567890abcdef.service --now", "sdx-FFFFFFFFFFFFFFFF.service"} {
		if finiteUnitID.MatchString(v) {
			t.Fatal("unsafe service ID accepted", v)
		}
	}
}
