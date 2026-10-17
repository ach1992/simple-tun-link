package ipsec

import (
	"strings"
	"testing"
)

const cleanLegacy249Dump = `Manager: systemd 249 (249.11-0ubuntu3)
Features: +PAM +AUDIT
-> Unit unrelated.service:
	Description: Unrelated manager service
	Unit Load State: loaded
	Unit Active State: active
	Upholds: unrelated-child.service (origin-file)
	StopWhenUnneeded: no
-> Unit strongswan.service:
	Description: strongSwan IKEv2 daemon
	Unit Load State: loaded
	Unit Active State: active
	Need Daemon Reload: no
	Fragment Path: /lib/systemd/system/strongswan.service
	WantedBy: multi-user.target (destination-file)
	StopWhenUnneeded: no
-> Unit multi-user.target:
	Description: Multi-User System
	Unit Load State: loaded
	Unit Active State: active
	StopWhenUnneeded: no
`

func TestVendorStopSystemdVersionCapabilityBoundary(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  int
		valid bool
	}{
		{"Version=247.3-7~deb11u9\n", 247, true},
		{"Version=248\n", 248, true},
		{"Version=249.11-0ubuntu3.17\n", 249, true},
		{"Version=250.1\n", 250, true},
		{"Version=251\n", 251, true},
		{"Version=259\n", 259, true},
		{"Version=249fake\n", 0, false},
		{"Version=249\nVersion=250\n", 0, false},
		{"Version=249 \n", 0, false},
		{"Version=249\x00\n", 0, false},
		{"Version=-249\n", 0, false},
		{"Version=2499\n", 0, false},
		{"Version=25\n", 0, false},
	} {
		got, valid := vendorStopSystemdVersion([]byte(tc.in))
		if got != tc.want || valid != tc.valid {
			t.Fatalf("version=%q got=%d valid=%v expected=%d %v", tc.in, got, valid, tc.want, tc.valid)
		}
	}
}

func TestVendorStopV249PID1DumpStrictAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, dump string
		version    int
		allow      bool
	}{
		{"clean official", cleanLegacy249Dump, 249, true},
		{"clean version 250", strings.Replace(cleanLegacy249Dump, "systemd 249 (", "systemd 250 (", 1), 250, true},
		{"direct inverse", strings.Replace(cleanLegacy249Dump, "\tWantedBy: multi-user.target", "\tUpheldBy: foreign-upholder.service (destination-file)\n\tWantedBy: multi-user.target", 1), 249, false},
		{"direct forward", strings.Replace(cleanLegacy249Dump, "\tUpholds: unrelated-child.service", "\tUpholds: strongswan.service", 1), 249, false},
		{"alias forward", strings.Replace(cleanLegacy249Dump, "\tUpholds: unrelated-child.service", "\tUpholds: strongswan-swanctl.service", 1), 249, false},
		{"unrelated forward permitted", cleanLegacy249Dump, 249, true},
		{"other reverse permitted", strings.Replace(cleanLegacy249Dump, "\tUpholds: unrelated-child.service", "\tUpheldBy: unrelated-parent.service", 1), 249, true},
		{"stale manager", cleanLegacy249Dump, 250, false},
		{"modern version not supported", cleanLegacy249Dump, 251, false},
		{"duplicate selected unit", cleanLegacy249Dump + cleanLegacy249Dump[strings.Index(cleanLegacy249Dump, "-> Unit strongswan.service:"):], 249, false},
		{"unexpected fragment", strings.Replace(cleanLegacy249Dump, "/lib/systemd/system/strongswan.service", "/etc/systemd/system/strongswan.service", 1), 249, false},
		{"missing terminator", strings.Replace(cleanLegacy249Dump, "\tStopWhenUnneeded: no\n-> Unit multi-user.target", "-> Unit multi-user.target", 1), 249, false},
		{"duplicate key", strings.Replace(cleanLegacy249Dump, "\tNeed Daemon Reload: no\n", "\tNeed Daemon Reload: no\n\tNeed Daemon Reload: no\n", 1), 249, false},
		{"pending reload", strings.Replace(cleanLegacy249Dump, "\tNeed Daemon Reload: no", "\tNeed Daemon Reload: yes", 1), 249, false},
		{"inactive official", strings.Replace(cleanLegacy249Dump[strings.Index(cleanLegacy249Dump, "Manager:"):], "\tUnit Active State: active\n\tNeed Daemon Reload", "\tUnit Active State: inactive\n\tNeed Daemon Reload", 1), 249, true},
		{"absent unit", strings.Replace(cleanLegacy249Dump, "-> Unit strongswan.service:", "-> Unit random.service:", 1), 249, false},
		{"corrupted header", strings.Replace(cleanLegacy249Dump, "Manager: systemd 249", "Manager: systemd 2499", 1), 249, false},
		{"bad newline", strings.Replace(cleanLegacy249Dump, "\tUnit Load State: loaded", "\tUnit Load State: loa\rded", 1), 249, false},
		{"truncated line", strings.Repeat("X", 2*1024*1024) + "\n" + cleanLegacy249Dump, 249, false},
		{"empty", "", 249, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := vendorStopParseLegacyManagerDump(strings.NewReader(tc.dump), tc.version)
			if (err == nil) != tc.allow {
				t.Fatalf("legacy systemd manager dump accepted=%v want=%v err=%v", err == nil, tc.allow, err)
			}
		})
	}
}
