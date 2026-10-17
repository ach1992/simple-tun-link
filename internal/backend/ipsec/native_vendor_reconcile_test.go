package ipsec

import (
	"context"
	"strings"
	"testing"
)

func TestNativeVendorUnitMetadataStrict(t *testing.T) {
	good := []byte("LoadState=loaded\nNeedDaemonReload=no\nDropInPaths=\nSourcePath=\nFragmentPath=/usr/lib/systemd/system/strongswan.service\n")
	fragment, err := nativeVendorUnitMetadataStrict(good)
	if err != nil || fragment != "/usr/lib/systemd/system/strongswan.service" {
		t.Fatalf("known distro metadata rejected: fragment=%q err=%v", fragment, err)
	}
	bad := [][]byte{
		nil,
		good[:len(good)-1],
		[]byte(strings.Replace(string(good), "LoadState=loaded", "LoadState=not-found", 1)),
		[]byte(strings.Replace(string(good), "NeedDaemonReload=no", "NeedDaemonReload=yes", 1)),
		[]byte(strings.Replace(string(good), "DropInPaths=", "DropInPaths=/etc/systemd/system/strongswan.service.d/evil.conf", 1)),
		[]byte(strings.Replace(string(good), "SourcePath=", "SourcePath=/etc/foreign", 1)),
		[]byte(strings.Replace(string(good), "/usr/lib/systemd/system/strongswan.service", "/etc/systemd/system/strongswan.service", 1)),
		[]byte(string(good) + "DropInPaths=\n"),
		[]byte(string(good) + "ExecStop=foreign\n"),
	}
	for _, raw := range bad {
		if _, err := nativeVendorUnitMetadataStrict(raw); err == nil {
			t.Fatalf("invalid or ambiguous vendor service metadata accepted: %q", raw)
		}
	}
}

func TestStopDisableVerifiedVendorRejectsUnapprovedIdentity(t *testing.T) {
	for _, plan := range []VendorServiceStopPlan{
		{},
		{Unit: "ipsec.service", Active: "active", Enabled: "enabled"},
		{Unit: "strongswan.service", Active: "failed", Enabled: "enabled"},
		{Unit: "strongswan.service", Active: "active", Enabled: "masked"},
		{Unit: "strongswan.service", Active: "inactive", Enabled: "disabled"},
	} {
		// The last case can only be an already-no-op candidate and must
		// be rejected by the freshness check rather than changed.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := StopDisableVerifiedVendorService(ctx, plan); err == nil {
			t.Fatalf("unapproved/cancelled vendor mutation accepted: %+v", plan)
		}
	}
}

// Direct [Unit] Upholds= is represented in the selected service's effective
// reverse UpheldBy= property, not necessarily in any *.upholds directory.
// Empty output is NOT positive proof except on verified systemd 247/248,
// which predate this dependency type.
func TestVendorStopEffectiveUpheldByReceiptFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, property, manager string
		allowed                 bool
	}{
		{"clean supported", "UpheldBy=\n", "", true},
		{"direct live upholder", "UpheldBy=stl-upholder.service\n", "", false},
		{"multiple upholders", "UpheldBy=alpha.service beta.service\n", "", false},
		{"unsupported but old 247", "", "Version=247.3-7~deb11u9\n", true},
		{"unsupported but old 248", "", "Version=248\n", true},
		{"unsupported new 249", "", "Version=249\n", false},
		{"unsupported new 250", "", "Version=250\n", false},
		{"missing both", "", "", false},
		{"malformed 247 suffix", "", "Version=247fake\n", false},
		{"malformed version", "", "Version=247\nVersion=248\n", false},
		{"malformed property", "UpheldBy", "Version=247\n", false},
		{"duplicated empty property", "UpheldBy=\nUpheldBy=\n", "Version=247\n", false},
		{"nonempty stderr-like property", "WARNING\n", "Version=247\n", false},
		{"nonempty UpheldBy on old version", "UpheldBy=foreign.service\n", "Version=247\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := vendorStopUpheldByReceipt([]byte(tc.property), []byte(tc.manager))
			if (err == nil) != tc.allowed {
				t.Fatalf("UpheldBy/manager receipt incorrectly classified: allowed=%t err=%v", tc.allowed, err)
			}
		})
	}
}
