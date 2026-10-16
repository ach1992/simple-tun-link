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
