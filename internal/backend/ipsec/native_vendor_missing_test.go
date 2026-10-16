package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeMissingVendorUnitPropertiesRequiresCompleteAbsentProof(t *testing.T) {
	// Exact properties reported by systemd on the Owner's missing alternate
	// StrongSwan services. This is not authorization derived from the
	// service-file-name alone; missing effective AND on-disk identity required.
	good := "LoadState=not-found\nActiveState=inactive\nFragmentPath=\nSourcePath=\nDropInPaths=\nUnitFileState=\nNeedDaemonReload=no\n"
	if !nativeMissingVendorUnitProperties([]byte(good)) {
		t.Fatal("complete empty-unit status rejected")
	}
	for _, tc := range []struct{ name, content string }{
		{"missing fields", strings.Replace(good, "DropInPaths=\n", "", 1)},
		{"loaded", strings.Replace(good, "LoadState=not-found", "LoadState=loaded", 1)},
		{"masked", strings.Replace(good, "LoadState=not-found", "LoadState=masked", 1)},
		{"active", strings.Replace(good, "ActiveState=inactive", "ActiveState=active", 1)},
		{"enabled", strings.Replace(good, "UnitFileState=", "UnitFileState=enabled", 1)},
		{"masked unit file", strings.Replace(good, "UnitFileState=", "UnitFileState=masked", 1)},
		{"distro fragment", strings.Replace(good, "FragmentPath=", "FragmentPath=/lib/systemd/system/ipsec.service", 1)},
		{"foreign source", strings.Replace(good, "SourcePath=", "SourcePath=/etc/init.d/ipsec", 1)},
		{"foreign drop in", strings.Replace(good, "DropInPaths=", "DropInPaths=/etc/systemd/system/override.conf", 1)},
		{"pending reload", strings.Replace(good, "NeedDaemonReload=no", "NeedDaemonReload=yes", 1)},
		{"duplicate field", good + "LoadState=not-found\n"},
		{"extra field", good + "PSK=PRIVATE\n"},
		{"truncated", strings.TrimSuffix(good, "\n")},
		{"unbounded", strings.Repeat("x", 1025)},
		{"control bytes", strings.Replace(good, "ActiveState=inactive", "ActiveState=inactive\r", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if nativeMissingVendorUnitProperties([]byte(tc.content)) {
				t.Fatalf("unverified or conflicted systemd status accepted: %s", tc.name)
			}
		})
	}
}

func TestNativeMissingVendorDiskIdentityRejectsAnyOverride(t *testing.T) {
	for _, unit := range []string{"strongswan.service", "strongswan-starter.service", "charon-systemd.service", "ipsec.service"} {
		t.Run(unit, func(t *testing.T) {
			root := t.TempDir()
			if !nativeMissingVendorUnitFiles(root, unit) {
				t.Fatal("isolated empty filesystem did not prove absence")
			}
			for _, parent := range []string{
				"etc/systemd/system", "run/systemd/system",
				"usr/lib/systemd/system", "lib/systemd/system",
				"run/systemd/generator", "run/systemd/generator.early", "run/systemd/generator.late",
			} {
				path := filepath.Join(root, parent, unit)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/missing/foreign.service", path); err != nil {
					t.Fatal(err)
				}
				if nativeMissingVendorUnitFiles(root, unit) {
					t.Fatalf("dangling or foreign unit path accepted: %s", parent)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if unit != "charon-systemd.service" {
				path := filepath.Join(root, "etc/init.d", strings.TrimSuffix(unit, ".service"))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("foreign"), 0o644); err != nil {
					t.Fatal(err)
				}
				if nativeMissingVendorUnitFiles(root, unit) {
					t.Fatal("legacy foreign SysV service accepted as missing")
				}
			}
		})
	}
	if nativeMissingVendorUnitFiles(t.TempDir(), "some-other.service") {
		t.Fatal("unlisted service authorized")
	}
}

func TestNativeMissingVendorFallbackNeverOverridesPositiveOrMalformedStates(t *testing.T) {
	for _, good := range []string{"", "inactive\n", "unknown\n", "not-found\n"} {
		if !nativeVendorMissingStatusFallbackEligible([]byte(good)) {
			t.Fatalf("missing-unit status rejected: %q", good)
		}
	}
	for _, bad := range []string{"active\n", "enabled\n", "failed\n", "masked\n", "inactive\nactive\n", "unknown", "\x1b[31mactive\n"} {
		if nativeVendorMissingStatusFallbackEligible([]byte(bad)) {
			t.Fatalf("conflicting or malformed status could enter absence proof: %q", bad)
		}
	}
	if nativeVendorUnitVerifiedMissing(nil, "ipsec.service") {
		t.Fatal("nil context permitted missing-unit attestation")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if nativeVendorUnitVerifiedMissing(ctx, "ipsec.service") {
		t.Fatal("canceled context permitted missing-unit attestation")
	}
}

func TestNativeVendorUnitInterpretationOnlyAcceptsIndependentlyVerifiedAbsence(t *testing.T) {
	ctx := context.Background()
	positiveCalls := 0
	verifier := func(context.Context, string) bool {
		positiveCalls++
		return true
	}
	for _, tc := range []struct {
		action, stdout string
		code           int
		want           string
	}{
		{"is-active", "inactive\n", 3, "inactive"},
		{"is-enabled", "disabled\n", 1, "disabled"},
		{"is-active", "unknown\n", 4, "unknown"},
		{"is-enabled", "not-found\n", 4, "not-found"},
	} {
		got, err := interpretNativeVendorUnitState(ctx, tc.action, "strongswan.service",
			[]byte(tc.stdout), nil, tc.code, verifier)
		if err != nil || got != tc.want {
			t.Fatalf("exact vendor state lost: %+v got=%s err=%v", tc, got, err)
		}
	}
	if positiveCalls != 0 {
		t.Fatal("already verified systemd states triggered unnecessary fallback")
	}
	for _, tc := range []struct {
		name, action, stdout string
		stderr               string
		code                 int
		verified             bool
		want                 string
	}{
		{"missing active alternate code", "is-active", "inactive\n", "", 1, true, "unknown"},
		{"missing enablement alternate code", "is-enabled", "not-found\n", "", 1, true, "not-found"},
		{"missing enablement diagnostic", "is-enabled", "", "Unit does not exist\n", 1, true, "not-found"},
		{"missing but proof failed", "is-enabled", "not-found\n", "", 1, false, ""},
		{"active cannot be overridden", "is-active", "active\n", "", 3, true, ""},
		{"enabled cannot be overridden", "is-enabled", "enabled\n", "", 1, true, ""},
		{"failed cannot be overridden", "is-active", "failed\n", "", 3, true, ""},
		{"extra lines cannot be overridden", "is-enabled", "not-found\nmasked\n", "", 1, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifierCalled := 0
			got, err := interpretNativeVendorUnitState(ctx, tc.action, "ipsec.service",
				[]byte(tc.stdout), []byte(tc.stderr), tc.code, func(context.Context, string) bool {
					verifierCalled++
					return tc.verified
				})
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatalf("false vacancy accepted: got=%s err=%v", got, err)
				}
			} else if err != nil || got != tc.want || verifierCalled != 1 {
				t.Fatalf("known absent unit not recognized: got=%s err=%v fallbackCalls=%d", got, err, verifierCalled)
			}
			if tc.stdout == "active\n" && verifierCalled != 0 {
				t.Fatal("positive active result reached absence verifier")
			}
		})
	}
	if _, err := interpretNativeVendorUnitState(ctx, "is-active", "foreign.service",
		nil, nil, 1, verifier); err == nil {
		t.Fatal("arbitrary service authorized")
	}
}
