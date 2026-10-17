package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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
			for _, parent := range vendorUnitSearchPaths {
				path := filepath.Join(root, strings.TrimPrefix(parent, "/"), unit)
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
			for _, test := range []struct{ path string }{
				{filepath.Join(root, "run/systemd/system.attached", unit)},
				{filepath.Join(root, "etc/systemd/system", "multi-user.target.wants", unit)},
				{filepath.Join(root, "run/systemd/system", "stl.target.requires", unit)},
				{filepath.Join(root, "etc/systemd/system", "stl.target.upholds", unit)},
				{filepath.Join(root, "etc/systemd/system", unit+".d")},
				{filepath.Join(root, "etc/systemd/system", "service.d")},
			} {
				if err := os.MkdirAll(filepath.Dir(test.path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/missing/foreign.service", test.path); err != nil {
					t.Fatal(err)
				}
				if nativeMissingVendorUnitFiles(root, unit) {
					t.Fatalf("foreign search path, boot edge, or drop-in accepted: %s", test.path)
				}
				if err := os.Remove(test.path); err != nil {
					t.Fatal(err)
				}
			}
			// Every known vendor name, including charon-systemd, can
			// later be synthesized by systemd-sysv-generator.
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
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			// Every applicable systemd hierarchical prefix is a future
			// identity even when the exact unit file is absent today.
			for _, dropin := range nativeMissingVendorDropIns(unit) {
				path := filepath.Join(root, "run/systemd/system", dropin)
				if err := os.MkdirAll(path, 0o755); err != nil {
					t.Fatal(err)
				}
				if nativeMissingVendorUnitFiles(root, unit) {
					t.Fatalf("dormant vendor prefix drop-in accepted: %s", dropin)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if !nativeMissingVendorUnitFiles(root, unit) {
				t.Fatal("empty fixture did not restore proven absence after removal")
			}
		})
	}
	if nativeMissingVendorUnitFiles(t.TempDir(), "some-other.service") {
		t.Fatal("unlisted service authorized")
	}
}

func TestNativeMissingVendorIdentityAliasesAndDropInInheritance(t *testing.T) {
	for _, tc := range []struct {
		unit         string
		expectPrefix string
	}{
		{"strongswan-starter.service", "strongswan-.service.d"},
		{"charon-systemd.service", "charon-.service.d"},
	} {
		names := nativeMissingVendorDropIns(tc.unit)
		if !slices.Contains(names, tc.expectPrefix) {
			t.Fatalf("systemd dash-prefix drop-in omitted for %s: %v", tc.unit, names)
		}
	}
	aliases := nativeMissingVendorIdentities("strongswan.service")
	if !slices.Contains(aliases, "strongswan-swanctl.service") {
		t.Fatalf("approved distro alias omitted: %v", aliases)
	}
	root := t.TempDir()
	for _, tc := range []struct {
		name, target, path string
		isDir              bool
	}{
		{"official vendor alias unit", "strongswan.service", "run/systemd/system/strongswan-swanctl.service", false},
		{"official vendor alias drop-in", "", "run/systemd/system/strongswan-swanctl.service.d", true},
		{"official vendor alias prefix", "", "run/systemd/system/strongswan-.service.d", true},
		{"official vendor alias boot edge", "strongswan.service", "etc/systemd/system/multi-user.target.wants/strongswan-swanctl.service", false},
		{"arbitrary dormant service alias", "strongswan.service", "run/systemd/system/stl-foreign-vendor-alias.service", false},
		{"arbitrary boot edge alias", "strongswan.service", "etc/systemd/system/multi-user.target.wants/stl-foreign-vendor-alias.service", false},
		{"upheld alias", "strongswan.service", "etc/systemd/system/stl.target.upholds/stl-foreign-vendor-alias.service", false},
		{"official SysV alias", "", "etc/init.d/strongswan-swanctl", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full := filepath.Join(root, tc.path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.isDir {
				if err := os.Mkdir(full, 0o755); err != nil {
					t.Fatal(err)
				}
			} else if tc.target != "" {
				if err := os.Symlink(tc.target, full); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(full, []byte("foreign"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if nativeMissingVendorUnitFiles(root, "strongswan.service") {
				t.Fatalf("dormant alias identity accepted: %s", tc.path)
			}
			if err := os.Remove(full); err != nil {
				t.Fatal(err)
			}
			if !nativeMissingVendorUnitFiles(root, "strongswan.service") {
				t.Fatalf("unrelated file or previous fixture leaked into result: %s", tc.path)
			}
		})
	}
	// Do not block on another service's unrelated symlink. That would
	// reintroduce the unnecessary host-wide readiness failure this fixes.
	unrelated := filepath.Join(root, "etc/systemd/system/unrelated.service")
	if err := os.Symlink("unrelated-target.service", unrelated); err != nil {
		t.Fatal(err)
	}
	if !nativeMissingVendorUnitFiles(root, "charon-systemd.service") {
		t.Fatal("unrelated service alias caused a false IPsec readiness conflict")
	}
	// A boot-edge directory that is itself a symlink is not an
	// independently verified canonical manager directory.
	link := filepath.Join(root, "etc/systemd/system/foreign.target.wants")
	if err := os.Symlink(filepath.Join(root, "run"), link); err != nil {
		t.Fatal(err)
	}
	if nativeMissingVendorUnitFiles(root, "charon-systemd.service") {
		t.Fatal("symlinked systemd boot-edge directory was accepted as verified absent")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if !nativeMissingVendorUnitFiles(root, "charon-systemd.service") {
		t.Fatal("empty boot-edge cleanup did not restore positive absence")
	}
	upholdsLink := filepath.Join(root, "etc/systemd/system/foreign.target.upholds")
	if err := os.Symlink(filepath.Join(root, "run"), upholdsLink); err != nil {
		t.Fatal(err)
	}
	if nativeMissingVendorUnitFiles(root, "charon-systemd.service") {
		t.Fatal("symlinked systemd .upholds directory was accepted as vacant")
	}
	if err := os.Remove(upholdsLink); err != nil {
		t.Fatal(err)
	}
	if !nativeMissingVendorUnitFiles(root, "charon-systemd.service") {
		t.Fatal("empty .upholds cleanup did not restore positive absence")
	}
}

func TestNativeMissingVendorFallbackNeverOverridesPositiveOrMalformedStates(t *testing.T) {
	for _, tc := range []struct {
		action, stdout, stderr string
		code                   int
		want                   bool
	}{
		{"is-active", "", "", 1, true},
		{"is-active", "inactive\n", "", 1, true},
		{"is-active", "unknown\n", "", 4, true},
		{"is-enabled", "", "", 1, true},
		{"is-enabled", "not-found\n", "", 1, true},
		{"is-enabled", "", "Failed to get unit file state for ipsec.service: No such file or directory\n", 1, true},
		{"is-enabled", "", "Unit ipsec.service could not be found.\n", 4, true},
		{"is-enabled", "", "Failed to get unit file state for 'ipsec.service': No such file or directory\n", 1, true},
		{"is-active", "active\n", "", 1, false},
		{"is-enabled", "enabled\n", "", 1, false},
		{"is-active", "failed\n", "", 4, false},
		{"is-active", "inactive\nactive\n", "", 1, false},
		{"is-enabled", "not-found\nmasked\n", "", 1, false},
		{"is-enabled", "not-found", "", 1, false},
		{"is-enabled", "not-found\n", "unrecognized failure\n", 1, false},
		{"is-enabled", "", "Something else went wrong\n", 1, false},
		{"is-enabled", "", "Unit other.service could not be found.\n", 1, false},
		{"is-enabled", "", "Unit ipsec.service could not be found.\n", 0, false},
		{"is-enabled", "", "Unit ipsec.service could not be found.\n", 2, false},
		{"is-active", "", "", 0, false},
		{"is-active", "", "", 3, false},
		{"is-enabled", "inactive\n", "", 1, false},
		{"is-enabled", "masked\n", "", 1, false},
		{"is-active", "\x1b[31mactive\n", "", 4, false},
	} {
		got := nativeVendorMissingStatusFallbackEligible(tc.action, "ipsec.service", []byte(tc.stdout), []byte(tc.stderr), tc.code)
		if got != tc.want {
			t.Fatalf("fallback entry mismatch action=%s code=%d stdout=%q stderr=%q: got=%t want=%t",
				tc.action, tc.code, tc.stdout, tc.stderr, got, tc.want)
		}
	}
	if nativeVendorMissingStatusFallbackEligible("is-enabled", "unlisted.service", nil, nil, 1) {
		t.Fatal("unlisted service identity permitted")
	}
	if nativeVendorMissingStatusFallbackEligible("start", "ipsec.service", nil, nil, 1) {
		t.Fatal("mutating action permitted")
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
		{"canonical missing enablement", "is-enabled", "not-found\n", "", 4, true, "not-found"},
		{"canonical missing but disk occupied", "is-enabled", "not-found\n", "", 4, false, ""},
		{"missing enablement diagnostic", "is-enabled", "", "Failed to get unit file state for ipsec.service: No such file or directory\n", 1, true, "not-found"},
		{"missing but proof failed", "is-enabled", "not-found\n", "", 1, false, ""},
		{"active cannot be overridden", "is-active", "active\n", "", 3, true, ""},
		{"enabled cannot be overridden", "is-enabled", "enabled\n", "", 1, true, ""},
		{"failed cannot be overridden", "is-active", "failed\n", "", 3, true, ""},
		{"extra lines cannot be overridden", "is-enabled", "not-found\nmasked\n", "", 1, true, ""},
		{"positive zero exit cannot be overridden", "is-enabled", "", "", 0, true, ""},
		{"unexpected failure exit cannot be overridden", "is-enabled", "", "", 7, true, ""},
		{"unrelated diagnostic cannot be overridden", "is-enabled", "", "File not found\n", 1, true, ""},
		{"mixed stdout and stderr cannot be overridden", "is-enabled", "not-found\n", "Unit ipsec.service could not be found.\n", 1, true, ""},
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
			if tc.name == "canonical missing but disk occupied" && verifierCalled != 1 {
				t.Fatal("canonical missing-unit result skipped disk verification")
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
	if state, err := interpretNativeVendorUnitState(ctx, "is-enabled", "ipsec.service",
		[]byte("not-found\n"), nil, 4, nil); err == nil || state != "" {
		t.Fatal("canonical not-found was admitted without an absence verifier")
	}
}

func TestNativeCanonicalNotFoundRejectsDormantDropIn(t *testing.T) {
	root := t.TempDir()
	const name = "charon-systemd.service"
	verify := func(_ context.Context, unit string) bool {
		return nativeMissingVendorUnitFiles(root, unit)
	}
	ctx := context.Background()
	check := func(wantAbsent bool) {
		t.Helper()
		state, err := interpretNativeVendorUnitState(ctx, "is-enabled", name,
			[]byte("not-found\n"), nil, 4, verify)
		if wantAbsent && (err != nil || state != "not-found") {
			t.Fatalf("clean missing vendor not admitted: state=%q err=%v", state, err)
		}
		if !wantAbsent && (err == nil || state != "") {
			t.Fatalf("dormant vendor identity admitted: state=%q err=%v", state, err)
		}
	}
	check(true)
	dropin := filepath.Join(root, "etc/systemd/system/charon-.service.d")
	if err := os.MkdirAll(dropin, 0o755); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err := os.Remove(dropin); err != nil {
		t.Fatal(err)
	}
	check(true)
}
