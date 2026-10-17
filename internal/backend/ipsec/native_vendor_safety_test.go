package ipsec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func vendorSafeFake(block string, observed *[]string) vendorStopSafetyOps {
	gate := func(name string) func(context.Context) error {
		return func(context.Context) error {
			*observed = append(*observed, name)
			if name == block {
				return errors.New("unverified host condition")
			}
			return nil
		}
	}
	return vendorStopSafetyOps{
		manager: gate("manager"), packages: gate("packages"),
		private: gate("private"),
		aliases: func(_ context.Context, fragment string) error {
			*observed = append(*observed, "aliases")
			if fragment != "/usr/lib/systemd/system/strongswan.service" || block == "aliases" {
				return errors.New("unverified host service alias")
			}
			return nil
		},
		configs: gate("configs"),
		owners: func(_ context.Context, state string) error {
			*observed = append(*observed, "owners")
			if state != "active" && state != "inactive" || block == "owners" {
				return errors.New("unknown selected vendor process/ports")
			}
			return nil
		},
	}
}

func TestVendorStopCompleteReadOnlyEligibility(t *testing.T) {
	all := []string{"manager", "private", "aliases", "configs", "owners", "packages"}
	for _, blocked := range append([]string{""}, all...) {
		t.Run("blocked_"+blocked, func(t *testing.T) {
			var calls []string
			err := vendorStopHostSafe(context.Background(), "active",
				"/usr/lib/systemd/system/strongswan.service", vendorSafeFake(blocked, &calls))
			if (err == nil) != (blocked == "") {
				t.Fatalf("blocked=%q error=%v", blocked, err)
			}
			if blocked == "" && !slices.Equal(calls, all) {
				t.Fatalf("complete host attestation missing: %v", calls)
			}
			if blocked != "" && (!slices.Contains(calls, blocked) ||
				slices.Contains(calls, "packages") && blocked != "packages") {
				t.Fatalf("unsafe dependent checks after a failure: blocked=%s calls=%v", blocked, calls)
			}
		})
	}
	for _, tc := range []struct{ state, fragment string }{
		{"unknown", "/usr/lib/systemd/system/strongswan.service"},
		{"failed", "/usr/lib/systemd/system/strongswan.service"},
		{"active", ""},
	} {
		var calls []string
		if err := vendorStopHostSafe(context.Background(), tc.state, tc.fragment,
			vendorSafeFake("", &calls)); err == nil || len(calls) != 0 {
			t.Fatalf("invalid selected identity admitted: %+v calls=%v err=%v", tc, calls, err)
		}
	}
}

func TestVendorStopReattestsCompleteHostAfterConsentUnderLock(t *testing.T) {
	approved := VendorServiceStopPlan{Unit: vendorServiceName, Active: "active", Enabled: "enabled"}
	independentChecks := []string{"manager", "private", "aliases", "configs", "owners", "packages"}
	for _, failure := range append([]string{""}, append(independentChecks, "state_drift", "failed_stop", "failed_disable", "failed_post")...) {
		t.Run("change_"+failure, func(t *testing.T) {
			var observations, transitions []string
			held, releases := false, 0
			ops := vendorStopExecutionOps{
				acquire: func(context.Context) (func(), error) {
					if held {
						t.Fatal("recursive host lease")
					}
					held = true
					return func() { held = false; releases++ }, nil
				},
				inspect: func(ctx context.Context) (VendorServiceStopPlan, error) {
					if !held {
						t.Fatal("STOP host eligibility was checked outside installed lock")
					}
					if err := vendorStopHostSafe(ctx, "active",
						"/usr/lib/systemd/system/strongswan.service",
						vendorSafeFake(failure, &observations)); err != nil {
						return VendorServiceStopPlan{}, err
					}
					if failure == "state_drift" {
						return VendorServiceStopPlan{Unit: vendorServiceName, Active: "inactive", Enabled: "enabled"}, nil
					}
					return approved, nil
				},
				transition: func(_ context.Context, action string) error {
					if !held {
						t.Fatal("service affected without installed lock")
					}
					transitions = append(transitions, action)
					if failure == "failed_"+action {
						return errors.New("partial effect")
					}
					return nil
				},
				postcheck: func(context.Context) (string, string, error) {
					if !held {
						t.Fatal("service postcheck outside installed lock")
					}
					if failure == "failed_post" {
						return "active", "enabled", nil
					}
					return "inactive", "disabled", nil
				},
			}
			err := stopDisableVerifiedVendorWithOps(context.Background(), approved, ops)
			if (err == nil) != (failure == "") || held || releases != 1 {
				t.Fatalf("full safety/lock failure=%s err=%v released=%d held=%t", failure, err, releases, held)
			}
			if slices.Contains(independentChecks, failure) || failure == "state_drift" {
				if len(transitions) != 0 {
					t.Fatalf("STOP/disable before full host safety: failure=%s transitions=%v", failure, transitions)
				}
				return
			}
			if failure == "" && !slices.Equal(transitions, []string{"stop", "disable"}) {
				t.Fatalf("successful exact-unit transition missing: %v", transitions)
			}
			if failure == "failed_stop" && !slices.Equal(transitions, []string{"stop"}) {
				t.Fatalf("continued after uncertain stop: %v", transitions)
			}
			if failure == "failed_disable" && !slices.Equal(transitions, []string{"stop", "disable"}) {
				t.Fatalf("stale disable failure path: %v", transitions)
			}
		})
	}
}

func TestVendorStopRejectsUnboundedOrMissingProductionOperations(t *testing.T) {
	cases := []VendorServiceStopPlan{
		{}, {Unit: "strongswan-swanctl.service", Active: "active", Enabled: "enabled"},
		{Unit: vendorServiceName, Active: "inactive", Enabled: "disabled"},
		{Unit: vendorServiceName, Active: "failed", Enabled: "enabled"},
	}
	for _, candidate := range cases {
		if err := stopDisableVerifiedVendorWithOps(context.Background(), candidate, vendorStopExecutionOps{
			acquire: func(context.Context) (func(), error) { t.Fatal("unexpected lease"); return nil, nil },
			inspect: func(context.Context) (VendorServiceStopPlan, error) {
				t.Fatal("unexpected inspect")
				return VendorServiceStopPlan{}, nil
			},
			transition: func(context.Context, string) error { t.Fatal("unauthorized transition"); return nil },
			postcheck:  func(context.Context) (string, string, error) { t.Fatal("unexpected postcheck"); return "", "", nil },
		}); err == nil {
			t.Fatalf("invalid service approval: %+v", candidate)
		}
	}
}

// The STOP safety gate and missing-unit gate must share the same systemd
// dependency inventory while allowing only unrelated units and the ordinary
// consented vendor .wants/.requires boot edges.
func TestVendorStopBootEdgesProtectUpholdsWithoutRejectingUnrelatedServices(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	checkSafe := func() {
		t.Helper()
		if err := vendorStopBootEdgesSafeAt(root); err != nil {
			t.Fatalf("clean or unrelated manager dependencies rejected: %v", err)
		}
	}
	checkUnsafe := func() {
		t.Helper()
		if err := vendorStopBootEdgesSafeAt(root); err == nil {
			t.Fatal("foreign or upheld vendor dependency admitted")
		}
	}
	checkSafe()
	for _, tc := range []struct{ dir, name string }{
		{"stl.target.wants", "charon-systemd.service"},
		{"stl.target.requires", "simple-tun-link-ipsec.service"},
		{"stl.target.upholds", "charon-systemd.service"},
		{"stl.target.upholds", "strongswan.service"},
		{"stl.target.upholds", "strongswan-swanctl.service"},
	} {
		t.Run(tc.dir+"_"+tc.name, func(t *testing.T) {
			edge := filepath.Join(base, tc.dir)
			if err := os.MkdirAll(edge, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(edge, tc.name)
			if err := os.Symlink("/missing/vendor.service", path); err != nil {
				t.Fatal(err)
			}
			checkUnsafe()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			checkSafe()
		})
	}
	for _, name := range []string{"strongswan.service", "strongswan-swanctl.service"} {
		// Normal official vendor enablement is not an unconditional STOP
		// conflict: a separately consented STOP can disable such an edge.
		for _, suffix := range []string{".wants", ".requires"} {
			edge := filepath.Join(base, "stl.target"+suffix)
			if err := os.MkdirAll(edge, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(edge, name)
			if err := os.Symlink(name, path); err != nil {
				t.Fatal(err)
			}
			checkSafe()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	edge := filepath.Join(base, "stl.target.upholds")
	unrelated := filepath.Join(edge, "unrelated.service")
	if err := os.Symlink("/missing/unrelated.service", unrelated); err != nil {
		t.Fatal(err)
	}
	checkSafe()
	if err := os.Remove(unrelated); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, target string }{
		{"stl-foreign-alias.service", "charon-systemd.service"},
		{"stl-upheld-alias.service", "strongswan.service"},
	} {
		if err := os.Symlink(tc.target, filepath.Join(edge, tc.name)); err != nil {
			t.Fatal(err)
		}
		checkUnsafe()
		if err := os.Remove(filepath.Join(edge, tc.name)); err != nil {
			t.Fatal(err)
		}
		checkSafe()
	}
	if err := os.Remove(edge); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), edge); err != nil {
		t.Fatal(err)
	}
	checkUnsafe()
	if err := os.Remove(edge); err != nil {
		t.Fatal(err)
	}
	checkSafe()
}
