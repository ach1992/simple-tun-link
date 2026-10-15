package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/linux"
)

type nativeSystemdFixtureRunner struct {
	stdout        []byte
	stderr        []byte
	err           error
	calls         []string
	limits        []linux.CaptureLimits
	unboundedUsed bool
}

func (r *nativeSystemdFixtureRunner) Run(_ context.Context, _ string, _ ...string) (linux.CommandResult, error) {
	r.unboundedUsed = true
	return linux.CommandResult{}, errors.New("unbounded execution forbidden")
}

func (r *nativeSystemdFixtureRunner) RunBounded(_ context.Context, limits linux.CaptureLimits, bin string, args ...string) (linux.CommandResult, error) {
	r.calls = append(r.calls, strings.Join(append([]string{bin}, args...), " "))
	r.limits = append(r.limits, limits)
	return linux.CommandResult{Stdout: r.stdout, Stderr: r.stderr}, r.err
}

func nativeSystemdLoadedFixture(load string) []byte {
	return []byte(nativeSystemdUnitName + " " + load + " inactive dead Proposed STL IPsec daemon\n")
}

func TestNativeSystemdInventoryOnlyAndNoInducedLoading(t *testing.T) {
	cases := []struct {
		name       string
		stdout     []byte
		wantStatus string
		wantCode   string
	}{
		{"unit absent from in-memory list", nil, "blocked", "native_systemd_unit_not_loaded"},
		{"unit already in memory but overrides unverified", nativeSystemdLoadedFixture("loaded"), "unknown", "native_systemd_unit_unverified"},
		{"failed unit", nativeSystemdLoadedFixture("bad-setting"), "blocked", "native_systemd_unit_conflict"},
		{"masked unit", nativeSystemdLoadedFixture("masked"), "blocked", "native_systemd_unit_conflict"},
		{"unprovisioned placeholder", nativeSystemdLoadedFixture("not-found"), "blocked", "native_systemd_unit_not_provisioned"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &nativeSystemdFixtureRunner{stdout: tc.stdout}
			got := inspectNativeSystemdLoadedUnit(context.Background(), runner)
			if got.Status != tc.wantStatus || got.ReasonCode != tc.wantCode || got.NextStep == "" {
				t.Fatalf("incomplete/unsafe manager observation: %+v", got)
			}
			if runner.unboundedUsed || len(runner.limits) != 1 || runner.limits[0].Stdout != maxSystemdListBytes ||
				runner.limits[0].Stderr != maxSystemdStderrBytes {
				t.Fatal("systemd manager probe used unbounded execution")
			}
			want := "/usr/bin/systemctl " + strings.Join(nativeSystemdListArgs, " ")
			if len(runner.calls) != 1 || runner.calls[0] != want {
				t.Fatalf("unexpected systemd command: %q", runner.calls)
			}
			if strings.Contains(want, " show ") || strings.Contains(want, " GetUnit") || strings.Contains(want, " LoadUnit") {
				t.Fatal("a unit-object lookup can induce manager loading")
			}
			encoded, err := json.Marshal(got)
			if err != nil || strings.Contains(string(encoded), "private_key") || strings.Contains(string(encoded), "PSK=") {
				t.Fatalf("result leaked secret or JSON failed: %v", err)
			}
		})
	}
}

func TestNativeSystemdLoadedOutputNeverAttestsUnknownEffectiveState(t *testing.T) {
	valid := nativeSystemdLoadedFixture("loaded")
	cases := map[string][]byte{
		"empty valid but not a positive owner": nil,
		"partial":                              []byte(nativeSystemdUnitName + " loaded\n"),
		"duplicated row":                       append(append([]byte(nil), valid...), valid...),
		"unknown load state":                   nativeSystemdLoadedFixture("future-state"),
		"not-found but active":                 []byte(nativeSystemdUnitName + " not-found active running Unsafe identity\n"),
		"not-found but failed":                 []byte(nativeSystemdUnitName + " not-found inactive failed Unsafe identity\n"),
		"unexpected name":                      []byte("strongswan.service loaded active running Foreign strongSwan daemon\n"),
		"unexpected alias":                     []byte(nativeSystemdUnitName + " loaded active running strongswan.service\n"),
		"dropin-like property injection":       append(append([]byte(nil), valid...), []byte("DropInPaths=/etc/systemd/system/debug.conf\n")...),
		"fragment-like property injection":     []byte("FragmentPath=/usr/lib/systemd/system/strongswan.service\n"),
		"generator-like property injection":    []byte("SourcePath=/run/systemd/generator/private\n"),
		"Unicode marker":                       []byte("● " + string(valid)),
		"oversized":                            []byte(strings.Repeat("A", maxSystemdListBytes+1)),
		"missing newline":                      []byte(strings.TrimSuffix(string(valid), "\n")),
		"embedded CR":                          append(append([]byte(nil), valid...), []byte("\r")...),
		"embedded NUL":                         []byte(nativeSystemdUnitName + " loaded active running\x00 poisoned\n"),
		"extra blank line":                     append(append([]byte(nil), valid...), '\n'),
	}
	for label, data := range cases {
		t.Run(label, func(t *testing.T) {
			got := inspectNativeSystemdLoadedUnit(context.Background(), &nativeSystemdFixtureRunner{stdout: data})
			if label == "empty valid but not a positive owner" {
				if got.Status != "blocked" || got.ReasonCode != "native_systemd_unit_not_loaded" {
					t.Fatalf("missing unit interpreted as owned: %+v", got)
				}
			} else if got.Status != "unknown" || got.ReasonCode != "native_systemd_unit_unverified" {
				t.Fatalf("invalid manager output promoted to observation: %+v", got)
			}
		})
	}
}

type systemdUnboundedOnly struct{ calls int }

func (r *systemdUnboundedOnly) Run(_ context.Context, _ string, _ ...string) (linux.CommandResult, error) {
	r.calls++
	return linux.CommandResult{Stdout: nativeSystemdLoadedFixture("loaded")}, nil
}

func TestNativeSystemdFailClosedOnUnavailableBoundedRunnerAndErrors(t *testing.T) {
	plain := &systemdUnboundedOnly{}
	got := inspectNativeSystemdLoadedUnit(context.Background(), plain)
	if got.Status != "unknown" || plain.calls != 0 {
		t.Fatal("unbounded fallback allowed")
	}
	for _, tt := range []struct {
		name   string
		ctx    context.Context
		runner *nativeSystemdFixtureRunner
	}{
		{"failed command", context.Background(), &nativeSystemdFixtureRunner{err: errors.New("PSK=NEVER_PRINT")}},
		{"unexpected stderr", context.Background(), &nativeSystemdFixtureRunner{stderr: []byte("PSK=NEVER_PRINT")}},
		{"nil context", nil, &nativeSystemdFixtureRunner{}},
		{"nil runner", context.Background(), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var runner linux.Runner = tt.runner
			if tt.runner == nil {
				runner = nil
			}
			got := inspectNativeSystemdLoadedUnit(tt.ctx, runner)
			if got.Status != "unknown" || got.ReasonCode != "native_systemd_unit_unverified" {
				t.Fatalf("error or incomplete probe upgraded: %+v", got)
			}
			data, _ := json.Marshal(got)
			if strings.Contains(string(data), "NEVER_PRINT") {
				t.Fatal("untrusted diagnostics escaped output")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := inspectNativeSystemdLoadedUnit(ctx, &nativeSystemdFixtureRunner{}); got.Status != "unknown" {
		t.Fatal("canceled probe accepted")
	}
}
