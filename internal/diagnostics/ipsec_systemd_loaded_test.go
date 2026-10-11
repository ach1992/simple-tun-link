package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type nativeSystemdFixtureRunner struct {
	stdout []byte
	err    error
	calls  []string
}

func (r *nativeSystemdFixtureRunner) Run(_ context.Context, bin string, args ...string) (linux.CommandResult, error) {
	r.calls = append(r.calls, strings.Join(append([]string{bin}, args...), " "))
	return linux.CommandResult{Stdout: r.stdout, Stderr: []byte("PSK=SECRET_NEVER_PRINT")}, r.err
}

func nativeSystemdFixture(overrides map[string]string) []byte {
	props := []string{
		"Id=" + nativeSystemdUnitName,
		"Names=" + nativeSystemdUnitName,
		"Following=",
		"LoadState=loaded",
		"FragmentPath=" + ipsec.NativeExclusiveServiceUnitPath,
		"SourcePath=",
		"DropInPaths=",
		"NeedDaemonReload=no",
		"Transient=no",
		"UnitFileState=static",
	}
	for i, line := range props {
		key, _, _ := strings.Cut(line, "=")
		if value, ok := overrides[key]; ok {
			props[i] = key + "=" + value
		}
	}
	return []byte(strings.Join(props, "\n") + "\n")
}

func TestNativeSystemdLoadedUnitReadOnlyIdentityBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		mod        map[string]string
		wantStatus string
		wantCode   string
	}{
		{"canonical manager snapshot only", nil, "observed", "native_systemd_unit_loaded_snapshot"},
		{"missing unit", map[string]string{"LoadState": "not-found", "FragmentPath": "", "UnitFileState": ""}, "blocked", "native_systemd_unit_not_loaded"},
		{"missing but foreign source", map[string]string{"LoadState": "not-found", "FragmentPath": "", "UnitFileState": "", "SourcePath": "/run/generator/malicious"}, "blocked", "native_systemd_unit_conflict"},
		{"different fragment", map[string]string{"FragmentPath": "/usr/lib/systemd/system/strongswan.service"}, "blocked", "native_systemd_unit_conflict"},
		{"drop-in override", map[string]string{"DropInPaths": "/etc/systemd/system/simple-tun-link-ipsec.service.d/debug.conf"}, "blocked", "native_systemd_unit_conflict"},
		{"foreign alias", map[string]string{"Names": nativeSystemdUnitName + " strongswan.service"}, "blocked", "native_systemd_unit_conflict"},
		{"following unit", map[string]string{"Following": "strongswan.service"}, "blocked", "native_systemd_unit_conflict"},
		{"generated config", map[string]string{"SourcePath": "/etc/init.d/ipsec"}, "blocked", "native_systemd_unit_conflict"},
		{"pending reload", map[string]string{"NeedDaemonReload": "yes"}, "blocked", "native_systemd_unit_conflict"},
		{"transient unit", map[string]string{"Transient": "yes"}, "blocked", "native_systemd_unit_conflict"},
		{"linked unit", map[string]string{"UnitFileState": "linked"}, "blocked", "native_systemd_unit_conflict"},
		{"enabled unit", map[string]string{"UnitFileState": "enabled"}, "blocked", "native_systemd_unit_conflict"},
		{"masked unit", map[string]string{"LoadState": "masked"}, "blocked", "native_systemd_unit_conflict"},
		{"wrong ID", map[string]string{"Id": "strongswan.service"}, "blocked", "native_systemd_unit_conflict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &nativeSystemdFixtureRunner{stdout: nativeSystemdFixture(tt.mod)}
			got := inspectNativeSystemdLoadedUnit(context.Background(), runner)
			if got.Status != tt.wantStatus || got.ReasonCode != tt.wantCode || got.NextStep == "" {
				t.Fatalf("incorrect state or unsafe admission: %+v", got)
			}
			if len(runner.calls) != 1 || runner.calls[0] != "/usr/bin/systemctl "+strings.Join(nativeSystemdShowArgs, " ") {
				t.Fatalf("unexpected systemd invocation: %q", runner.calls)
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "SECRET_NEVER_PRINT") || strings.Contains(string(data), "strongswan.service.d/debug.conf") {
				t.Fatal("raw stderr or path was exposed in public diagnostics")
			}
		})
	}
}

func TestNativeSystemdLoadedUnitUnknownIsNotVacancy(t *testing.T) {
	valid := nativeSystemdFixture(nil)
	cases := map[string][]byte{
		"empty":        nil,
		"partial":      []byte("Id=" + nativeSystemdUnitName + "\n"),
		"duplicate":    append(append([]byte(nil), valid...), []byte("Id="+nativeSystemdUnitName+"\n")...),
		"unknown key":  append(append([]byte(nil), valid...), []byte("ExecStartPost=unsafe\n")...),
		"oversized":    append(append([]byte(nil), valid...), []byte(strings.Repeat("X", maxSystemdShowBytes))...),
		"no newline":   []byte(strings.TrimSuffix(string(valid), "\n")),
		"embedded CR":  append(append([]byte(nil), valid...), []byte("Id=poison\r\n")...),
		"embedded NUL": append(append([]byte(nil), valid...), []byte("Id=poison\x00\n")...),
		"extra empty":  append(append([]byte(nil), valid...), '\n'),
	}
	for label, data := range cases {
		t.Run(label, func(t *testing.T) {
			got := inspectNativeSystemdLoadedUnit(context.Background(), &nativeSystemdFixtureRunner{stdout: data})
			if got.Status != "unknown" || got.ReasonCode != "native_systemd_unit_unverified" {
				t.Fatalf("invalid manager output treated as admissible: %+v", got)
			}
		})
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
	}{
		{"command failure", context.Background(), errors.New("PSK=DO_NOT_PRINT")},
		{"nil context", nil, nil},
		{"nil runner unaffected", context.Background(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &nativeSystemdFixtureRunner{stdout: valid, err: tc.err}
			var got IPsecHostCheck
			if tc.name == "nil runner unaffected" {
				got = inspectNativeSystemdLoadedUnit(tc.ctx, nil)
			} else {
				got = inspectNativeSystemdLoadedUnit(tc.ctx, runner)
			}
			if got.Status != "unknown" || got.ReasonCode != "native_systemd_unit_unverified" {
				t.Fatalf("uncertain inspection was upgraded: %+v", got)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := inspectNativeSystemdLoadedUnit(ctx, &nativeSystemdFixtureRunner{stdout: valid}); got.Status != "unknown" {
		t.Fatal("cancelled inspection was accepted")
	}
}
