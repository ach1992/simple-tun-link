package linux

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type wssVacancyRunner struct {
	result    map[string]string
	fail      string
	cancel    context.CancelFunc
	calls     []string
	stderrFor string
}

func (r *wssVacancyRunner) Run(ctx context.Context, binary string, args ...string) (CommandResult, error) {
	return r.RunBounded(ctx, CaptureLimits{Stdout: 1 << 20, Stderr: 1 << 16}, binary, args...)
}

func (r *wssVacancyRunner) RunBounded(_ context.Context, _ CaptureLimits, binary string, args ...string) (CommandResult, error) {
	command := binary + " " + strings.Join(args, " ")
	r.calls = append(r.calls, command)
	if command == r.fail {
		return CommandResult{}, errors.New("unavailable inventory")
	}
	if command == "wg show all listen-port" && r.cancel != nil {
		r.cancel()
	}
	out, exists := r.result[command]
	if !exists {
		return CommandResult{}, errors.New("unexpected inventory request")
	}
	if command == r.stderrFor {
		return CommandResult{Stdout: []byte(out), Stderr: []byte("SENSITIVE_FOREIGN_WG_STDERR")}, nil
	}
	return CommandResult{Stdout: []byte(out)}, nil
}

func TestWSSGuardVacancyGlobalAgreementAndFailClosed(t *testing.T) {
	local := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	other := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	original := map[string]string{
		"wg show interfaces":      "foreign0",
		"wg show all public-key":  "foreign0 " + other + "\n",
		"wg show all listen-port": "foreign0 51872\n",
		"ss -H -u -l -n":          "UNCONN 0 0 0.0.0.0:51872 0.0.0.0:*\n",
	}
	cases := []struct {
		name    string
		change  func(map[string]string)
		deny    bool
		wantErr bool
	}{
		{"vacant", nil, false, false},
		{"no_interfaces", func(m map[string]string) {
			for k := range m {
				m[k] = ""
			}
		}, false, false},
		{"matching_local_key", func(m map[string]string) {
			m["wg show all public-key"] = "foreign0 " + local
		}, true, false},
		{"matching_udp", func(m map[string]string) {
			m["wg show all listen-port"] = "foreign0 51871"
		}, true, false},
		// wireguard-tools prints a numeric zero for an unconfigured
		// listen-port; "off" belongs to the separate fwmark field.
		{"unconfigured_numeric_zero", func(m map[string]string) {
			m["wg show all listen-port"] = "foreign0 0\n"
		}, false, false},
		{"noncanonical_off_listen_port", func(m map[string]string) {
			m["wg show all listen-port"] = "foreign0 off\n"
		}, true, true},
		{"noncanonical_leading_zero_listen_port", func(m map[string]string) {
			m["wg show all listen-port"] = "foreign0 00\n"
		}, true, true},
		// A wireguard interface created in this (guard) namespace may
		// disappear from wg show when moved to another namespace, while
		// its live UDP socket stays here. Namespace-local wg inventories
		// alone would falsely authorize deletion.
		{"migrated_live_socket", func(m map[string]string) {
			m["wg show interfaces"] = ""
			m["wg show all public-key"] = ""
			m["wg show all listen-port"] = ""
			m["ss -H -u -l -n"] = "UNCONN 0 0 0.0.0.0:51871 0.0.0.0:*\n"
		}, true, false},
		{"migrated_live_socket_ipv6", func(m map[string]string) {
			m["wg show interfaces"] = ""
			m["wg show all public-key"] = ""
			m["wg show all listen-port"] = ""
			m["ss -H -u -l -n"] = "UNCONN 0 0 [::]:51871 [::]:*\n"
		}, true, false},
		{"malformed_socket_inventory", func(m map[string]string) {
			m["ss -H -u -l -n"] = "INCOMPLETE\n"
		}, true, true},
		{"missing_key_row", func(m map[string]string) { m["wg show all public-key"] = "" }, true, true},
		{"missing_port_row", func(m map[string]string) { m["wg show all listen-port"] = "" }, true, true},
		{"unknown_interface", func(m map[string]string) {
			m["wg show all public-key"] = "another0 " + other
		}, true, true},
		{"duplicate_interface", func(m map[string]string) {
			m["wg show interfaces"] = "foreign0 foreign0"
		}, true, true},
		{"duplicate_row", func(m map[string]string) {
			m["wg show all public-key"] += "foreign0 " + other
		}, true, true},
		{"malformed_public_key", func(m map[string]string) {
			m["wg show all public-key"] = "foreign0 invalid"
		}, true, true},
		{"malformed_port", func(m map[string]string) {
			m["wg show all listen-port"] = "foreign0 65536"
		}, true, true},
		{"incomplete_inventory", func(m map[string]string) {
			m["wg show interfaces"] = "foreign0 other0"
		}, true, true},
		{"malformed_name", func(m map[string]string) {
			m["wg show interfaces"] = "foreign0/../../evil"
		}, true, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			data := make(map[string]string)
			for k, v := range original {
				data[k] = v
			}
			if tt.change != nil {
				tt.change(data)
			}
			run := &wssVacancyRunner{result: data}
			clear, err := WSSGlobalWGKernelVacant(context.Background(), run, "wg", local, 51871)
			if (err != nil) != tt.wantErr || (err == nil && clear == tt.deny) {
				t.Fatalf("clear=%t err=%v want deny=%t wantErr=%t", clear, err, tt.deny, tt.wantErr)
			}
			if len(run.calls) > 4 {
				t.Fatal("unexpected repeated inventory reads")
			}
		})
	}
	for _, tc := range []struct {
		name string
		ctx  func(*wssVacancyRunner) context.Context
	}{
		{"canceled_before", func(*wssVacancyRunner) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
		{"canceled_during", func(r *wssVacancyRunner) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			r.cancel = cancel
			return ctx
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &wssVacancyRunner{result: original}
			ctx := tc.ctx(run)
			clear, err := WSSGlobalWGKernelVacant(ctx, run, "wg", local, 51871)
			if err == nil || clear {
				t.Fatalf("canceled inspection released guard: %v", err)
			}
		})
	}
	run := &wssVacancyRunner{result: original, fail: "wg show all public-key"}
	if clear, err := WSSGlobalWGKernelVacant(context.Background(), run, "wg", local, 51871); err == nil || clear {
		t.Fatalf("unavailable global inventory proved vacancy: %v", err)
	}
	run = &wssVacancyRunner{result: original, fail: "ss -H -u -l -n"}
	if clear, err := WSSGlobalWGKernelVacant(context.Background(), run, "wg", local, 51871); err == nil || clear {
		t.Fatalf("unavailable birthplace socket inventory proved vacancy: %v", err)
	}
}

// The same live-WG vacancy reader protects both legacy WSS guard retirement
// and the new QUIC pre-create admission. Successful exit with ANY stderr is
// ambiguous, never proof of vacant original keys/ports or migratable sockets.
func TestWSSGlobalWGKernelVacantRejectsEachSuccessfulWGDiagnostic(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	for _, command := range []string{"wg show interfaces", "wg show all public-key", "wg show all listen-port"} {
		t.Run(command, func(t *testing.T) {
			r := &wssVacancyRunner{result: map[string]string{
				"wg show interfaces":      "",
				"wg show all public-key":  "",
				"wg show all listen-port": "",
				"ss -H -u -l -n":          "",
			}, stderrFor: command}
			vacant, err := WSSGlobalWGKernelVacant(context.Background(), r, "wg", key, 51871)
			if err == nil || vacant || strings.Contains(err.Error(), "SENSITIVE_FOREIGN_WG_STDERR") {
				t.Fatalf("successful but ambiguous WG inventory accepted/leaked: vacant=%t err=%v", vacant, err)
			}
		})
	}
	ordinary := &wssVacancyRunner{result: map[string]string{
		"wg show interfaces": "", "wg show all public-key": "",
		"wg show all listen-port": "", "ss -H -u -l -n": "",
	}}
	vacant, err := WSSGlobalWGKernelVacant(context.Background(), ordinary, "wg", key, 51871)
	if err != nil || !vacant {
		t.Fatalf("clean empty WG inventory rejected: %v", err)
	}
}
