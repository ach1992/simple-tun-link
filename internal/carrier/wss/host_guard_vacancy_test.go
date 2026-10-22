package wss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type wssGuardVacancyStub struct {
	table, comment string
	port           uint16
	local, other   string
	malformed      string
	wgCanceled     context.CancelFunc
	socketOccupied bool
	calls          []string
}

func (r *wssGuardVacancyStub) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	return r.RunBounded(ctx, linux.CaptureLimits{Stdout: 1 << 20, Stderr: 1 << 16}, name, args...)
}
func (r *wssGuardVacancyStub) RunBounded(_ context.Context, _ linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	switch {
	case call == "nft -j list tables":
		return linux.CommandResult{Stdout: []byte(fmt.Sprintf(`{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}},{"table":{"family":"inet","name":%q,"handle":1}}]}`, r.table))}, nil
	case call == "nft -j list table inet "+r.table:
		rows := []any{
			map[string]any{"metainfo": map[string]any{"version": "1.1.3", "json_schema_version": 1}},
			map[string]any{"table": map[string]any{"family": "inet", "name": r.table, "handle": 1}},
			map[string]any{"chain": map[string]any{"family": "inet", "table": r.table, "name": "ingress", "handle": 2, "type": "filter", "hook": "input", "prio": -250, "policy": "accept"}},
			map[string]any{"rule": map[string]any{"family": "inet", "table": r.table, "chain": "ingress", "handle": 3, "comment": r.comment, "expr": []any{
				map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": "lo"}},
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "udp", "field": "dport"}}, "right": r.port}},
				map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}},
				map[string]any{"drop": nil},
			}}},
		}
		raw, _ := json.Marshal(map[string]any{"nftables": rows})
		return linux.CommandResult{Stdout: raw}, nil
	case call == "ss -H -u -l -n":
		if r.socketOccupied {
			return linux.CommandResult{Stdout: []byte(fmt.Sprintf("UNCONN 0 0 0.0.0.0:%d 0.0.0.0:*\n", r.port))}, nil
		}
		return linux.CommandResult{}, nil
	case call == "wg show interfaces":
		return linux.CommandResult{Stdout: []byte("foreign0\n")}, nil
	case call == "wg show all public-key":
		if r.malformed == "key" {
			return linux.CommandResult{Stdout: []byte("")}, nil
		}
		return linux.CommandResult{Stdout: []byte("foreign0 " + r.other + "\n")}, nil
	case call == "wg show all listen-port":
		if r.wgCanceled != nil {
			r.wgCanceled()
		}
		if r.malformed == "port" {
			return linux.CommandResult{}, errors.New("readback unavailable")
		}
		port := uint16(45678)
		if r.local == "port" {
			port = r.port
		}
		return linux.CommandResult{Stdout: []byte("foreign0 " + strconv.Itoa(int(port)) + "\n")}, nil
	}
	return linux.CommandResult{}, errors.New("unexpected readback or attempted mutation: " + call)
}

// Verify a foreign WG listener/key appearing between kernel retirement and
// the last guard-deletion call cannot unprotect the global UDP listener.
// This test intentionally never executes an nft mutation on the host.
func TestWSSHostRemoveGuardFailsClosedBeforeNFTDeletion(t *testing.T) {
	l := wssTestLink()
	l.Backend = domain.BackendWireGuardWSS
	l.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	ctx, err := core.WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := linux.NewWSSWGIngressPlan(l.ID, l.WireGuard.ListenPort)
	if err != nil {
		t.Fatal(err)
	}
	guard.OriginalNonce = core.WSSOrigin(ctx)
	// Even an empty namespace-local WG/socket inventory is not enough
	// without the original index-targeted deletion that preceded this
	// guard boundary in the actual Engine transaction.
	noWitnessRunner := &wssGuardVacancyStub{
		table: guard.TableName(), port: l.WireGuard.ListenPort,
		comment: "stl:" + string(l.ID) + ":wg-udp-guard:" +
			strconv.Itoa(int(l.WireGuard.ListenPort)) + ":tx:" + core.WSSOrigin(ctx),
		other: l.WireGuard.PeerPublicKey,
	}
	if undo, err := (Host{Runner: noWitnessRunner}).RemoveGuard(ctx, l); err == nil || undo != nil {
		t.Fatal("WSS guard removal admitted absent original kernel-deletion witness")
	}
	for _, call := range noWitnessRunner.calls {
		if !strings.HasPrefix(call, "nft -j list") {
			t.Fatalf("guard proof missing but unsafe host command dispatched: %s", call)
		}
	}
	ctx, err = core.WithWSSWGDeleted(ctx, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, local, malformed string
		canceled               bool
	}{
		{"foreign_same_key", "key", "", false},
		{"foreign_same_port", "port", "", false},
		{"missing_key_inventory", "", "key", false},
		{"failed_port_inventory", "", "port", false},
		{"canceled_inventory", "", "", true},
		{"birthplace_udp_socket", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &wssGuardVacancyStub{
				table:   guard.TableName(),
				comment: "stl:" + string(l.ID) + ":wg-udp-guard:" + strconv.Itoa(int(l.WireGuard.ListenPort)) + ":tx:" + core.WSSOrigin(ctx),
				port:    l.WireGuard.ListenPort,
				local:   tc.local, malformed: tc.malformed, other: l.WireGuard.PeerPublicKey,
				socketOccupied: tc.name == "birthplace_udp_socket",
			}
			currentCtx := ctx
			if tc.canceled {
				var cancel context.CancelFunc
				currentCtx, cancel = context.WithCancel(ctx)
				run.wgCanceled = cancel
				defer cancel()
			}
			if tc.local == "key" {
				run.other = l.WireGuard.LocalPublicKey
			}
			undo, err := (Host{Runner: run}).RemoveGuard(currentCtx, l)
			if err == nil || undo != nil {
				t.Fatalf("guard removal proceeded without vacancy: err=%v", err)
			}
			for _, call := range run.calls {
				if !strings.HasPrefix(call, "nft -j list") && !strings.HasPrefix(call, "wg show") &&
					call != "ss -H -u -l -n" {
					t.Fatalf("unsafe command dispatched: %s", call)
				}
			}
		})
	}
}
