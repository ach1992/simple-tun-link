package quicguard

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const testBootID = "1a2b3c4d-5e6f-789a-bcde-f0123456789a"
const testNetNS = "net:[4026532789]"

type liveGuardReader struct{ *guardTestRunner }

func (r liveGuardReader) RunBounded(ctx context.Context, lim linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	result, err := r.guardTestRunner.RunBounded(ctx, lim, name, args...)
	if err == nil && name == "nft" && reflect.DeepEqual(args, []string{"-j", "list", "tables"}) && r.present {
		// The old QUIC fixture tests did not require census handle identity.
		// For actual stable observation the two complete nft views must agree.
		result.Stdout = []byte(strings.Replace(string(result.Stdout), `"handle":2`, `"handle":1`, 1))
	}
	return result, err
}

func TestReadOnlyIngressGuardHandlesRejectMissingOrDriftedHostEvidence(t *testing.T) {
	t.Run("complete matching shape", func(t *testing.T) {
		underlying, wg := guardFixture(t)
		underlying.present = true
		guard, err := linux.NewQUICWGIngressPlan(fixtureID, wg.ListenPort, fixtureNonce)
		if err != nil {
			t.Fatal(err)
		}
		present, handles, err := linux.ReadWGIngressGuardHandles(context.Background(), liveGuardReader{underlying}, guard)
		if err != nil || !present || handles != (linux.WGIngressLiveHandles{Table: 1, Chain: 1, Rule: 2}) {
			t.Fatalf("valid original nft handles not read: present=%t h=%+v err=%v", present, handles, err)
		}
		// Handles prove only objects were observed, never that this caller
		// created them or has automatic cleanup authority after a crash.
	})
	t.Run("complete absence is scoped", func(t *testing.T) {
		underlying, wg := guardFixture(t)
		guard, _ := linux.NewQUICWGIngressPlan(fixtureID, wg.ListenPort, fixtureNonce)
		present, handles, err := linux.ReadWGIngressGuardHandles(context.Background(), liveGuardReader{underlying}, guard)
		if err != nil || present || handles != (linux.WGIngressLiveHandles{}) {
			t.Fatalf("absence incorrectly fabricated live handles: %+v %t %v", handles, present, err)
		}
	})
	for _, tt := range []struct {
		name   string
		change func(*guardTestRunner)
	}{
		{"census/table handle mismatch", func(*guardTestRunner) {}},
		{"missing table handle", func(r *guardTestRunner) {
			r.exact = []byte(strings.Replace(string(r.exact), `"handle":1`, `"handle":0`, 1))
		}},
		{"missing chain handle", func(r *guardTestRunner) {
			r.exact = []byte(strings.Replace(string(r.exact), `"name":"ingress","handle":1`, `"name":"ingress","handle":0`, 1))
		}},
		{"missing rule handle", func(r *guardTestRunner) {
			r.exact = []byte(strings.Replace(string(r.exact), `"handle":2`, `"handle":0`, 1))
		}},
		{"nonce mismatch", func(r *guardTestRunner) { r.drift = true }},
		{"truncated nft tables", func(r *guardTestRunner) { r.badTables = true }},
		{"nft diagnostic stderr", func(r *guardTestRunner) { r.stderrFor = "nft -j list tables" }},
		{"table readback failed", func(r *guardTestRunner) { r.failed = "nft -j list table inet " + r.table }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			underlying, wg := guardFixture(t)
			underlying.present = true
			tt.change(underlying)
			guard, _ := linux.NewQUICWGIngressPlan(fixtureID, wg.ListenPort, fixtureNonce)
			reader := linux.BoundedRunner(underlying)
			if tt.name != "census/table handle mismatch" {
				reader = liveGuardReader{underlying}
			}
			present, handles, err := linux.ReadWGIngressGuardHandles(context.Background(), reader, guard)
			if err == nil || present || handles != (linux.WGIngressLiveHandles{}) || strings.Contains(err.Error(), "SENSITIVE_FOREIGN") {
				t.Fatalf("foreign nft evidence unexpectedly recognized: present=%t handles=%+v err=%v", present, handles, err)
			}
		})
	}
}

func TestReadOnlyQUICObservationRefusesUnadmittedEngineAndUntrustedBootSource(t *testing.T) {
	reader, _ := guardFixture(t)
	boot := func() (string, error) { return testBootID, nil }
	ns := func() (string, error) { return testNetNS, nil }
	ctx := context.Background()
	if _, err := inspectPendingOriginal(ctx, nil, fixtureID, reader, boot, ns); err == nil || len(reader.calls) != 0 {
		t.Fatal("original ingress observer accepted missing Engine")
	}
	engine, store := isolatedEngine(t)
	if _, err := inspectPendingOriginal(ctx, engine, fixtureID, reader, boot, ns); stlerr.CodeOf(err) != stlerr.CodeConflict || len(reader.calls) != 0 {
		t.Fatalf("original observer probed host without journal: %v", err)
	}
	in := isolatedIntent("listen")
	if _, err := engine.PrepareQUICCrash(ctx, in, isolatedVacancyProbe{}); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectPendingOriginal(ctx, engine, in.Plan.Local.LinkID, reader, boot, ns); stlerr.CodeOf(err) != stlerr.CodeState || len(reader.calls) != 0 {
		t.Fatalf("missing original materials allowed read-only host: %v", err)
	}
	if _, err := InspectPendingOriginal(ctx, engine, in.Plan.Local.LinkID); stlerr.CodeOf(err) != stlerr.CodeState {
		t.Fatalf("production source unexpectedly reported a present owner with missing materials: %v", err)
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only failure modified state: %v", err)
	}
	if _, err := inspectPendingOriginal(nil, engine, fixtureID, reader, boot, ns); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := inspectPendingOriginal(ctx, engine, fixtureID, nil, boot, ns); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := inspectPendingOriginal(ctx, engine, fixtureID, reader, nil, ns); err == nil {
		t.Fatal("nil host source accepted")
	}
}

func TestGuardObservationScopeIDValidation(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want bool
	}{
		{testNetNS, true}, {"net:[1]", true}, {"net:[0]", false}, {"net:[0123]", false},
		{"net:[1] extra", false}, {"pid:[4026532789]", false}, {"net:[-4]", false},
		{"net:[123456789012345678901]", false}, {"net:[123]", true},
	} {
		if validNetworkNamespaceID(tc.s) != tc.want {
			t.Fatalf("netns identifier acceptance mismatch %q", tc.s)
		}
	}
	if _, err := currentNetworkNamespace(); err != nil {
		t.Skipf("kernel network namespace unreadable in this test environment: %v", err)
	}
}
