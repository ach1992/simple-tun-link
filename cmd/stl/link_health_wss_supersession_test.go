package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestHealthCenterPersistedSupersessionIsExplicitWithoutPeerProbe(t *testing.T) {
	root, oldID, nextID := cliSupersessionFixture(t)
	var out, errOut strings.Builder
	options := &runtimeOptions{stateRoot: root}
	code := runWithRuntime([]string{"link", "supersede-wss", string(oldID),
		"--replacement", string(nextID), "--confirm", string(oldID), "--json"},
		&out, &errOut, options)
	if code != 0 || errOut.Len() != 0 {
		t.Fatalf("cannot establish durable original supersession: code=%d err=%q", code, errOut.String())
	}
	// An otherwise healthy native Link must still receive its legitimate
	// independent probe, regardless of superseded WSS inventory membership.
	native := fixtureReadLink("lnk_ffffffffffffffffffffffffffffffff",
		"10.98.44.0/31", "10.98.44.1/31", domain.BackendGRE)
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: native})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, parallel := range []string{"1", "3"} {
		t.Run("parallel_"+parallel, func(t *testing.T) {
			var nativeCalls, forbiddenWSSCalls atomic.Int32
			deps := healthCenterServices{
				observe: func(_ context.Context, link domain.Link, _ runtimeOptions) (linkDiagnostic, error) {
					if link.ID != native.ID {
						forbiddenWSSCalls.Add(1)
					} else {
						nativeCalls.Add(1)
					}
					return parallelHealthMeasured(), nil
				},
			}
			code, raw, stderr := executeHealthRemediationTest(
				[]string{"diagnose", "--all", "--json", "--parallel", parallel},
				options, deps,
			)
			var report healthCenterResponse
			if err := json.Unmarshal([]byte(raw), &report); err != nil || code != 4 ||
				stderr != "" || report.Outcome != "complete" || report.Total != 3 ||
				report.Blocked != 2 || report.Observed != 1 || report.Unknown != 0 ||
				forbiddenWSSCalls.Load() != 0 || nativeCalls.Load() != 1 {
				t.Fatalf("batch did not correctly isolate original and native peer: %d %+v %q %v", code, report, stderr, err)
			}
			if strings.Contains(raw, "NEVER_LEAK") || strings.Contains(raw, "private_key") ||
				strings.Contains(raw, "wss_original_object_nonce") {
				t.Fatal("sensitive WSS State leaked through the batch report")
			}
			seen := make(map[domain.LinkID]healthLinkCheck)
			for _, check := range report.Checks {
				seen[check.Link.ID] = check
			}
			old := seen[oldID]
			if old.Status != "blocked" || old.ReasonCode != "wss_original_superseded" ||
				old.Link.Disposition != "quarantined_old" || old.Link.SupersededBy != nextID ||
				old.Observed != nil || !strings.Contains(old.NextStep, "plan-wss-replacement") ||
				!strings.Contains(old.NextStep, string(nextID)) {
				t.Fatalf("superseded old WSS was presented as ordinary WSS: %+v", old)
			}
			replacement := seen[nextID]
			if replacement.Status != "blocked" ||
				replacement.ReasonCode != "wss_active_diagnostics_not_implemented" ||
				replacement.Link.Disposition != "" || replacement.Link.SupersededBy != "" ||
				replacement.Observed != nil {
				t.Fatalf("unquarantined new WSS changed diagnostic semantics: %+v", replacement)
			}
			healthy := seen[native.ID]
			if healthy.Status != "observed" || healthy.ReasonCode != "link_peer_replied" ||
				healthy.Link.Disposition != "" || healthy.Observed == nil {
				t.Fatalf("unrelated healthy native Link lost independent evidence: %+v", healthy)
			}
			humanCode, human, humanErr := executeHealthRemediationTest(
				[]string{"diagnose", "--all", "--parallel", parallel}, options, deps)
			if humanCode != 4 || humanErr != "" ||
				!strings.Contains(human, string(oldID)+" wireguard-wss/udp: blocked/wss_original_superseded") ||
				!strings.Contains(human, string(nextID)) ||
				!strings.Contains(human, "peer replied: 1 | blocked: 2 | unknown: 0") ||
				strings.Contains(human, "NEVER_LEAK") {
				t.Fatalf("human batch concealed quarantine or claimed healthy original: %d %q %q", humanCode, human, humanErr)
			}
		})
	}
}

// A completed State read may return just after the requested total budget.
// The saved supersession relationship stays reportable, but an unprocessed
// row is UNKNOWN rather than being promoted to any completed diagnosis.
func TestHealthCenterSupersededWSSDoesNotOverrideInterruptedObservation(t *testing.T) {
	root, oldID, nextID := cliSupersessionFixture(t)
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		previous, exists := s.Find(oldID)
		if !exists {
			return context.Canceled
		}
		previous.WSSSupersededBy = nextID
		s.Upsert(previous)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var forbiddenProbeCalls atomic.Int32
	deps := healthCenterServices{
		load: func(ctx context.Context) (state.Snapshot, error) {
			<-ctx.Done()
			return snapshot, nil
		},
		observe: func(context.Context, domain.Link, runtimeOptions) (linkDiagnostic, error) {
			forbiddenProbeCalls.Add(1)
			return parallelHealthMeasured(), nil
		},
	}
	code, raw, stderr := executeHealthRemediationTest(
		[]string{"diagnose", "--all", "--json", "--timeout", "1ms", "--parallel", "2"},
		&runtimeOptions{stateRoot: root}, deps,
	)
	var report healthCenterResponse
	if err := json.Unmarshal([]byte(raw), &report); err != nil || code != 1 || stderr != "" ||
		report.Outcome != "interrupted" || report.Observed != 0 ||
		report.Blocked != 0 || report.Unknown != 2 || report.Total != 2 ||
		forbiddenProbeCalls.Load() != 0 {
		t.Fatalf("expired inventory manufactured a health or quarantine probe: code=%d %+v %q %v", code, report, stderr, err)
	}
	found := false
	for _, check := range report.Checks {
		if check.Link.ID == oldID {
			found = check.Status == "unknown" && check.ReasonCode == "diagnostic_interrupted" &&
				check.Link.Disposition == "quarantined_old" && check.Link.SupersededBy == nextID &&
				check.Observed == nil
		}
	}
	if !found {
		t.Fatalf("interruption hid or prematurely promoted saved supersession: %+v", report.Checks)
	}
}
