package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func healthRemediationInventory() state.Snapshot {
	snapshot := state.EmptySnapshot()
	for _, link := range []domain.Link{
		fixtureReadLink("lnk_11111111111111111111111111111111", "10.80.11.0/31", "10.80.11.1/31", domain.BackendGRE),
		fixtureReadLink("lnk_22222222222222222222222222222222", "10.80.12.0/31", "10.80.12.1/31", domain.BackendIPIP),
	} {
		snapshot.Upsert(state.LinkRecord{Desired: link})
	}
	return snapshot
}

func executeHealthRemediationTest(args []string, options *runtimeOptions, deps healthCenterServices) (int, string, string) {
	var stdout, stderr strings.Builder
	exit := linkDiagnoseAllWithServices(args, &stdout, &stderr, options, deps)
	return exit, stdout.String(), stderr.String()
}

func TestHealthCenterDeadlineStartsBeforeStateLoad(t *testing.T) {
	snapshot := healthRemediationInventory()
	const runTimeout = "30ms"
	for _, tc := range []struct {
		name               string
		load               func(context.Context) (state.Snapshot, error)
		wantKnownInventory bool
	}{
		{
			name: "inventory_unavailable_after_deadline",
			load: func(ctx context.Context) (state.Snapshot, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("inventory load started without the requested total deadline")
				}
				<-ctx.Done()
				return state.Snapshot{}, ctx.Err()
			},
		},
		{
			name: "inventory_returned_after_deadline",
			load: func(ctx context.Context) (state.Snapshot, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("inventory read started outside requested batch deadline")
				}
				<-ctx.Done()
				return snapshot, nil
			},
			wantKnownInventory: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepareCalls, observeCalls := 0, 0
			deps := healthCenterServices{
				load: tc.load,
				prepare: func(context.Context) (*runtimeOptions, error) {
					prepareCalls++
					return &runtimeOptions{}, nil
				},
				observe: func(context.Context, domain.Link, runtimeOptions) (linkDiagnostic, error) {
					observeCalls++
					return linkDiagnostic{}, nil
				},
			}
			code, out, stderr := executeHealthRemediationTest(
				[]string{"diagnose", "--all", "--timeout", runTimeout, "--json"}, nil, deps,
			)
			if code != 1 || stderr != "" || prepareCalls != 0 || observeCalls != 0 {
				t.Fatalf("pre-probe expiration reached runtime/probes: exit=%d prep=%d inspect=%d out=%q stderr=%q",
					code, prepareCalls, observeCalls, out, stderr)
			}
			if tc.wantKnownInventory {
				var batch healthCenterResponse
				if err := json.Unmarshal([]byte(out), &batch); err != nil || batch.Total != 2 ||
					batch.Outcome != "interrupted" || batch.Unknown != 2 || len(batch.Checks) != 2 ||
					batch.Checks[0].ReasonCode != "diagnostic_interrupted" ||
					batch.Checks[1].ReasonCode != "diagnostic_interrupted" {
					t.Fatalf("known inventory was dropped, skipped or claimed observed: %+v %v", batch, err)
				}
			} else {
				var result linkReadErrorResponse
				if err := json.Unmarshal([]byte(out), &result); err != nil || result.SchemaVersion != 1 ||
					result.Error == nil || result.Error.ReasonCode != "diagnostic_interrupted" ||
					result.Error.NextStep == "" || strings.Contains(out, `"total":0`) {
					t.Fatalf("unknown inventory was claimed empty or healthy: %+v %v", result, err)
				}
			}
		})
	}
}

func TestHealthCenterDeadlineCoversRuntimeInitialization(t *testing.T) {
	snapshot := healthRemediationInventory()
	prepareCalls, observeCalls := 0, 0
	deps := healthCenterServices{
		load: func(ctx context.Context) (state.Snapshot, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("snapshot loader did not get the batch deadline")
			}
			return snapshot, nil
		},
		prepare: func(ctx context.Context) (*runtimeOptions, error) {
			prepareCalls++
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("diagnostic runtime initialization did not get batch deadline")
			}
			<-ctx.Done()
			// Even a late 'success' must not start observations.
			return &runtimeOptions{}, nil
		},
		observe: func(context.Context, domain.Link, runtimeOptions) (linkDiagnostic, error) {
			observeCalls++
			return linkDiagnostic{}, errors.New("should never observe after deadline")
		},
	}
	code, out, stderr := executeHealthRemediationTest(
		[]string{"diagnose", "--all", "--timeout", "250ms", "--json"}, nil, deps,
	)
	var result healthCenterResponse
	if err := json.Unmarshal([]byte(out), &result); err != nil || code != 1 || stderr != "" ||
		prepareCalls != 1 || observeCalls != 0 || result.Outcome != "interrupted" ||
		result.Total != 2 || result.Unknown != 2 || len(result.Checks) != 2 ||
		result.Checks[0].Status != "unknown" || result.Checks[1].Status != "unknown" {
		t.Fatalf("runtime preparation not covered by total deadline: code=%d out=%+v prep=%d probe=%d stderr=%q err=%v",
			code, result, prepareCalls, observeCalls, stderr, err)
	}
}

func TestHealthCenterDeadlineDuringLinkCannotPromoteLateHealthyResult(t *testing.T) {
	snapshot := healthRemediationInventory()
	observedIDs := make([]domain.LinkID, 0, 2)
	deps := healthCenterServices{
		load: func(ctx context.Context) (state.Snapshot, error) { return snapshot, nil },
		observe: func(ctx context.Context, link domain.Link, _ runtimeOptions) (linkDiagnostic, error) {
			observedIDs = append(observedIDs, link.ID)
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("in-progress Link has no inherited total deadline")
			}
			<-ctx.Done()
			// Simulate a noncooperative adapter that finishes after timeout
			// but returns seemingly successful observation anyway.
			return linkDiagnostic{
				quality:     diagnostics.QualityResult{Status: diagnostics.QualityMeasured, Reachable: true},
				counterUnit: "packets",
			}, nil
		},
	}
	code, out, stderr := executeHealthRemediationTest(
		[]string{"diagnose", "--all", "--timeout", "250ms", "--json"},
		&runtimeOptions{stateRoot: t.TempDir()}, deps,
	)
	var batch healthCenterResponse
	if err := json.Unmarshal([]byte(out), &batch); err != nil || code != 1 || stderr != "" ||
		len(observedIDs) != 1 || observedIDs[0] != snapshot.Links[0].Desired.ID ||
		batch.Outcome != "interrupted" || batch.Observed != 0 || batch.Unknown != 2 ||
		len(batch.Checks) != 2 || batch.Checks[0].Status != "unknown" ||
		batch.Checks[0].ReasonCode != "diagnostic_interrupted" || batch.Checks[0].Observed != nil ||
		batch.Checks[1].ReasonCode != "diagnostic_interrupted" || batch.Checks[1].Observed != nil {
		t.Fatalf("deadline inflated healthy result or began another probe: code=%d batch=%+v calls=%v stderr=%q err=%v",
			code, batch, observedIDs, stderr, err)
	}
}

func TestHealthCenterIPsecDoctorRecoveryIdenticalAcrossAllThreeSurfaces(t *testing.T) {
	root, implementations, probe, links := fixtureHealthCenter(t)
	wantID := links[3].ID
	var expectedReason, expectedStep string
	for _, operation := range []string{"status", "diagnose"} {
		exit, result, stderr := readCLI(t, root, nil, "link", operation, string(wantID), "--json")
		var response linkReadErrorResponse
		if err := json.Unmarshal([]byte(result), &response); err != nil || exit != 4 ||
			stderr != "" || response.Error == nil ||
			response.Error.ReasonCode != "ipsec_runtime_not_registered" ||
			response.Error.NextStep != ipsecDoctorNextStep {
			t.Fatalf("per-Link %s lost canonical doctor contract: code=%d output=%q stderr=%q err=%v",
				operation, exit, result, stderr, err)
		}
		if expectedReason == "" {
			expectedReason, expectedStep = response.Error.ReasonCode, response.Error.NextStep
		} else if response.Error.ReasonCode != expectedReason || response.Error.NextStep != expectedStep {
			t.Fatal("per-Link status and diagnose disagree on IPsec recovery")
		}
	}
	exit, result, stderr := runHealth(t, root, implementations, probe, "--json")
	var batch healthCenterResponse
	if err := json.Unmarshal([]byte(result), &batch); err != nil || exit != 4 || stderr != "" ||
		len(batch.Checks) != 4 || batch.Checks[3].Link.ID != wantID ||
		batch.Checks[3].Status != "blocked" ||
		batch.Checks[3].ReasonCode != expectedReason ||
		batch.Checks[3].NextStep != expectedStep ||
		batch.Checks[3].Observed != nil {
		t.Fatalf("all-Link IPsec recovery differs from doctor path: code=%d batch=%+v stderr=%q err=%v",
			exit, batch, stderr, err)
	}
}
