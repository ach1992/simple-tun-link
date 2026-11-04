package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	ipipbackend "github.com/ach1992/simple-tun-link/internal/backend/ipip"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// An Engine-backed, link-scoped fixture. Its first inspection may succeed and
// its second one may fail after resource locks. The fake never owns a second
// lifecycle algorithm: it exercises the production CLI -> Engine call.
type stagedIPIPInventory struct {
	*lifecycleFakeBackend
	reads         int
	failAt        int
	verifyInspect bool
}

func (*stagedIPIPInventory) Kind() domain.Backend { return domain.BackendIPIP }

func (b *stagedIPIPInventory) Inspect(ctx context.Context, link domain.Link) (backend.Observation, error) {
	b.reads++
	if b.reads == b.failAt {
		return nil, sampleIPIPInventoryIssue(nil)
	}
	return b.lifecycleFakeBackend.Inspect(ctx, link)
}

func (b *stagedIPIPInventory) Verify(ctx context.Context, req backend.Request) (backend.Observation, error) {
	if b.verifyInspect {
		if _, err := b.Inspect(ctx, req.Link); err != nil {
			return nil, err
		}
	}
	return b.lifecycleFakeBackend.Verify(ctx, req)
}

func sampleIPIPInventoryIssue(cause error) error {
	e := stlerr.Wrap(stlerr.CodeInspect, "ipip_inspect", "", "ipip",
		"PSK=VERY_SECRET_NOT_FOR_OUTPUT", cause)
	e.ReasonCode = "ipip_kernel_inventory_unverified"
	e.NextStep = "UNTRUSTED=VERY_SECRET_NOT_FOR_OUTPUT"
	return e
}

func TestIPIPInventoryFailureAtBothEnginePreApplyInspections(t *testing.T) {
	for _, operation := range []string{"ensure", "import", "remove"} {
		for _, failAt := range []int{1, 2} {
			for _, jsonOutput := range []bool{false, true} {
				t.Run(operation+"/stage_"+string(rune('0'+failAt))+"/json_"+map[bool]string{true: "yes", false: "no"}[jsonOutput], func(t *testing.T) {
					root := t.TempDir()
					link, _ := makeLifecycleDesired(t, "f", "10.70.52.0/31")
					link.Backend, link.Encapsulation = domain.BackendIPIP, domain.EncapNative
					fake := &stagedIPIPInventory{lifecycleFakeBackend: newLifecycleFake()}
					opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake},
						probeRunner: &greReceiverProbe{inventory: greReceiverInventory("eth0", link.Underlay.Peer.String())}}
					if operation == "remove" {
						before := desiredRequestJSON(t, link, desiredLinkSchemaVersion)
						var out, errOut bytes.Buffer
						if code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"}, strings.NewReader(before),
							&out, &errOut, opts); code != 0 {
							t.Fatalf("cannot seed saved IPIP link: %d %s %s", code, out.String(), errOut.String())
						}
						fake.reads = 0
					}
					prior, err := state.NewFileStore(root).Load(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					fake.failAt = failAt
					appliesBefore := len(fake.applies)
					var args []string
					var input string
					switch operation {
					case "ensure":
						args = []string{"link", "ensure", "--stdin"}
						input = desiredRequestJSON(t, link, desiredLinkSchemaVersion)
					case "import":
						encoded := testQuickSetupLink(t, link, nil)
						args = []string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(encoded)}
						input = encoded
					case "remove":
						args = []string{"link", "remove", string(link.ID), "--confirm", string(link.ID)}
					}
					if jsonOutput {
						args = append(args, "--json")
					}
					var stdout, stderr bytes.Buffer
					code := runWithRuntimeInput(args, strings.NewReader(input), &stdout, &stderr, opts)
					if code != 1 || len(fake.applies) != appliesBefore || fake.reads != failAt {
						t.Fatalf("failure bypassed canonical pre-Apply inspection: code=%d reads=%d apply=%d stdout=%q stderr=%q",
							code, fake.reads, len(fake.applies)-appliesBefore, stdout.String(), stderr.String())
					}
					if strings.Contains(stdout.String()+stderr.String(), "VERY_SECRET_NOT_FOR_OUTPUT") ||
						strings.Contains(stdout.String()+stderr.String(), "UNTRUSTED=") ||
						strings.Contains(stdout.String()+stderr.String(), link.DisplayName) {
						t.Fatalf("raw error or display name escaped: %q %q", stdout.String(), stderr.String())
					}
					now, err := state.NewFileStore(root).Load(context.Background())
					if err != nil || !reflect.DeepEqual(prior, now) {
						t.Fatalf("rejected %s changed saved state: before=%+v after=%+v err=%v", operation, prior, now, err)
					}
					wantStage := "inspect"
					if failAt == 2 {
						wantStage = "plan"
					}
					if jsonOutput {
						if stderr.Len() != 0 {
							t.Fatalf("JSON emitted stderr: %s", stderr.String())
						}
						var result lifecycleFailureResponse
						if json.Unmarshal(stdout.Bytes(), &result) != nil || result.Error == nil ||
							result.Error.Code != stlerr.CodeInspect ||
							result.Error.ReasonCode != "ipip_kernel_inventory_unverified" ||
							result.Error.Evidence == nil || result.Error.Evidence.Stage != wantStage ||
							result.Error.Evidence.HostMutation != "not_attempted" ||
							result.Error.Evidence.Rollback != "not_required" ||
							!strings.Contains(result.Error.NextStep, "ip -details -json link show type ipip") {
							t.Fatalf("IPIP %s second read lost stage/recovery: %+v %q", operation, result, stdout.String())
						}
					} else {
						if stdout.Len() != 0 || !strings.Contains(stderr.String(), "ipip_kernel_inventory_unverified") ||
							!strings.Contains(stderr.String(), "stage="+wantStage+" host_mutation=not_attempted") ||
							!strings.Contains(stderr.String(), "Next: ") {
							t.Fatalf("human %s stage/reason missing: %q %q", operation, stdout.String(), stderr.String())
						}
					}
				})
			}
		}
	}
}

func TestIPIPInventoryInterruptedBeforeApplyKeepsTimeoutPriority(t *testing.T) {
	for _, interruption := range []error{context.Canceled, context.DeadlineExceeded} {
		observed := sampleIPIPInventoryIssue(interruption)
		proof := &stlerr.OperationEvidence{Stage: "plan", HostMutation: "not_attempted",
			DesiredState: "no_commit_attempted", Rollback: "not_required"}
		var stdout, stderr bytes.Buffer
		exit := lifecycleFailureWithEvidence(&stdout, &stderr, true, stlerr.CodeInspect, "link_ensure",
			nil, "safe generic failure", proof, observed)
		var response lifecycleFailureResponse
		if exit != 1 || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil ||
			response.Error.ReasonCode == "ipip_kernel_inventory_unverified" ||
			strings.Contains(stdout.String(), "VERY_SECRET_NOT_FOR_OUTPUT") {
			t.Fatalf("interruption was misreported as inventory readiness: %+v", response)
		}
	}
}

func TestIPIPInventoryPostApplyVerifyUsesRealRollbackEvidence(t *testing.T) {
	root := t.TempDir()
	link, desired := makeLifecycleDesired(t, "c", "10.70.53.0/31")
	link.Backend, link.Encapsulation = domain.BackendIPIP, domain.EncapNative
	desired = desiredRequestJSON(t, link, desiredLinkSchemaVersion)
	fake := &stagedIPIPInventory{lifecycleFakeBackend: newLifecycleFake(), failAt: 3, verifyInspect: true}
	var stdout, stderr bytes.Buffer
	code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"}, strings.NewReader(desired),
		&stdout, &stderr, &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}})
	var response lifecycleFailureResponse
	if code != 1 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &response) != nil ||
		response.Error == nil || response.Error.Evidence == nil ||
		response.Error.Evidence.Stage != "verify" || response.Error.Evidence.HostMutation != "attempted" ||
		response.Error.Evidence.Rollback != "completed_unverified" ||
		response.Error.ReasonCode != "rollback_completed_unverified" ||
		len(fake.applies) != 1 || fake.present[link.ID] ||
		strings.Contains(stdout.String(), "VERY_SECRET_NOT_FOR_OUTPUT") ||
		strings.Contains(stdout.String(), "no host state was applied") {
		t.Fatalf("post-Apply failure falsely claimed no host effect: code=%d response=%+v out=%s", code, response, stdout.String())
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snapshot.Links) != 0 {
		t.Fatalf("failed verify committed Link: %+v %v", snapshot, err)
	}
}

func TestIPIPInventoryDiagnosticSurfacesStayTypedAndSecretSafe(t *testing.T) {
	for _, backendError := range []struct {
		name       string
		err        error
		wantReason string
	}{
		{"unknown inventory", sampleIPIPInventoryIssue(nil), "ipip_kernel_inventory_unverified"},
		{"proven inactive module", backend.KernelModuleNotLoaded("ipip"), "kernel_module_not_loaded"},
		{"raw failure", errors.New("private_key=VERY_SECRET_NOT_FOR_OUTPUT"), "observation_unverified"},
	} {
		t.Run(backendError.name, func(t *testing.T) {
			root := t.TempDir()
			link := fixtureReadLink("lnk_88888888888888888888888888888888", "10.80.80.0/31", "10.80.80.1/31", domain.BackendIPIP)
			storeReadLinks(t, root, link)
			name, _ := ipipbackend.InterfaceName(link.ID)
			inspector := &readIPIPDiagnosticBackend{
				capability: linux.CapabilityStatus{Available: true},
				state:      ipipbackend.DiagnosticState{Interface: name, IfIndex: 77, Encapsulation: domain.EncapNative},
				err:        backendError.err,
			}
			probe := &readGREProbeRunner{link: link, name: name, observedIndex: 77}
			for _, variant := range []struct {
				label string
				args  []string
				json  bool
			}{
				{"status_json", []string{"link", "status", string(link.ID), "--json"}, true},
				{"status_human", []string{"link", "status", string(link.ID)}, false},
				{"diagnose_json", []string{"link", "diagnose", string(link.ID), "--json"}, true},
				{"diagnose_human", []string{"link", "diagnose", string(link.ID)}, false},
				{"all_json", []string{"link", "diagnose", "--all", "--json"}, true},
				{"all_human", []string{"link", "diagnose", "--all"}, false},
			} {
				t.Run(variant.label, func(t *testing.T) {
					var stdout, stderr bytes.Buffer
					code := runWithRuntime(variant.args, &stdout, &stderr, &runtimeOptions{
						stateRoot: root, backends: []backend.Backend{inspector}, probeRunner: probe,
					})
					if code == 0 || strings.Contains(stdout.String()+stderr.String(), "VERY_SECRET_NOT_FOR_OUTPUT") ||
						strings.Contains(stdout.String()+stderr.String(), "UNTRUSTED=") {
						t.Fatalf("unsafe diagnostic: exit=%d out=%q err=%q", code, stdout.String(), stderr.String())
					}
					if variant.json {
						if stderr.Len() != 0 {
							t.Fatalf("JSON stderr: %s", stderr.String())
						}
						if variant.label == "all_json" {
							var r healthCenterResponse
							wantUnknown, wantBlocked := 1, 0
							if backendError.wantReason == "kernel_module_not_loaded" {
								wantUnknown, wantBlocked = 0, 1
							}
							if json.Unmarshal(stdout.Bytes(), &r) != nil || r.Unknown != wantUnknown || r.Blocked != wantBlocked || len(r.Checks) != 1 ||
								r.Checks[0].ReasonCode != map[string]string{"observation_unverified": "diagnostic_observation_unverified", "ipip_kernel_inventory_unverified": "ipip_kernel_inventory_unverified", "kernel_module_not_loaded": "kernel_module_not_loaded"}[backendError.wantReason] ||
								r.Checks[0].Observed != nil || r.Checks[0].NextStep == "" {
								t.Fatalf("bad multi-Link health: %+v %s", r, stdout.String())
							}
						} else {
							var r linkReadErrorResponse
							want := backendError.wantReason
							if json.Unmarshal(stdout.Bytes(), &r) != nil || r.Error == nil || r.Error.ReasonCode != want ||
								r.Error.NextStep == "" || r.Error.Code != stlerr.CodeInspect {
								t.Fatalf("diagnostic did not preserve safe reason: %+v %s", r, stdout.String())
							}
						}
					} else {
						expected := backendError.wantReason
						if variant.label == "all_human" && expected == "observation_unverified" {
							expected = "diagnostic_observation_unverified"
						}
						payload := stdout.String() + stderr.String()
						if !strings.Contains(payload, expected) || !strings.Contains(payload, "Next:") {
							t.Fatalf("human diagnostic lost action: %q", payload)
						}
					}
				})
			}
			if probe.probes != 0 {
				t.Fatalf("diagnostics probed peer after invalid inventory: %d", probe.probes)
			}
		})
	}
}

func TestIPIPInventoryReadCancellationAndBackendScope(t *testing.T) {
	issue := sampleIPIPInventoryIssue(context.Canceled)
	if isIPIPInventoryUnverified(issue) {
		t.Fatal("canceled observation reported as inventory defect")
	}
	issue = sampleIPIPInventoryIssue(context.DeadlineExceeded)
	if isIPIPInventoryUnverified(issue) {
		t.Fatal("timed-out observation reported as inventory defect")
	}
	foreign := stlerr.New(stlerr.CodeInspect, "gre_inspect", "", "gre", "foreign secret")
	foreign.ReasonCode = "ipip_kernel_inventory_unverified"
	if isIPIPInventoryUnverified(foreign) {
		t.Fatal("other backend impersonated IPIP inventory reason")
	}
	var stdout, stderr bytes.Buffer
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	code := readStatusInspectionError(canceled, &stdout, &stderr, true, sampleIPIPInventoryIssue(nil))
	var payload linkReadErrorResponse
	if code != 1 || json.Unmarshal(stdout.Bytes(), &payload) != nil || payload.Error == nil ||
		payload.Error.ReasonCode == "ipip_kernel_inventory_unverified" {
		t.Fatalf("cancellation lost priority: %+v", payload)
	}
	link := fixtureReadLink("lnk_88888888888888888888888888888888",
		"10.80.80.0/31", "10.80.80.1/31", domain.BackendIPIP)
	if r := healthDiagnosticFailure(link, sampleIPIPInventoryIssue(context.DeadlineExceeded)); r.ReasonCode != "diagnostic_interrupted" {
		t.Fatalf("multi-Link timeout masked: %+v", r)
	}
}

// Status observes the IPIP adapter directly; active Diagnose first requests
// capability. Cover both that capability-gate failure and the *later*
// DiagnosticState failure, rather than only a fake that fails capability.
type ipipStateOnlyInventoryFailure struct {
	*readIPIPDiagnosticBackend
	failure error
}

func (b *ipipStateOnlyInventoryFailure) DiagnosticState(context.Context, domain.Link) (ipipbackend.DiagnosticState, error) {
	return ipipbackend.DiagnosticState{}, b.failure
}

func TestIPIPInventoryDiagnosticStateFailureAfterCapabilityPass(t *testing.T) {
	root := t.TempDir()
	link := fixtureReadLink("lnk_99999999999999999999999999999999",
		"10.80.90.0/31", "10.80.90.1/31", domain.BackendIPIP)
	storeReadLinks(t, root, link)
	name, _ := ipipbackend.InterfaceName(link.ID)
	adapter := &ipipStateOnlyInventoryFailure{
		readIPIPDiagnosticBackend: &readIPIPDiagnosticBackend{
			capability: linux.CapabilityStatus{Available: true},
			state:      ipipbackend.DiagnosticState{Interface: name, IfIndex: 77, Encapsulation: domain.EncapNative},
		},
		failure: sampleIPIPInventoryIssue(nil),
	}
	probe := &readGREProbeRunner{link: link, name: name, observedIndex: 77}
	for _, args := range [][]string{
		{"link", "status", string(link.ID), "--json"},
		{"link", "diagnose", string(link.ID), "--json"},
		{"link", "diagnose", "--all", "--json"},
	} {
		code, out, errOut := runIPIPRead(root, adapter, probe, args...)
		if code != 1 || errOut != "" || !strings.Contains(out, "ipip_kernel_inventory_unverified") ||
			strings.Contains(out, "VERY_SECRET_NOT_FOR_OUTPUT") || probe.probes != 0 {
			t.Fatalf("valid capability concealed malformed DiagnosticState: args=%v exit=%d out=%s err=%s", args, code, out, errOut)
		}
	}
}

func TestIPIPInventoryCapabilityReasonDrivesDiagnoseAndHealth(t *testing.T) {
	for _, tc := range []struct {
		reason           string
		wantExit         int
		wantHealthStatus string
	}{
		{"ipip_kernel_inventory_unverified", 1, "unknown"},
		{"kernel_module_not_loaded", 4, "blocked"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			root := t.TempDir()
			link := fixtureReadLink("lnk_77777777777777777777777777777777",
				"10.80.77.0/31", "10.80.77.1/31", domain.BackendIPIP)
			storeReadLinks(t, root, link)
			name, _ := ipipbackend.InterfaceName(link.ID)
			adapter := &readIPIPDiagnosticBackend{
				capability: linux.CapabilityStatus{Available: false, ReasonCode: tc.reason, Reason: "UNTRUSTED=PSK_DO_NOT_ECHO"},
				state:      ipipbackend.DiagnosticState{Interface: name, IfIndex: 77, Encapsulation: domain.EncapNative},
			}
			probe := &readGREProbeRunner{link: link, name: name, observedIndex: 77}
			code, out, errOut := runIPIPRead(root, adapter, probe, "link", "diagnose", string(link.ID), "--json")
			var response linkReadErrorResponse
			if code != tc.wantExit || errOut != "" || json.Unmarshal([]byte(out), &response) != nil ||
				response.Error == nil || response.Error.ReasonCode != tc.reason || response.Error.NextStep == "" ||
				strings.Contains(out, "UNTRUSTED") || probe.probes != 0 {
				t.Fatalf("capability guidance mismatch: exit=%d response=%+v raw=%q", code, response, out)
			}
			code, out, errOut = runIPIPRead(root, adapter, probe, "link", "diagnose", "--all", "--json")
			var report healthCenterResponse
			if code != tc.wantExit || errOut != "" || json.Unmarshal([]byte(out), &report) != nil ||
				len(report.Checks) != 1 || report.Checks[0].ReasonCode != tc.reason ||
				report.Checks[0].Status != tc.wantHealthStatus || report.Checks[0].NextStep == "" ||
				strings.Contains(out, "UNTRUSTED") || probe.probes != 0 {
				t.Fatalf("health capability guidance mismatch: exit=%d report=%+v raw=%q", code, report, out)
			}
		})
	}
}
