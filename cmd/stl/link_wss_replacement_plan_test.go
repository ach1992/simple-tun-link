package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestWSSReplacementPlanReadOnlyAndNeverAssumesOriginalDead(t *testing.T) {
	req := testWSSCreateRequest()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	link, _, err := makeWSSPair(req, req.LinkID, key, peer)
	if err != nil {
		t.Fatal(err)
	}
	link.DisplayName = "private_key=DO_NOT_PRINT"
	sha := strings.Repeat("a", 64)
	record := state.LinkRecord{Desired: link, WSSOrigin: strings.Repeat("b", 32),
		WSSFiles: state.WSSFileIdentity{Certificate: sha, TLSKey: sha, TrustCA: sha, Authorization: sha, Restrictions: sha}}
	root := filepath.Join(t.TempDir(), "state")
	store := state.NewFileStore(root)
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	status := runWithRuntime([]string{"link", "plan-wss-replacement", string(link.ID), "--json"},
		&out, &stderr, &runtimeOptions{stateRoot: root})
	var plan WSSReplacementPlan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil || status != 0 || stderr.Len() != 0 ||
		plan.RecoveryState != "committed_health_unverified" || !plan.Committed ||
		plan.CrashJournalRetained || !plan.OldResourcesReserved ||
		plan.HostMutated || plan.RebootPerformed || plan.OriginalDeletionProven ||
		!strings.Contains(strings.Join(plan.Steps, " "), "diagnose-wss") {
		t.Fatalf("unsafe plan status=%d err=%v plan=%+v stderr=%q", status, err, plan, stderr.String())
	}
	if strings.Contains(out.String(), "DO_NOT_PRINT") ||
		strings.Contains(out.String(), record.WSSOrigin) ||
		strings.Contains(out.String(), link.WireGuard.LocalPublicKey) {
		t.Fatal("read-only recovery plan leaked stored identity")
	}
	after, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("plan mutated protected State", err)
	}
}

func TestWSSReplacementPlanHandlesCrashWithoutPromotingDeletion(t *testing.T) {
	req := testWSSCreateRequest()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	link, _, err := makeWSSPair(req, req.LinkID, key, peer)
	if err != nil {
		t.Fatal(err)
	}
	s := state.EmptySnapshot()
	s.WSSCrashOperations = append(s.WSSCrashOperations, state.WSSCrashOperation{Intent: link, Operation: "ensure"})
	plan, ok := planWSSReplacement(s, link.ID)
	if !ok || plan.RecoveryState != "crash_journal_quarantined" || !plan.CrashJournalRetained ||
		!plan.OldResourcesReserved || plan.Committed || plan.OriginalDeletionProven {
		t.Fatalf("uncommitted crash falsely treated as vacant: %+v", plan)
	}
	if _, ok := planWSSReplacement(s, domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); ok {
		t.Fatal("unknown original accepted")
	}
}

func TestWSSReplacementPlanReportsPersistedCrashAndDiagnosisAction(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "committed"}[committed], func(t *testing.T) {
			req := testWSSCreateRequest()
			key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
			link, _, err := makeWSSPair(req, req.LinkID, key, peer)
			if err != nil {
				t.Fatal(err)
			}
			link.DisplayName = "private_key=DO_NOT_PRINT"
			path, err := composition.Build(link, composition.CarrierForLink(link))
			if err != nil {
				t.Fatal(err)
			}
			resources := []domain.ResourceClaim{
				{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(link.WireGuard.ListenPort))},
				{Kind: domain.ResourceFirewall, Key: "wss/nft/" + string(link.ID)},
			}
			resources = append(resources, path.CarrierClaims()...)
			resources = append(resources,
				domain.ResourceClaim{Kind: domain.ResourceInterface, Key: "stlwg" + string(link.ID)[4:14]},
				domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
				domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
				domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "wireguard/local-public/" + link.WireGuard.LocalPublicKey},
			)
			root := filepath.Join(t.TempDir(), "state")
			if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
				original := ""
				if committed {
					digest := strings.Repeat("a", 64)
					original = strings.Repeat("b", 32)
					s.Upsert(state.LinkRecord{Desired: link, WSSOrigin: original,
						WSSFiles: state.WSSFileIdentity{
							Certificate: digest, TLSKey: digest, TrustCA: digest,
							Authorization: digest, Restrictions: digest,
						}})
				}
				s.WSSCrashOperations = append(s.WSSCrashOperations, state.WSSCrashOperation{
					Intent: link, Operation: "ensure", Nonce: strings.Repeat("c", 32),
					Resources: resources, HadCommittedLink: committed, OriginalHostNonce: original,
				})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := runWithRuntime([]string{"link", "plan-wss-replacement", string(link.ID), "--json"},
				&out, &errOut, &runtimeOptions{stateRoot: root})
			var plan WSSReplacementPlan
			if err := json.Unmarshal(out.Bytes(), &plan); err != nil || code != 0 || errOut.Len() != 0 ||
				plan.RecoveryState != "crash_journal_quarantined" || !plan.CrashJournalRetained ||
				!plan.OldResourcesReserved || !plan.OldIdentityReserved || plan.Committed != committed ||
				plan.OriginalDeletionProven || plan.RebootPerformed || plan.HostMutated {
				t.Fatalf("stored WSS crash misdiagnosed: code=%d plan=%+v err=%v stderr=%q",
					code, plan, err, errOut.String())
			}
			out.Reset()
			errOut.Reset()
			code = runWithRuntime([]string{"link", "diagnose-wss", string(link.ID), "--json"},
				&out, &errOut, &runtimeOptions{stateRoot: root})
			var fail linkReadErrorResponse
			if err := json.Unmarshal(out.Bytes(), &fail); err != nil || code != 1 || errOut.Len() != 0 ||
				fail.Error == nil || fail.Error.ReasonCode != "wss_crash_quarantined" ||
				!strings.Contains(fail.Error.NextStep, "plan-wss-replacement") {
				t.Fatalf("unsafe or unactionable live diagnostic on unresolved original: %d %+v %v %q",
					code, fail, err, errOut.String())
			}
			after, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("diagnostics altered original Crash Journal or credentials: %v", err)
			}
		})
	}
}

// A typed Engine reason is distinct from a raw kernel/credential error.
// Host-Apply ambiguity or a foreign backend cannot claim safe recovery.
func TestWSSLifecycleFailureGuidanceIsIdentityAndStageBound(t *testing.T) {
	const id = "lnk_1234567890abcdef1234567890abcdef"
	for _, reason := range []string{"wss_crash_quarantined", "wss_original_unverified", "wss_original_superseded"} {
		for _, tc := range []struct {
			name, backend, mutation string
			wantSpecific            bool
		}{
			{"wss_before_apply", "wireguard-wss", "not_attempted", true},
			{"wss_after_apply", "wireguard-wss", "attempted", false},
			{"other_backend", "gre", "not_attempted", false},
		} {
			t.Run(reason+"/"+tc.name, func(t *testing.T) {
				source := stlerr.New(stlerr.CodeConflict, "ensure", id, tc.backend,
					"private_key=DO_NOT_EXPOSE_UNTRUSTED_ERROR")
				source.ReasonCode = reason
				ev := &stlerr.OperationEvidence{
					Stage: "preflight", HostMutation: tc.mutation,
					DesiredState: "no_commit_attempted", Rollback: "not_required",
				}
				var out, errOut bytes.Buffer
				rc := lifecycleFailureWithEvidence(&out, &errOut, true,
					stlerr.CodeConflict, "link_ensure", nil,
					"Link operation not completed; inspect saved State", ev, source)
				var result lifecycleFailureResponse
				if err := json.Unmarshal(out.Bytes(), &result); err != nil || rc != 1 ||
					errOut.Len() != 0 || result.Error == nil ||
					strings.Contains(out.String(), "DO_NOT_EXPOSE") {
					t.Fatalf("typed recovery error leaked or failed: %d %v %+v", rc, err, result)
				}
				if tc.wantSpecific {
					if result.Error.ReasonCode != reason ||
						!strings.Contains(result.Error.NextStep, "plan-wss-replacement "+id) {
						t.Fatalf("specific safe WSS repair next step was lost: %+v", result.Error)
					}
				} else if result.Error.ReasonCode == reason {
					t.Fatalf("uncertain host effects or foreign backend were falsely promoted: %+v", result.Error)
				}
			})
		}
	}
}
