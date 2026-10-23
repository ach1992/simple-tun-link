package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func cliSupersessionFixture(t *testing.T) (string, domain.LinkID, domain.LinkID) {
	t.Helper()
	request := testWSSCreateRequest()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	original, _, err := makeWSSPair(request, request.LinkID, key, peer)
	if err != nil {
		t.Fatal(err)
	}
	original.DisplayName = "secret=NEVER_LEAK"
	fresh := original
	fresh.ID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fresh.WireGuard.LocalPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	fresh.WireGuard.PeerPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	fresh.WireGuard.ListenPort = 51825
	fresh.WireGuard.PeerPort = 51826
	fresh.WSS.TCPPort = 59446
	fresh.Addresses.Local = netip.MustParsePrefix("10.94.0.1/30")
	fresh.Addresses.Peer = netip.MustParsePrefix("10.94.0.2/30")
	if err := fresh.Validate(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "state")
	digests := func(ch string) state.WSSFileIdentity {
		d := strings.Repeat(ch, 64)
		return state.WSSFileIdentity{Certificate: d, TLSKey: d,
			TrustCA: d, Authorization: d, Restrictions: d}
	}
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: original, WSSOrigin: strings.Repeat("c", 32),
			WSSFiles: digests("a"), OwnedResources: []domain.ResourceClaim{
				{Kind: domain.ResourceInterface, Key: "originalwss"},
				{Kind: domain.ResourceUDPListenPort, Key: "51821"},
			}})
		s.Upsert(state.LinkRecord{Desired: fresh, WSSOrigin: strings.Repeat("d", 32),
			WSSFiles: digests("b"), OwnedResources: []domain.ResourceClaim{
				{Kind: domain.ResourceInterface, Key: "newwss"},
				{Kind: domain.ResourceUDPListenPort, Key: "51825"},
			}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return root, original.ID, fresh.ID
}

func TestWSSCLIExplicitSupersessionAndReadOnlyObservability(t *testing.T) {
	root, old, next := cliSupersessionFixture(t)
	runCmd := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		exit := runWithRuntime(args, &out, &errOut, &runtimeOptions{stateRoot: root})
		return exit, out.String(), errOut.String()
	}
	code, _, _ := runCmd("link", "supersede-wss", string(old),
		"--replacement", string(next), "--confirm", string(next), "--json")
	if code != 2 {
		t.Fatal("nonmatching confirmation was accepted")
	}
	before, _ := state.NewFileStore(root).Load(context.Background())
	if oldRecord, _ := before.Find(old); oldRecord.WSSSupersededBy != "" {
		t.Fatal("invalid confirmation mutated State")
	}
	args := []string{"link", "supersede-wss", string(old),
		"--replacement", string(next), "--confirm", string(old), "--json"}
	exit, raw, stderr := runCmd(args...)
	var result wssSupersessionResponse
	if err := json.Unmarshal([]byte(raw), &result); err != nil || exit != 0 ||
		stderr != "" || !result.Changed || result.Outcome != "quarantined_old" ||
		result.OldLinkID != old || result.ReplacementLinkID != next ||
		!result.OldRestoreBlocked || result.HostMutated ||
		result.OriginalDeletionProven || result.ReplacementTrafficVerified || result.RebootPerformed ||
		strings.Contains(raw, "NEVER_LEAK") {
		t.Fatalf("unsafe CLI mutation result: %d %+v %v %q", exit, result, err, stderr)
	}
	after, _ := state.NewFileStore(root).Load(context.Background())
	persisted, _ := after.Find(old)
	if persisted.WSSSupersededBy != next ||
		persisted.WSSOrigin != strings.Repeat("c", 32) ||
		persisted.WSSFiles.Authorization != strings.Repeat("a", 64) ||
		len(persisted.OwnedResources) != 2 {
		t.Fatal("CLI supersession did not protect original credentials and reservations")
	}
	if code, raw, _ := runCmd(args...); code != 0 ||
		!strings.Contains(raw, `"changed":false`) {
		t.Fatalf("idempotent operator retry was not stable: %d %q", code, raw)
	}
	code, raw, _ = runCmd("link", "plan-wss-replacement", string(old), "--json")
	var plan WSSReplacementPlan
	if err := json.Unmarshal([]byte(raw), &plan); err != nil || code != 0 ||
		plan.RecoveryState != "superseded_quarantined" ||
		plan.SupersededBy != next || !plan.OldRestoreBlocked ||
		!plan.OldIdentityReserved || plan.OriginalDeletionProven {
		t.Fatalf("plan concealed protected old status: code=%d %+v %v", code, plan, err)
	}
	code, raw, _ = runCmd("link", "list", "--json")
	var list linkListResponse
	if err := json.Unmarshal([]byte(raw), &list); err != nil || code != 0 {
		t.Fatalf("cannot list superseded Link: %d %v", code, err)
	}
	marked := false
	for _, item := range list.Links {
		if item.ID == old {
			marked = item.Disposition == "quarantined_old" && item.SupersededBy == next
		}
	}
	if !marked {
		t.Fatal("configured list deceptively presented superseded old as ordinary active Link")
	}
	for _, cmd := range [][]string{
		{"link", "status", string(old), "--json"},
		{"link", "diagnose-wss", string(old), "--json"},
	} {
		code, raw, _ = runCmd(cmd...)
		var issue linkReadErrorResponse
		if err := json.Unmarshal([]byte(raw), &issue); err != nil || code != 1 ||
			issue.Error == nil || issue.Error.ReasonCode != "wss_original_superseded" {
			t.Fatalf("superseded old falsely reported live: args=%v code=%d %+v err=%v", cmd, code, issue, err)
		}
	}
}
