package state

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func crashJournalStateFixture(t *testing.T) (domain.Link, WSSCrashOperation) {
	t.Helper()
	link := validPendingForLifecycleTest(t).Link
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	op := WSSCrashOperation{
		Intent: link, Operation: "ensure",
		Nonce:            strings.Repeat("a", 32),
		HadCommittedLink: false,
	}
	claims, err := requiredWSSCrashClaims(op)
	if err != nil {
		t.Fatal(err)
	}
	op.Resources = claims
	return link, op
}
func TestWSSCrashJournalStrictDurableStateAndInvalidRecords(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "state")
	store := NewFileStore(root)
	_, op := crashJournalStateFixture(t)
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.WSSCrashOperations = append(s.WSSCrashOperations, op)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := saved.FindWSSCrashOperation(op.Intent.ID)
	if !ok || got.Intent != op.Intent || got.Nonce != op.Nonce || len(got.Resources) < 7 {
		t.Fatal("fsynced WSS pre-effect intent is missing or changed")
	}
	raw, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private_key") ||
		strings.Contains(string(raw), "authorization-token") ||
		strings.Contains(string(raw), "authorization-headers") {
		t.Fatal("WSS crash journal exposes secret material")
	}
	mutations := map[string]func(*WSSCrashOperation){
		"duplicate":           func(o *WSSCrashOperation) { o.Resources = append(o.Resources, o.Resources[0]) },
		"wrong-backend":       func(o *WSSCrashOperation) { o.Intent.Backend = domain.BackendGRE },
		"invalid-nonce":       func(o *WSSCrashOperation) { o.Nonce = "not-a-nonce" },
		"invalid-operation":   func(o *WSSCrashOperation) { o.Operation = "adopt" },
		"unexpected-prior":    func(o *WSSCrashOperation) { o.HadCommittedLink = true },
		"unexpected-original": func(o *WSSCrashOperation) { o.OriginalHostNonce = strings.Repeat("c", 32) },
		"empty-reservation":   func(o *WSSCrashOperation) { o.Resources = nil },
	}
	for label, modify := range mutations {
		t.Run(label, func(t *testing.T) {
			copied := op
			copied.Resources = append([]domain.ResourceClaim(nil), op.Resources...)
			modify(&copied)
			s := EmptySnapshot()
			s.WSSCrashOperations = []WSSCrashOperation{copied}
			if err := validateSnapshot(s); err == nil {
				t.Fatal("unsafe WSS crash journal was accepted")
			}
		})
	}
	s := EmptySnapshot()
	s.WSSCrashOperations = []WSSCrashOperation{op, op}
	if err := validateSnapshot(s); err == nil {
		t.Fatal("duplicate WSS crash transaction accepted")
	}
}
func TestLegacyStateCannotGainWSSJournalThroughWhitespaceOrCasing(t *testing.T) {
	for _, k := range []string{"wss_crash_operations", "WsS_CrAsH_OpErAtIoNs", "wss"} {
		raw := []byte("{\"schema_version\":3,\"links\":[],\"" + k + "\" : []}")
		if err := rejectLegacyWSSFields(raw); err == nil {
			t.Fatalf("legacy state accepted WSS key %q", k)
		}
	}
}
