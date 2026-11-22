//go:build linux

package spoofhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type rpFilterLab struct {
	t       *testing.T
	manager ManagedRPFilter
	store   *state.FileStore
	linkA   domain.Link
	linkB   domain.Link
}

func newRPFilterLab(t *testing.T, all, in0, in1 int) *rpFilterLab {
	t.Helper()
	root := t.TempDir()
	proc := t.TempDir()
	lab := &rpFilterLab{t: t, store: state.NewFileStore(root), manager: ManagedRPFilter{Root: root, ProcRoot: proc}}
	for iface, val := range map[string]int{"all": all, "in0": in0, "in1": in1} {
		lab.set(iface, val)
	}
	lab.linkA = rpFilterTestLink("lnk_1234567890abcdef1234567890abcdef", "10.0.1.1", "10.0.1.2")
	lab.linkB = rpFilterTestLink("lnk_fedcba0987654321fedcba0987654321", "10.0.2.1", "10.0.2.2")
	if err := lab.store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: lab.linkA})
		s.Upsert(state.LinkRecord{Desired: lab.linkB})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return lab
}
func rpFilterTestLink(id domain.LinkID, local, peer string) domain.Link {
	return domain.Link{
		ID: id, Backend: domain.BackendSpoof, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr(local), Peer: netip.MustParseAddr(peer)},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.245.49.1/32"), Peer: netip.MustParsePrefix("10.245.49.2/32")},
		Spoof: domain.SpoofOptions{
			Role: "creator", SourceFile: "/root/stl/spoof/sources.txt", OuterProtocol: "udp",
			ListenPort: 48001, PeerPort: 48002, IngressInterface: "in0",
			LocalPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
			MaterialSHA256: strings.Repeat("a", 64),
		},
	}
}

func (l *rpFilterLab) set(iface string, value int) {
	l.t.Helper()
	path, err := l.manager.sysctlPath(iface)
	if err != nil {
		l.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(string(rune('0'+value))+"\n"), 0600); err != nil {
		l.t.Fatal(err)
	}
}
func (l *rpFilterLab) expect(iface string, want int) {
	l.t.Helper()
	got, err := l.manager.read(iface)
	if err != nil || got != want {
		l.t.Fatalf("%s rp_filter = %d (%v); want %d", iface, got, err, want)
	}
}
func (l *rpFilterLab) snap() state.Snapshot {
	l.t.Helper()
	s, err := l.store.Load(context.Background())
	if err != nil {
		l.t.Fatal(err)
	}
	return s
}

func TestManagedRPFilterPreviewLooseApplyRebootAndOwnerRelease(t *testing.T) {
	lab := newRPFilterLab(t, 1, 1, 1)
	ctx := context.Background()
	plan, err := lab.manager.Preview(ctx, lab.snap(), lab.linkA.ID, "in0", "loose")
	if err != nil || plan.EffectiveBefore != 1 || plan.EffectiveAfter != 2 || plan.GlobalImpact || len(plan.Changes) != 1 {
		t.Fatalf("incorrect no-global-change Loose preview: %+v %v", plan, err)
	}
	lab.expect("in0", 1)
	if len(lab.snap().SpoofRPFilterSettings) != 0 {
		t.Fatal("Preview wrote canonical state")
	}
	applied, err := lab.manager.Apply(ctx, lab.store, lab.linkA.ID, "in0", "loose")
	if err != nil || applied.EffectiveAfter != 2 {
		t.Fatalf("apply loose: %+v %v", applied, err)
	}
	lab.expect("all", 1)
	lab.expect("in0", 2)
	// An independent service restart lost a volatile kernel sysctl value.
	lab.set("in0", 1)
	if err := lab.manager.Reconcile(ctx, lab.store); err != nil {
		t.Fatalf("boot reconciliation: %v", err)
	}
	lab.expect("in0", 2)
	if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err != nil {
		t.Fatalf("release: %v", err)
	}
	lab.expect("in0", 1)
	lab.expect("all", 1)
	if s := lab.snap(); len(s.SpoofRPFilterClaims) != 0 || len(s.SpoofRPFilterSettings) != 0 {
		t.Fatalf("owner was not retired: %+v %+v", s.SpoofRPFilterClaims, s.SpoofRPFilterSettings)
	}
	if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err != nil {
		t.Fatal(err)
	}
}

func TestManagedRPFilterExplicitOffChangesAllAndRestoresBaseline(t *testing.T) {
	for _, tc := range []struct{ all, nic int }{{1, 1}, {2, 0}, {0, 2}} {
		t.Run(string(rune('0'+tc.all))+"-"+string(rune('0'+tc.nic)), func(t *testing.T) {
			lab := newRPFilterLab(t, tc.all, tc.nic, 1)
			ctx := context.Background()
			plan, err := lab.manager.Apply(ctx, lab.store, lab.linkA.ID, "in0", "off")
			if err != nil || plan.EffectiveAfter != 0 {
				t.Fatalf("off apply failed %+v %v", plan, err)
			}
			lab.expect("all", 0)
			lab.expect("in0", 0)
			if tc.all != 0 && !plan.GlobalImpact {
				t.Fatal("global impact not exposed")
			}
			if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err != nil {
				t.Fatal(err)
			}
			lab.expect("all", tc.all)
			lab.expect("in0", tc.nic)
		})
	}
}

func TestManagedRPFilterConcurrentOwnersAndTransitionOffToLoose(t *testing.T) {
	lab := newRPFilterLab(t, 1, 1, 1)
	ctx := context.Background()
	if _, err := lab.manager.Apply(ctx, lab.store, lab.linkA.ID, "in0", "loose"); err != nil {
		t.Fatal(err)
	}
	if _, err := lab.manager.Apply(ctx, lab.store, lab.linkB.ID, "in0", "off"); err != nil {
		t.Fatal(err)
	}
	lab.expect("all", 0)
	lab.expect("in0", 0)
	if err := lab.manager.Release(ctx, lab.store, lab.linkB.ID); err != nil {
		t.Fatal(err)
	}
	lab.expect("all", 1)
	lab.expect("in0", 2)
	if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err != nil {
		t.Fatal(err)
	}
	lab.expect("all", 1)
	lab.expect("in0", 1)
	if _, err := lab.manager.Apply(ctx, lab.store, lab.linkA.ID, "in0", "off"); err != nil {
		t.Fatal(err)
	}
	if _, err := lab.manager.Apply(ctx, lab.store, lab.linkB.ID, "in1", "loose"); err != nil {
		t.Fatal(err)
	}
	lab.expect("all", 0)
	lab.expect("in0", 0)
	lab.expect("in1", 2)
	if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err != nil {
		t.Fatal(err)
	}
	lab.expect("all", 1)
	lab.expect("in0", 1)
	lab.expect("in1", 2)
	if err := lab.manager.Release(ctx, lab.store, lab.linkB.ID); err != nil {
		t.Fatal(err)
	}
	lab.expect("all", 1)
	lab.expect("in1", 1)
}

func TestManagedRPFilterInterruptedChangeForeignDivergenceAndPostRemove(t *testing.T) {
	lab := newRPFilterLab(t, 1, 1, 1)
	ctx := context.Background()
	err := lab.store.Update(ctx, func(s *state.Snapshot) error {
		s.SpoofRPFilterClaims = []state.SpoofRPFilterClaim{{LinkID: lab.linkA.ID, Interface: "in0", Mode: "off"}}
		s.SpoofRPFilterSettings = []state.SpoofRPFilterSetting{{Interface: "all", Original: 1, Previous: 1, Desired: 0}, {Interface: "in0", Original: 1, Previous: 1, Desired: 0}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	lab.expect("all", 1)
	lab.expect("in0", 1)
	if err := lab.manager.Reconcile(ctx, lab.store); err != nil {
		t.Fatalf("replay crash after journal: %v", err)
	}
	lab.expect("all", 0)
	lab.expect("in0", 0)
	lab.set("in0", 2) // foreign operator changed it outside managed original/desired states
	if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err == nil || !strings.Contains(err.Error(), "diverged") {
		t.Fatalf("foreign concurrent edit was silently overwritten: %v", err)
	}
	lab.expect("in0", 2)
	if len(lab.snap().SpoofRPFilterSettings) == 0 {
		t.Fatal("lost retryable restoration journal")
	}
	lab.set("in0", 0)
	if err := lab.manager.Reconcile(ctx, lab.store); err != nil {
		t.Fatal(err)
	}
	lab.expect("in0", 1)
	lab.expect("all", 1)
	if err := lab.store.Update(ctx, func(s *state.Snapshot) error {
		s.SpoofRPFilterClaims = []state.SpoofRPFilterClaim{{LinkID: lab.linkB.ID, Interface: "in0", Mode: "loose"}}
		s.SpoofRPFilterSettings = []state.SpoofRPFilterSetting{{Interface: "in0", Original: 1, Previous: 1, Desired: 2}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate atomic Engine Remove having committed its original receipt.
	if err := lab.store.Update(ctx, func(s *state.Snapshot) error {
		s.Delete(lab.linkB.ID)
		s.SpoofRemovalReceipts = append(s.SpoofRemovalReceipts, state.SpoofRemovalReceipt{Link: lab.linkB})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := lab.manager.Reconcile(ctx, lab.store); err != nil {
		t.Fatal(err)
	}
	lab.expect("in0", 1)
	if s := lab.snap(); len(s.SpoofRPFilterSettings) != 0 || len(s.SpoofRPFilterClaims) != 0 {
		t.Fatal("removed Link policy was not restored")
	}
}

func TestManagedRPFilterNoUnconsentedChangeAndNoEmptyStateCreation(t *testing.T) {
	root := t.TempDir()
	proc := t.TempDir()
	manager := ManagedRPFilter{Root: root, ProcRoot: proc}
	store := state.NewFileStore(root)
	if err := manager.Reconcile(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("read-only empty restore wrote state: %v", err)
	}
	lab := newRPFilterLab(t, 1, 1, 1)
	if _, err := lab.manager.Apply(context.Background(), lab.store, lab.linkA.ID, "../all", "off"); err == nil {
		t.Fatal("unsafe interface accepted")
	}
	if _, err := lab.manager.Apply(context.Background(), lab.store, "lnk_00000000000000000000000000000000", "in0", "off"); err == nil {
		t.Fatal("foreign Link owner accepted")
	}
	lab.expect("all", 1)
	lab.expect("in0", 1)
}

func TestManagedRPFilterWriteOrderingAvoidsUnnecessaryTransientStrict(t *testing.T) {
	cases := []struct {
		currentAll, targetAll int
		wantGlobalLast        bool
	}{
		{2, 0, true}, {1, 0, false}, {0, 2, false}, {1, 1, false},
	}
	for _, tc := range cases {
		settings := []state.SpoofRPFilterSetting{
			{Interface: "all", Original: tc.currentAll, Previous: tc.currentAll, Desired: tc.targetAll},
			{Interface: "in0", Original: 1, Previous: 1, Desired: 0},
		}
		got := orderRPFilterWrites(settings)
		if (got[len(got)-1].Interface == "all") != tc.wantGlobalLast {
			t.Fatalf("wrong all write ordering for %+v: %+v", tc, got)
		}
	}
}

func TestManagedRPFilterLooseUsesGlobalTwoWithoutUnnecessaryNICChange(t *testing.T) {
	for _, nic := range []int{0, 1, 2} {
		t.Run(string(rune('0'+nic)), func(t *testing.T) {
			lab := newRPFilterLab(t, 2, nic, 0)
			ctx := context.Background()
			plan, err := lab.manager.Preview(ctx, lab.snap(), lab.linkA.ID, "in0", "loose")
			if err != nil || plan.EffectiveBefore != 2 || plan.EffectiveAfter != 2 || len(plan.Changes) != 0 {
				t.Fatalf("already-compatible effective Loose changed unexpectedly: %+v %v", plan, err)
			}
			applied, err := lab.manager.Apply(ctx, lab.store, lab.linkA.ID, "in0", "loose")
			if err != nil || len(applied.Changes) != 0 {
				t.Fatalf("approved baseline-only claim changed NIC: %+v %v", applied, err)
			}
			lab.expect("all", 2)
			lab.expect("in0", nic)
			snapshot := lab.snap()
			if len(snapshot.SpoofRPFilterSettings) != 2 {
				t.Fatalf("global baseline not journaled for Loose: %+v", snapshot.SpoofRPFilterSettings)
			}
			// Simulated unrelated sysctl reset changes the effective Loose
			// policy. Never silently adopt or clobber this foreign setting;
			// report an explicit owner conflict and retain the journal.
			lab.set("all", 1)
			if err := lab.manager.Reconcile(ctx, lab.store); err == nil || !strings.Contains(err.Error(), "outside STL") {
				t.Fatalf("external policy drift not reported: %v", err)
			}
			lab.expect("all", 1)
			lab.expect("in0", nic)
			if len(lab.snap().SpoofRPFilterClaims) != 1 {
				t.Fatal("lost owner after conflict")
			}
			lab.set("all", 2)
			if err := lab.manager.Reconcile(ctx, lab.store); err != nil {
				t.Fatalf("original policy restored but journal unrecoverable: %v", err)
			}
			if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err != nil {
				t.Fatal(err)
			}
			lab.expect("all", 2)
			lab.expect("in0", nic)
			if len(lab.snap().SpoofRPFilterSettings) != 0 {
				t.Fatal("original global baseline not released")
			}
		})
	}
}

func TestManagedRPFilterGlobalTwoMixedOwnersReleaseOrders(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		lab := newRPFilterLab(t, 2, 1, 0)
		ctx := context.Background()
		if _, err := lab.manager.Apply(ctx, lab.store, lab.linkA.ID, "in0", "loose"); err != nil {
			t.Fatal(err)
		}
		if _, err := lab.manager.Apply(ctx, lab.store, lab.linkB.ID, "in1", "off"); err != nil {
			t.Fatal(err)
		}
		lab.expect("all", 0)
		lab.expect("in0", 2)
		lab.expect("in1", 0)
		if reverse {
			if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err != nil {
				t.Fatal(err)
			}
			lab.expect("all", 0)
			lab.expect("in0", 1)
			if err := lab.manager.Release(ctx, lab.store, lab.linkB.ID); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := lab.manager.Release(ctx, lab.store, lab.linkB.ID); err != nil {
				t.Fatal(err)
			}
			lab.expect("all", 2)
			lab.expect("in0", 1)
			if err := lab.manager.Release(ctx, lab.store, lab.linkA.ID); err != nil {
				t.Fatal(err)
			}
		}
		lab.expect("all", 2)
		lab.expect("in0", 1)
		lab.expect("in1", 0)
		if s := lab.snap(); len(s.SpoofRPFilterClaims) != 0 || len(s.SpoofRPFilterSettings) != 0 {
			t.Fatal("mixed owners left orphan journal")
		}
	}
}
