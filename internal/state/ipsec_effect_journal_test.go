package state

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestIPsecXFRMCrashJournalRetainsOriginalIfindexAcrossNewStore(t *testing.T) {
	for _, tt := range []struct {
		name, phase string
		index       int
	}{
		{"before-kernel", IPsecXFRMPrepared, 0},
		{"indeterminate-create", IPsecXFRMIssuingCreate, 0},
		{"before-alias", IPsecXFRMIndexed, 104},
		{"before-address", IPsecXFRMAliased, 104},
		{"complete-before-state-commit", IPsecXFRMConfigured, 104},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "protected")
			ctx := context.Background()
			store := NewFileStore(root)
			pending := pendingIPsecFixture()
			err := store.Update(ctx, func(s *Snapshot) error {
				s.PendingIPsec = []PendingIPsec{pending}
				s.IPsecVICIOperations = []IPsecVICIOperation{{Intent: pending, Nonce: strings.Repeat("1", 32), Phase: IPsecVICIPrepared}}
				s.IPsecXFRMOperations = []IPsecXFRMOperation{{Intent: pending.Link, Nonce: strings.Repeat("2", 32), Phase: tt.phase, IfIndex: tt.index}}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// New FileStore models process restart: no Go in-memory field survives.
			observed, err := NewFileStore(root).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			recovered, found := observed.FindIPsecXFRMOperation(pending.Link.ID)
			if !found || recovered.IfIndex != tt.index || recovered.Phase != tt.phase {
				t.Fatalf("lost original ifindex or phase: %+v", recovered)
			}
			// Name-only / if_id-only identity never gains a manufactured index.
			if tt.index == 0 && recovered.IfIndex != 0 {
				t.Fatal("anonymous kernel state gained deletion authority")
			}
		})
	}
}

func TestIPsecXFRMJournalRejectsAmbiguousAndOverlappingOwners(t *testing.T) {
	pending := pendingIPsecFixture()
	makeSnapshot := func() Snapshot {
		s := EmptySnapshot()
		s.PendingIPsec = []PendingIPsec{pending}
		s.IPsecVICIOperations = []IPsecVICIOperation{{Intent: pending, Nonce: strings.Repeat("1", 32), Phase: IPsecVICIPrepared}}
		s.IPsecXFRMOperations = []IPsecXFRMOperation{{Intent: pending.Link, Nonce: strings.Repeat("2", 32), Phase: IPsecXFRMIndexed, IfIndex: 101}}
		return s
	}
	if err := validateSnapshot(makeSnapshot()); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*Snapshot){
		"unknown-ifindex":           func(s *Snapshot) { s.IPsecXFRMOperations[0].IfIndex = 0 },
		"fabricated-prepared-index": func(s *Snapshot) { s.IPsecXFRMOperations[0].Phase = IPsecXFRMPrepared },
		"duplicate":                 func(s *Snapshot) { s.IPsecXFRMOperations = append(s.IPsecXFRMOperations, s.IPsecXFRMOperations[0]) },
		"orphan":                    func(s *Snapshot) { s.PendingIPsec = nil; s.IPsecVICIOperations = nil },
		"wrong-staged-intent":       func(s *Snapshot) { s.IPsecXFRMOperations[0].Intent.ID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		"wrong-daemon-intent":       func(s *Snapshot) { s.IPsecVICIOperations = nil },
		"bad-nonce":                 func(s *Snapshot) { s.IPsecXFRMOperations[0].Nonce = strings.Repeat("0", 32) },
		"invalid-phase":             func(s *Snapshot) { s.IPsecXFRMOperations[0].Phase = "unsafe-adopt" },
	} {
		t.Run(name, func(t *testing.T) {
			s := makeSnapshot()
			alter(&s)
			if err := validateSnapshot(s); err == nil {
				t.Fatal("ambiguous XFRM state accepted")
			}
		})
	}
	if IPsecXFRMNextPhase(IPsecXFRMIssuingCreate, IPsecXFRMAliased) {
		t.Fatal("XFRM original ifindex persistence was skipped")
	}
}

func TestIPsecRemoveCrashJournalRestartAndScope(t *testing.T) {
	ctx := context.Background()
	entry := pendingIPsecFixture()
	record := LinkRecord{Desired: entry.Link, OwnedResources: []domain.ResourceClaim{{Kind: "interface", Key: "stl-owned-test"}}}
	phases := IPsecRemovePhases
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "private")
			store := NewFileStore(root)
			if err := store.Update(ctx, func(s *Snapshot) error {
				s.Upsert(record)
				s.IPsecRemoveOperations = []IPsecRemoveOperation{{Intent: entry.Link, Nonce: strings.Repeat("3", 32), Phase: phase, IfIndex: 99}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			snap, err := NewFileStore(root).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			journal, ok := snap.FindIPsecRemoveOperation(entry.Link.ID)
			if !ok || journal.Phase != phase || journal.IfIndex != 99 || len(snap.Links) != 1 {
				t.Fatal("committed Link owner receipt lost across process restart")
			}
		})
	}
	makeSnapshot := func() Snapshot {
		s := EmptySnapshot()
		s.Upsert(record)
		s.IPsecRemoveOperations = []IPsecRemoveOperation{{Intent: entry.Link, Nonce: strings.Repeat("3", 32), Phase: IPsecRemoveIssuingShared, IfIndex: 99}}
		return s
	}
	for name, change := range map[string]func(*Snapshot){
		"orphan": func(s *Snapshot) { s.Links = nil },
		"duplicate": func(s *Snapshot) {
			s.IPsecRemoveOperations = append(s.IPsecRemoveOperations, s.IPsecRemoveOperations[0])
		},
		"foreign-intent": func(s *Snapshot) { s.IPsecRemoveOperations[0].Intent.ID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		"negative-index": func(s *Snapshot) { s.IPsecRemoveOperations[0].IfIndex = -1 },
		"unknown-phase":  func(s *Snapshot) { s.IPsecRemoveOperations[0].Phase = "unsafe-replace" },
		"overlap-reapply": func(s *Snapshot) {
			s.IPsecReapplyOperations = []IPsecReapplyOperation{{Intent: entry.Link, Nonce: strings.Repeat("4", 32), Phase: IPsecVICIPrepared}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := makeSnapshot()
			change(&s)
			if err := validateSnapshot(s); err == nil {
				t.Fatal("unsafe IPsec Remove journal admitted")
			}
		})
	}
	if IPsecRemoveNextPhase(IPsecRemoveIssuingConnection, IPsecRemoveIssuingDevice) {
		t.Fatal("IPsec Remove skip of credential unload was accepted")
	}
}
