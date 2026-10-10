package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type ipsecInventoryFixture struct {
	observed ipsec.Snapshot
	err      error
	calls    int
}

func (f *ipsecInventoryFixture) Inspect(_ context.Context, _ ipsec.Profile) (ipsec.Snapshot, error) {
	f.calls++
	return f.observed, f.err
}

type ipsecXFRMFixture struct {
	err   error
	calls int
}

func (f *ipsecXFRMFixture) RequireVacant(_ context.Context, _ ipsec.Profile) error {
	f.calls++
	return f.err
}

func TestIPsecActivationVacancyNeedsExactPendingAndProtectedKey(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "stl")
	e, stored, keys := stageEngineAtRoot(t, root)
	link := stagedIPsecLink("lnk_12121212121212121212121212121212", "10.84.32.0/31")
	vici := &ipsecInventoryFixture{}
	xfrm := &ipsecXFRMFixture{}
	if err := e.CheckIPsecActivationVacancy(ctx, link.ID, keys, vici, xfrm); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("missing pending Link authorized activation readiness: %v", err)
	}
	if vici.calls != 0 || xfrm.calls != 0 {
		t.Fatal("unchecked pending triggered host inspection")
	}
	offer := offerForStage(t, link, bytes.Repeat([]byte{0x5a}, 32))
	handoffs := 0
	if err := e.StageIPsecSender(ctx, offer, keys, func(string) error { handoffs++; return nil }); err != nil {
		t.Fatal(err)
	}
	before := mustState(t, stored)
	if err := e.CheckIPsecActivationVacancy(ctx, link.ID, keys, vici, xfrm); err != nil {
		t.Fatal(err)
	}
	if vici.calls != 1 || xfrm.calls != 1 || handoffs != 1 {
		t.Fatal("readiness did not inspect daemon/kernel exactly once or mutated handoff")
	}
	for _, tc := range []struct {
		name          string
		d             ipsec.Snapshot
		vErr, xErr    error
		wantXFRMCalls int
	}{
		{"foreign-connection", ipsec.Snapshot{ConnectionNamePresent: true}, nil, nil, 0},
		{"foreign-secret", ipsec.Snapshot{SecretNamePresent: true}, nil, nil, 0},
		{"foreign-both", ipsec.Snapshot{ConnectionNamePresent: true, SecretNamePresent: true}, nil, nil, 0},
		{"unknown-daemon", ipsec.Snapshot{}, errors.New("sensitive-daemon-reply"), nil, 0},
		{"unknown-kernel", ipsec.Snapshot{}, nil, errors.New("sensitive-kernel-reply"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &ipsecInventoryFixture{observed: tc.d, err: tc.vErr}
			x := &ipsecXFRMFixture{err: tc.xErr}
			err := e.CheckIPsecActivationVacancy(ctx, link.ID, keys, v, x)
			if err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("unverified ownership accepted or leaked sensitive error: %v", err)
			}
			if v.calls != 1 || x.calls != tc.wantXFRMCalls {
				t.Fatal("vacancy check continued after an unsafe observation")
			}
		})
	}
	if got := mustState(t, stored); !reflect.DeepEqual(before, got) {
		t.Fatal("read-only vacancy probe mutated canonical state")
	}
	if err := os.Remove(filepath.Join(root, "credentials", string(link.ID)+".ipsecpsk")); err != nil {
		t.Fatal(err)
	}
	vici.calls, xfrm.calls = 0, 0
	if err := e.CheckIPsecActivationVacancy(ctx, link.ID, keys, vici, xfrm); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("missing protected key accepted: %v", err)
	}
	if vici.calls != 0 || xfrm.calls != 0 || !reflect.DeepEqual(before, mustState(t, stored)) {
		t.Fatal("missing key allowed host inspection or mutated state")
	}
}

func TestIPsecActivationVacancyRejectsCanonicalResourceConflictsAndMissingInspectors(t *testing.T) {
	ctx := context.Background()
	e, stored, keys := stageEngine(t)
	link := stagedIPsecLink("lnk_13131313131313131313131313131313", "10.84.34.0/31")
	if err := e.StageIPsecSender(ctx, offerForStage(t, link, bytes.Repeat([]byte{0x73}, 32)), keys, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	vici := &ipsecInventoryFixture{}
	xfrm := &ipsecXFRMFixture{}
	for _, tc := range []struct {
		name string
		keys IPsecProtectedKeyReader
		v    IPsecVICIInventory
		x    IPsecXFRMVacancy
	}{
		{"nil-store", nil, vici, xfrm},
		{"nil-daemon", keys, nil, xfrm},
		{"nil-kernel", keys, vici, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := e.CheckIPsecActivationVacancy(ctx, link.ID, tc.keys, tc.v, tc.x); stlerr.CodeOf(err) != stlerr.CodeInvalid {
				t.Fatalf("missing dependency accepted: %v", err)
			}
		})
	}
	second := stagedIPsecLink("lnk_14141414141414141414141414141414", "10.84.34.0/31")
	claims, err := ipsec.NewProfile(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := stored.Update(ctx, func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: second, OwnedResources: claims.ResourceClaims()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	vici.calls, xfrm.calls = 0, 0
	if err := e.CheckIPsecActivationVacancy(ctx, link.ID, keys, vici, xfrm); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("other canonical Link resource reservation ignored: %v", err)
	}
	if vici.calls != 0 || xfrm.calls != 0 {
		t.Fatal("host probed before checking durable resource collision")
	}
	if err := e.CheckIPsecActivationVacancy(ctx, domain.LinkID("lnk_bad"), keys, vici, xfrm); stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("malformed Link ID accepted: %v", err)
	}
}
