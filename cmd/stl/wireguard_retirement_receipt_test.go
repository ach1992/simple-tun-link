package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestRetireRefusesOrphanKeyEvenWithOtherCommittedLinkState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store := state.NewFileStore(root)
	other, _ := makeLifecycleDesired(t, "c", "10.70.70.0/31")
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: other})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	id := domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	own, pub, err := wireguard.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.PutNew(id, own); err != nil {
		t.Fatal(err)
	}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{&wireGuardCreatorFake{newLifecycleFake()}}, probeRunner: &retirementProbeFake{}}
	args := []string{"link", "credential", "retire", string(id), "--confirm", string(id), "--public-key", pub, "--json"}
	code, out, stderr := creatorRun(args, "", opts)
	if code == 0 || stderr != "" || strings.Contains(out, own.SecretWireValue()) {
		t.Fatalf("unrelated state authorized orphan retirement: %d %q %q", code, out, stderr)
	}
	if _, err = keys.Load(id); err != nil {
		t.Fatal("orphan key destroyed by unrelated committed state", err)
	}
	snap, err := store.Load(context.Background())
	if err != nil || len(snap.Links) != 1 || len(snap.RemovalReceipts) != 0 {
		t.Fatal("rejected orphan retirement changed desired state or invented receipt")
	}
}

func TestRetirementReceiptRequiresSuccessfulRemoveAndIsConsumedIdempotently(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	opts.probeRunner = &retirementProbeFake{}
	link, _ := makeLifecycleDesired(t, "e", "10.70.71.0/31")
	handoff := filepath.Join(parent, "retirement.stl")
	code, _, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", handoff, "--json"}, creatorRequest(t, link), opts)
	if code != 0 || stderr != "" {
		t.Fatal("fixture create failed")
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keys.LocalPublicIdentity(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	before, err := store.Load(context.Background())
	if err != nil || len(before.Links) != 1 || len(before.RemovalReceipts) != 0 {
		t.Fatal("receipt existed before Remove")
	}
	desired := before.Links[0].Desired
	fake.failApply = true
	code, _, stderr = creatorRun([]string{"link", "remove", string(link.ID), "--confirm", string(link.ID), "--json"}, "", opts)
	if code == 0 || stderr != "" {
		t.Fatal("failed canonical Remove reported success")
	}
	failed, err := store.Load(context.Background())
	if err != nil || len(failed.Links) != 1 || len(failed.RemovalReceipts) != 0 {
		t.Fatal("failed Remove invented retirement receipt")
	}
	fake.failApply = false
	code, _, stderr = creatorRun([]string{"link", "remove", string(link.ID), "--confirm", string(link.ID), "--json"}, "", opts)
	if code != 0 || stderr != "" {
		t.Fatal("canonical Remove fixture failed")
	}
	removed, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	proof, ok := removed.FindRemovalReceipt(link.ID)
	if !ok || len(removed.Links) != 0 || proof.Retired || proof.Backend != domain.BackendWireGuard || proof.LocalPublicKey != pub {
		t.Fatal("successful durable Remove failed to record exact recipient/sender key identity")
	}
	args := []string{"link", "credential", "retire", string(link.ID), "--confirm", string(link.ID), "--public-key", pub, "--json"}
	code, _, stderr = creatorRun(args, "", opts)
	if code != 0 || stderr != "" {
		t.Fatal("exact canonical retirement failed")
	}
	retired, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	proof, ok = retired.FindRemovalReceipt(link.ID)
	if !ok || !proof.Retired || proof.LocalPublicKey != pub {
		t.Fatal("retirement did not persist exact per-Link retired receipt")
	}
	if _, err = keys.Load(link.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired key remains")
	}
	code, _, stderr = creatorRun(args, "", opts)
	if code != 0 || stderr != "" {
		t.Fatal("retired receipt did not support safe idempotent retry")
	}
	// Attempting new deployment with an already-removed ID is permitted only
	// after invalidating its historical retirement proof BEFORE Apply.
	fake.failApply = true
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.EnsureImported(context.Background(), desired)
	if err == nil {
		t.Fatal("injected failed re-ensure unexpectedly succeeded")
	}
	replay, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := replay.FindRemovalReceipt(link.ID); exists {
		t.Fatal("stale removal proof survived new attempted Ensure")
	}
	if _, exists := replay.Find(link.ID); exists {
		t.Fatal("failed Ensure committed Link")
	}
}

func TestFailedReEnsureCannotUseOldReceiptToRetireStillNeededKey(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	opts.probeRunner = &retirementProbeFake{}
	link, _ := makeLifecycleDesired(t, "f", "10.70.72.0/31")
	file := filepath.Join(parent, "retry.stl")
	code, _, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", file, "--json"}, creatorRequest(t, link), opts)
	if code != 0 || stderr != "" {
		t.Fatal("fixture Create failed")
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keys.LocalPublicIdentity(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	snap, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	desired := snap.Links[0].Desired
	code, _, stderr = creatorRun([]string{"link", "remove", string(link.ID), "--confirm", string(link.ID), "--json"}, "", opts)
	if code != 0 || stderr != "" {
		t.Fatal("fixture Remove failed")
	}
	fake.failApply = true
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.EnsureImported(context.Background(), desired); err == nil {
		t.Fatal("expected reensure failure")
	}
	after, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := after.FindRemovalReceipt(link.ID); exists {
		t.Fatal("old historical proof survived retry")
	}
	args := []string{"link", "credential", "retire", string(link.ID), "--confirm", string(link.ID), "--public-key", pub, "--json"}
	code, _, stderr = creatorRun(args, "", opts)
	if code == 0 || stderr != "" {
		t.Fatal("obsolete removal receipt authorized failed-retry key deletion")
	}
	if _, err = keys.Load(link.ID); err != nil {
		t.Fatal("protected retry key incorrectly retired")
	}
}
