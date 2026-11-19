package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	masquebackend "github.com/ach1992/simple-tun-link/internal/backend/masque"
	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/masquehost"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestMASQUECreateRefusesUnassignedPhysicalSourceBeforeIssuingSecrets(t *testing.T) {
	request := masqueInputTestRequest()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	target := filepath.Join(root, "receiver.json")
	var out, errOut bytes.Buffer
	rc := linkMASQUECommand([]string{"create-masque", "--stdin", "--output", target}, bytes.NewReader(raw), &out, &errOut, &runtimeOptions{stateRoot: root})
	if rc == 0 {
		t.Fatal("created receiver secrets for a source that is not assigned to this host")
	}
	for _, forbidden := range []string{target, filepath.Join(root, "masque")} {
		if _, err := os.Lstat(forbidden); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected artifact %s: %v", forbidden, err)
		}
	}
}

func TestMASQUEGuidedIPv6UnderlayAndPrivateAddressValidationWithoutHostEffects(t *testing.T) {
	var out bytes.Buffer
	input := strings.NewReader("not-an-ip\n2a10:ed40:9:e::1\n")
	got, err := askMASQUEUnderlay(createPrompts{reader: bufio.NewReader(input), out: &out}, false, netip.Addr{})
	if err != nil || got.String() != "2a10:ed40:9:e::1" || !strings.Contains(out.String(), "physical unicast") {
		t.Fatalf("ipv6 endpoint parsing: %v %s", err, out.String())
	}
	input = strings.NewReader("2a01:4f8::1\n10.252.98.2\n10.252.98.2\n10.252.98.2\n10.252.98.1\n")
	reader := bufio.NewReader(input)
	p := createPrompts{reader: reader, out: &out}
	peer, err := askMASQUEUnderlay(p, false, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	private, err := askMASQUEPrivatePair(p, state.Snapshot{})
	if err != nil || private.Local.String() != "10.252.98.2/32" || private.Peer.String() != "10.252.98.1/32" || peer.String() != "2a01:4f8::1" {
		t.Fatalf("private /32 pair: %v %+v", err, private)
	}
	if !strings.Contains(out.String(), "two distinct private IPv4") {
		t.Fatal("missing invalid private pair guidance")
	}
	var cancelOut, cancelErr bytes.Buffer
	cancelInput := strings.NewReader("q\n")
	root := t.TempDir()
	code := menuCreateMASQUE(cancelInput, bufio.NewReader(cancelInput), &cancelOut, &cancelErr, &runtimeOptions{stateRoot: root})
	if code != 0 {
		t.Fatalf("cancel failed with code %d", code)
	}
	if _, err := os.Stat(filepath.Join(root, "masque")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("menu cancel created protected materials")
	}
}

func TestMASQUEImportMenuRejectsUnassignedReceiverBeforeStaging(t *testing.T) {
	req := masqueInputTestRequest()
	sender, receiver, err := req.makePair(req.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := masque.GeneratePair(sender.ID, sender.MASQUE.TLSServerName, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Clear()
	root := t.TempDir()
	sender, own, err := masquehost.BuildMaterial(root, sender, pair)
	if err != nil {
		t.Fatal(err)
	}
	defer masquehost.ClearFiles(own)
	receiver, files, err := masquehost.BuildMaterial(root, receiver, pair)
	if err != nil {
		t.Fatal(err)
	}
	offer := masqueOfferV1{SchemaVersion: 1, Sender: sender, Receiver: receiver, ReceiverMaterial: files}
	defer offer.Clear()
	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.NewReader(string(encoded) + "\nYES\n")
	var out, errOut bytes.Buffer
	code := menuImportMASQUE(input, bufio.NewReader(input), &out, &errOut, &runtimeOptions{stateRoot: root})
	if code == 0 {
		t.Fatalf("unassigned receiver was imported: %s", out.String())
	}
	if strings.Contains(out.String(), "-----BEGIN PRIVATE KEY-----") || strings.Contains(out.String(), string(files["server-key.pem"])) {
		t.Fatal("private credential leaked by menu")
	}
	if !strings.Contains(out.String(), "not uniquely own") {
		t.Fatalf("receiver rejection was not actionable: %s", out.String())
	}
	if _, err := os.Lstat(filepath.Join(root, "masque")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused offer left protected material on disk")
	}
	// The interactive path alternative consumes the same original
	// protected file without copying it to a terminal or mutating State.
	// Use a dedicated private parent; the testing.T temporary hierarchy
	// may not attest every intermediate directory as trusted.
	privateParent, err := os.MkdirTemp("", "stl-masque-offer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(privateParent)
	offerPath := filepath.Join(privateParent, "receiver-offer.json")
	if err := os.WriteFile(offerPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, directErr := readPrivateHandoffFile(offerPath); directErr != nil {
		t.Fatalf("test private-file fixture violates owner checks: %v", directErr)
	}
	out.Reset()
	errOut.Reset()
	fileInput := strings.NewReader(offerPath + "\nYES\n")
	code = menuImportMASQUE(fileInput, bufio.NewReader(fileInput), &out, &errOut, &runtimeOptions{stateRoot: root})
	if code == 0 || !strings.Contains(out.String(), "not uniquely own") {
		t.Fatalf("protected-file import should reach local source admission: code=%d output=%s", code, out.String())
	}
	if strings.Contains(out.String(), string(files["server-key.pem"])) {
		t.Fatal("protected-file import disclosed key")
	}
	if _, err := os.Stat(filepath.Join(root, "masque")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("protected-file receiver rejection staged material")
	}
	if err := os.Chmod(offerPath, 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	fileInput = strings.NewReader(offerPath + "\n")
	code = menuImportMASQUE(fileInput, bufio.NewReader(fileInput), &out, &errOut, &runtimeOptions{stateRoot: root})
	if code == 0 || !strings.Contains(out.String(), "Cannot safely read that offer file") {
		t.Fatalf("unsafe protected file not rejected: code=%d output=%s", code, out.String())
	}
}

type masqueStatusFixture struct{ observed masquebackend.HostObservation }

func (h masqueStatusFixture) Inspect(context.Context, domain.Link) (masquebackend.HostObservation, error) {
	return h.observed, nil
}
func (h masqueStatusFixture) Preflight(context.Context, domain.Link, bool) error { return nil }
func (h masqueStatusFixture) Start(context.Context, domain.Link) (core.Rollback, error) {
	return nil, nil
}
func (h masqueStatusFixture) Stop(context.Context, domain.Link) (core.Rollback, error) {
	return nil, nil
}

func TestMASQUEStatusExposesLocalOwnershipWithoutFabricatingPeerConnectivity(t *testing.T) {
	req := masqueInputTestRequest()
	desired, _, err := req.makePair(req.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	desired.MASQUE.MaterialSHA256 = strings.Repeat("b", 64)
	root := t.TempDir()
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: desired, MASQUELastEffectNonce: strings.Repeat("c", 64)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, ready := range []bool{false, true} {
		fixture := masqueStatusFixture{observed: masquebackend.HostObservation{
			UnitExists: true, UnitOwned: true, UnitActive: ready, InterfaceExists: ready, InterfaceOwned: ready, InterfaceIndex: 17,
			LocalAddress: desired.Addresses.Local, PeerRoute: ready, RuntimeReady: ready,
		}}
		impl, err := masquebackend.New(fixture)
		if err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		opts := &runtimeOptions{stateRoot: root, backends: []core.Backend{impl}}
		code := linkReadCommand([]string{"status", string(desired.ID), "--json"}, &out, &errOut, opts)
		if code != 0 {
			t.Fatalf("local diagnostic failed: %s", errOut.String())
		}
		var resp linkStatusResponse
		if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Connectivity != "not_measured" || resp.InterfaceVerified != ready || resp.MASQUEState == nil || resp.MASQUEState.RuntimeReady != ready || resp.MASQUEState.InterfaceIndex != 17 {
			t.Fatalf("status lied about peer connectivity or local ownership: %+v", resp)
		}
		if strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), "connected") {
			t.Fatal("status exposed sensitive or unverified connectivity data")
		}
	}
}

// Exercise genuine MASQUE sender/recipient offer binding and shared
// post-Remove private-offer retirement without privileged host mutation.
func TestMASQUEOriginalMenuOfferRetiresAfterCommittedStateRemoval(t *testing.T) {
	request := masqueInputTestRequest()
	sender, receiver, err := request.makePair(request.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := masque.GeneratePair(sender.ID, sender.MASQUE.TLSServerName, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Clear()
	root := filepath.Join(t.TempDir(), "state")
	sender, own, err := masquehost.BuildMaterial(root, sender, pair)
	if err != nil {
		t.Fatal(err)
	}
	defer masquehost.ClearFiles(own)
	receiver, files, err := masquehost.BuildMaterial(root, receiver, pair)
	if err != nil {
		t.Fatal(err)
	}
	offer := masqueOfferV1{SchemaVersion: 1, Sender: sender, Receiver: receiver, ReceiverMaterial: files}
	defer offer.Clear()
	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: sender, MASQUELastEffectNonce: strings.Repeat("c", 64)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	opts := &runtimeOptions{stateRoot: root}
	path, err := prepareProtectedMenuHandoff(opts, sender.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSensitiveHandoff(path, append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := recordMenuHandoffOrigin(opts, sender.ID); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareProtectedHandoffRemoval(opts, sender.ID)
	if err != nil || prepared == nil {
		t.Fatalf("cannot bind genuine MASQUE original to committed sender: %v", err)
	}
	// A pre-commit cleanup attempt cannot delete an active Link's offer.
	if err := prepared.retireAfterRemove(opts); err == nil {
		t.Fatal("protected original was retired while its Link was committed")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("pre-commit preparation lost secret", err)
	}
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		if !s.Delete(sender.ID) {
			return errors.New("expected committed test Link")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := prepared.retireAfterRemove(opts); err != nil {
		t.Fatalf("verified MASQUE original was not retired: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("MASQUE original sensitive menu offer survived committed removal: %v", err)
	}
}
