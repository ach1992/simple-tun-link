package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func stagedIPsecLink(id domain.LinkID, linkNet string) domain.Link {
	a := netip.MustParsePrefix(linkNet)
	return domain.Link{
		ID: id, DisplayName: "test IPsec",
		Backend: domain.BackendIPsec, Encapsulation: domain.EncapESP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("192.0.2.11")},
		Addresses: domain.LinkAddresses{Local: a, Peer: netip.PrefixFrom(a.Addr().Next(), 31)},
	}
}
func stageEngine(t *testing.T) (*Engine, *state.FileStore, *ipsec.PSKStore) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "stl")
	registry, err := backend.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(registry, state.NewFileStore(root), state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ipsec.NewPSKStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return engine, state.NewFileStore(root), keys
}
func confirmIPsecURL(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}
func offerForStage(t *testing.T, link domain.Link, psk []byte) pairing.Offer {
	t.Helper()
	offer, err := pairing.NewQuickOffer(link, psk)
	if err != nil {
		t.Fatal(err)
	}
	return offer
}
func TestIPsecStageBindsExactSenderAndReceiverWithoutAnyActiveBackend(t *testing.T) {
	ctx := context.Background()
	a, sa, ka := stageEngine(t)
	b, sb, kb := stageEngine(t)
	link := stagedIPsecLink("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "10.84.2.0/31")
	psk := bytes.Repeat([]byte{0x53}, 32)
	offer := offerForStage(t, link, psk)
	var url string
	callback := func(raw string) error {
		if !strings.HasPrefix(raw, "stl://2.") {
			t.Fatal("unexpected format")
		}
		saved, err := sa.Load(ctx)
		if err != nil || len(saved.PendingIPsec) != 1 || saved.PendingIPsec[0].Origin != "sender" {
			t.Fatal("handoff visible without durable canonical sender intent", err)
		}
		if _, err := ka.Load(link.ID); err != nil {
			t.Fatal("handoff visible without protected key", err)
		}
		url = raw
		return nil
	}
	if err := a.StageIPsecSender(ctx, offer, ka, callback); err != nil {
		t.Fatal(err)
	}
	if url == "" {
		t.Fatal("no sensitive handoff published")
	}
	// Sender exact replay is allowed, with the same key, state and URL.
	if err := a.StageIPsecSender(ctx, offer, ka, func(replay string) error {
		if replay != url {
			t.Fatal("replay changed handoff identity")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	decoded, err := pairing.DecodeSetupLink(url)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ReceiverLink() != offer.ReceiverLink() {
		t.Fatal("decoded recipient inversion changed public identity")
	}
	if err := b.StageIPsecRecipient(ctx, url, strings.Repeat("a", 64), kb); stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("IPsec receiver staged without exact reviewed preview: %v", err)
	}
	if len(mustState(t, sb).PendingIPsec) != 0 {
		t.Fatal("invalid preview token persisted IPsec intent")
	}
	// A semantically identical valid wire offer may serialize JSON object
	// fields in another order. Confirm the exact received URL, not an
	// internally re-encoded Offer (which would change the digest).
	parts := strings.Split(url, ".")
	if len(parts) != 3 {
		t.Fatal("invalid test URL shape")
	}
	wireBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(wireBytes, &generic); err != nil {
		t.Fatal(err)
	}
	alternateBytes, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wireBytes, alternateBytes) {
		t.Fatal("expected distinct wire JSON ordering")
	}
	altSum := sha256.Sum256(alternateBytes)
	altURL := "stl://2." + base64.RawURLEncoding.EncodeToString(alternateBytes) + "." + hex.EncodeToString(altSum[:])
	if _, err := pairing.DecodeSetupLink(altURL); err != nil {
		t.Fatal("valid re-ordered JSON rejected", err)
	}
	if err := b.StageIPsecRecipient(ctx, altURL, confirmIPsecURL(altURL), kb); err != nil {
		t.Fatal(err)
	}
	receiver, err := sb.Load(ctx)
	if err != nil || len(receiver.PendingIPsec) != 1 || receiver.PendingIPsec[0].Origin != "recipient" ||
		receiver.PendingIPsec[0].Link != offer.ReceiverLink() || receiver.PendingIPsec[0].HandoffSHA256 != "" {
		t.Fatal("receiver did not bind exact inverted public intent", err)
	}
	for _, snapshot := range []state.Snapshot{mustState(t, sa), receiver} {
		wire, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(wire, []byte("recipient_secret")) || bytes.Contains(wire, []byte("0x53")) ||
			bytes.Contains(wire, []byte(url)) || bytes.Contains(wire, []byte("U1NTU1N")) {
			t.Fatal("credential leaked into ordinary state")
		}
		if len(snapshot.Links) != 0 {
			t.Fatal("staging claimed operational IPsec backend")
		}
	}
	senderKey, err := ka.Load(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := kb.Load(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(senderKey.SecretBytes(), psk) || !bytes.Equal(recipientKey.SecretBytes(), psk) {
		t.Fatal("protected per-endpoint key mismatch")
	}
	senderKey.Zeroize()
	recipientKey.Zeroize()
	if _, err := a.Ensure(ctx, link); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("normal Ensure bypassed pending identity guard: %v", err)
	}
}
func mustState(t *testing.T, s state.Store) state.Snapshot {
	t.Helper()
	v, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestIPsecStageRejectsRekeyReconfigureOriginAndLegacyWithoutHandoff(t *testing.T) {
	ctx := context.Background()
	e, store, keys := stageEngine(t)
	link := stagedIPsecLink("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "10.84.4.0/31")
	psk := bytes.Repeat([]byte{0x73}, 32)
	offer := offerForStage(t, link, psk)
	calls := 0
	emit := func(string) error { calls++; return nil }
	if err := e.StageIPsecSender(ctx, offer, keys, emit); err != nil {
		t.Fatal(err)
	}
	rekey := offerForStage(t, link, bytes.Repeat([]byte{0x74}, 32))
	if err := e.StageIPsecSender(ctx, rekey, keys, emit); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("unannounced rekey was accepted: %v", err)
	}
	modified := link
	modified.DisplayName = "altered public intent"
	if err := e.StageIPsecSender(ctx, offerForStage(t, modified, psk), keys, emit); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("changed Link matched staged identity: %v", err)
	}
	encodedForRecipient, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.StageIPsecRecipient(ctx, encodedForRecipient, confirmIPsecURL(encodedForRecipient), keys); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("sender role was silently repurposed: %v", err)
	}
	legacy := offerForStage(t, stagedIPsecLink("lnk_cccccccccccccccccccccccccccccccc", "10.84.6.0/31"), bytes.Repeat([]byte{0x45}, 16))
	if err := e.StageIPsecSender(ctx, legacy, keys, emit); stlerr.CodeOf(err) != stlerr.CodeUnsupported {
		t.Fatalf("legacy v2 non-256-bit key was activated: %v", err)
	}
	if calls != 1 || len(mustState(t, store).PendingIPsec) != 1 {
		t.Fatal("unexpected publication or public state mutation")
	}
}

func TestIPsecStageReservesOtherLinkResourcesAndPreservesConcurrentWinner(t *testing.T) {
	ctx := context.Background()
	e, stateStore, keys := stageEngine(t)
	first := stagedIPsecLink("lnk_dddddddddddddddddddddddddddddddd", "10.84.8.0/31")
	second := stagedIPsecLink("lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "10.84.8.0/31")
	firstPSK := bytes.Repeat([]byte{0x66}, 32)
	secondPSK := bytes.Repeat([]byte{0x67}, 32)
	firstOffer := offerForStage(t, first, firstPSK)
	if err := e.StageIPsecSender(ctx, firstOffer, keys, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := e.StageIPsecSender(ctx, offerForStage(t, second, secondPSK), keys, func(string) error { return nil }); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("cross-Link subnet conflict ignored: %v", err)
	}
	if _, err := keys.Load(second.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("losing Link wrote a credential: %v", err)
	}
	// Same-ID concurrent exact replay must not mutate the persisted intent.
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- e.StageIPsecSender(ctx, firstOffer, keys, func(string) error { return nil })
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("exact concurrent replay failed: %v", err)
		}
	}
	if len(mustState(t, stateStore).PendingIPsec) != 1 {
		t.Fatal("concurrent replay generated another owner")
	}
}

type failingIPsecState struct {
	base  state.Store
	after bool
}

func (s *failingIPsecState) Load(ctx context.Context) (state.Snapshot, error) {
	return s.base.Load(ctx)
}
func (s *failingIPsecState) Update(ctx context.Context, fn func(*state.Snapshot) error) error {
	if s.after {
		if err := s.base.Update(ctx, fn); err != nil {
			return err
		}
	}
	return errors.New("test intentionally failed staged state update")
}
func TestIPsecStageFailuresNeverPublishAndNeverAdoptUnboundOrphan(t *testing.T) {
	ctx := context.Background()
	e, ss, keys := stageEngine(t)
	link := stagedIPsecLink("lnk_ffffffffffffffffffffffffffffffff", "10.84.10.0/31")
	offer := offerForStage(t, link, bytes.Repeat([]byte{0x23}, 32))
	emits := 0
	original := e.store
	e.store = &failingIPsecState{base: original}
	if err := e.StageIPsecSender(ctx, offer, keys, func(string) error { emits++; return nil }); err == nil {
		t.Fatal("staging ignored failed intent publication")
	}
	if len(mustState(t, ss).PendingIPsec) != 0 || emits != 0 {
		t.Fatal("handoff advertised without durable intent")
	}
	// An orphan key cannot be adopted by a subsequent operation with the
	// same Link ID, even if the raw credential is identical.
	e.store = original
	if err := e.StageIPsecSender(ctx, offer, keys, func(string) error { emits++; return nil }); err == nil {
		t.Fatal("new public intent adopted an unbound orphan key")
	}
	if emits != 0 {
		t.Fatal("orphan material enabled handoff")
	}
	// A post-publish error has the opposite recovery state: exact replay
	// checks the already durable public intent and protected existing key.
	x, xs, xk := stageEngine(t)
	other := offerForStage(t, stagedIPsecLink("lnk_11111111111111111111111111111111", "10.84.12.0/31"), bytes.Repeat([]byte{0x2a}, 32))
	prior := x.store
	x.store = &failingIPsecState{base: prior, after: true}
	if err := x.StageIPsecSender(ctx, other, xk, func(string) error { emits++; return nil }); err == nil {
		t.Fatal("post-publish uncertain state was treated as success")
	}
	if len(mustState(t, xs).PendingIPsec) != 1 || emits != 0 {
		t.Fatal("post-publish uncertain state incorrectly disclosed secret")
	}
	x.store = prior
	if err := x.StageIPsecSender(ctx, other, xk, func(string) error { emits++; return nil }); err != nil {
		t.Fatal(err)
	}
	if emits != 1 {
		t.Fatal("exact recovery did not publish once")
	}
	if err := x.StageIPsecSender(ctx, other, xk, func(string) error { return errors.New("raw SENSITIVE url stl://2.secret") }); err == nil ||
		strings.Contains(err.Error(), "stl://") {
		t.Fatalf("SENSITIVE callback error leaked: %v", err)
	}
}
