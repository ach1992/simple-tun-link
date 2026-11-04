package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostaddress"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestIPsecStagingReadmitsUnderAllCanonicalLocksBeforePSKBothModes(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		for _, tc := range []struct {
			name  string
			cause error
		}{
			{"missing", hostaddress.ErrNotAssigned},
			{"ambiguous", hostaddress.ErrAmbiguous},
			{"unverified", errors.New("PRIVATE_INCOMPLETE_INTERFACE_INVENTORY_DO_NOT_PRINT")},
		} {
			t.Run(string(encap)+"/"+tc.name, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "private-root")
				engine, store, keys := stageEngineAtRoot(t, root)
				source := stagedIPsecLink(domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "10.84.32.0/31")
				source.Encapsulation = encap
				offer := offerForStage(t, source, bytes.Repeat([]byte{0x59}, 32))
				defer offer.ClearRecipientCredential()
				raw, err := offer.EncodeSetupLink()
				if err != nil {
					t.Fatal(err)
				}
				recipient := offer.ReceiverLink()
				// A previously existing foreign key must survive any failed
				// recipient staging attempt; it is never cleanup authority.
				foreignID := domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
				originalSecret := bytes.Repeat([]byte{0x46}, 32)
				if err := keys.PutNew(foreignID, originalSecret); err != nil {
					t.Fatal(err)
				}
				keyPath := filepath.Join(root, "credentials", string(foreignID)+".ipsecpsk")
				existing, _ := os.ReadFile(keyPath)
				// This models a successful unlocked CLI admission followed by
				// a changed local address before the Engine-locked readback.
				cliAdmission := true
				lockedCalls := 0
				admit := func(ctx context.Context, observed domain.Link) error {
					lockedCalls++
					if !cliAdmission || observed != recipient || ctx.Err() != nil {
						t.Fatal("wrong recipient identity or context at locked readmission")
					}
					if _, err := keys.Load(recipient.ID); err == nil {
						t.Fatal("recipient PSK was published before locked readmission")
					}
					prior, err := store.Load(ctx)
					if err != nil || len(prior.PendingIPsec) != 0 {
						t.Fatal("IPsec pending State published before locked readmission", err)
					}
					return tc.cause
				}
				admissionErr := engine.StageIPsecRecipientAdmitted(context.Background(), raw, confirmIPsecURL(raw), keys, admit)
				if !errors.Is(admissionErr, tc.cause) || lockedCalls != 1 {
					t.Fatalf("expected one typed locked refusal: calls=%d err=%v", lockedCalls, admissionErr)
				}
				evi := stlerr.EvidenceOf(admissionErr)
				if evi == nil || evi.Stage != "preflight" || evi.HostMutation != "not_attempted" ||
					evi.CredentialProvision != "" || stlerr.Public(admissionErr).ReasonCode != "local_underlay_unverified" {
					t.Fatalf("unsafe IPsec staging evidence: %+v", evi)
				}
				if _, err := keys.Load(recipient.ID); err == nil {
					t.Fatal("wrong recipient PSK published")
				}
				snap, err := store.Load(context.Background())
				if err != nil || len(snap.PendingIPsec) != 0 || len(snap.Links) != 0 {
					t.Fatalf("wrong recipient IPsec State published: %+v %v", snap, err)
				}
				protected, err := keys.Load(foreignID)
				if err != nil || !bytes.Equal(protected.SecretBytes(), originalSecret) {
					t.Fatalf("foreign PSK not preserved: %v", err)
				}
				protected.Zeroize()
				if prior, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(prior, existing) {
					t.Fatal("preexisting foreign credential bytes changed")
				}
				if strings.Contains(admissionErr.Error(), "PRIVATE_INCOMPLETE_INTERFACE_INVENTORY_DO_NOT_PRINT") {
					t.Fatal("unsafe subprocess diagnostic exposed")
				}
			})
		}
	}
}

func TestManagedQUICReadmitsAfterResourceLockBeforeFirstJournal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
	}{
		{"missing", hostaddress.ErrNotAssigned},
		{"ambiguous", hostaddress.ErrAmbiguous},
		{"unverified", errors.New("PRIVATE_BAD_LOCAL_IPROUTE_OUTPUT_DO_NOT_PRINT")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, b, link := managedQUICEngineFixture(t)
			before, err := b.store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			admission := func(ctx context.Context, desired domain.Link) error {
				calls++
				if desired != link || ctx.Err() != nil {
					t.Fatal("wrong QUIC original bound at lock")
				}
				current, err := b.store.Load(ctx)
				if err != nil || len(current.QUICCrashOperations) != 0 {
					t.Fatalf("QUIC journal written before locked readmission: %+v %v", current, err)
				}
				if slices.Contains(b.events, "key") || slices.Contains(b.events, "stage") || slices.Contains(b.events, "apply") {
					t.Fatal("QUIC protected material published before locked admission")
				}
				if calls == 1 {
					return nil // The earlier Link-locked admission passed.
				}
				return tc.cause // Assignment changed during resource-lock wait.
			}
			_, err = engine.EnsureWithQUICCredentialAdmitted(context.Background(), link,
				[]byte("private fixture credential"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil, admission)
			if !errors.Is(err, tc.cause) || calls != 2 {
				t.Fatalf("QUIC failed to perform both locked admissions: %d %v", calls, err)
			}
			evi := stlerr.EvidenceOf(err)
			if evi == nil || evi.HostMutation != "not_attempted" || evi.CredentialProvision != "" {
				t.Fatalf("QUIC admission lost no-Apply evidence: %+v", evi)
			}
			after, loadErr := b.store.Load(context.Background())
			if loadErr != nil || !reflect.DeepEqual(before, after) || b.applyCount != 0 ||
				slices.Contains(b.events, "key") || slices.Contains(b.events, "stage") || slices.Contains(b.events, "apply") {
				t.Fatalf("QUIC accepted invalid locked receiver: %+v %v events=%v", after, loadErr, b.events)
			}
			if strings.Contains(err.Error(), "PRIVATE_BAD_LOCAL_IPROUTE_OUTPUT_DO_NOT_PRINT") {
				t.Fatal("QUIC private inventory text leaked")
			}
		})
	}
}

// A Native WireGuard removal receipt is credential-retirement authority,
// even if its original key was already retired. A managed QUIC Import with
// that historical Link ID must not remove the receipt or adopt the identity.
// The first external CLI admission is modeled as successful; the Engine
// callback models a changed local address while acquiring its own locks.
func TestManagedQUICImportPreservesNativeWireGuardRetirementReceipt(t *testing.T) {
	for _, retired := range []bool{false, true} {
		name := "not_retired"
		if retired {
			name = "retired"
		}
		for _, tc := range []struct {
			name  string
			cause error
		}{
			{"missing", hostaddress.ErrNotAssigned},
			{"ambiguous", hostaddress.ErrAmbiguous},
			{"unverified", errors.New("PRIVATE_QUIC_RECEIVER_INVENTORY_NOT_FOR_OUTPUT")},
			{"valid_receiver_but_reserved_identity", nil},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				engine, b, link := managedQUICEngineFixture(t)
				root := b.store.RootDir()
				// The production credential store intentionally rejects a
				// writable group/other test directory.
				if err := os.Chmod(root, 0o700); err != nil {
					t.Fatal(err)
				}
				keys, err := wgbackend.NewKeyStore(root)
				if err != nil {
					t.Fatal(err)
				}
				existingKey, originalPublic, err := wgbackend.GenerateKeyPair()
				if err != nil {
					t.Fatal(err)
				}
				defer existingKey.Zeroize()
				// For Retired=false, the target's original protected WG key
				// remains legitimately present. Retired=true models an
				// already-removed target key while a sibling's key persists.
				if !retired {
					if err := keys.PutNew(link.ID, existingKey); err != nil {
						t.Fatal(err)
					}
				}
				foreignID := domain.LinkID("lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
				foreignKey, _, err := wgbackend.GenerateKeyPair()
				if err != nil {
					t.Fatal(err)
				}
				defer foreignKey.Zeroize()
				if err := keys.PutNew(foreignID, foreignKey); err != nil {
					t.Fatal(err)
				}
				exactReceipt := state.RemovalReceipt{LinkID: link.ID,
					Backend:        domain.BackendWireGuard,
					LocalPublicKey: originalPublic, Retired: retired}
				if err := b.store.Update(ctx, func(s *state.Snapshot) error {
					s.RemovalReceipts = append(s.RemovalReceipts, exactReceipt)
					return nil
				}); err != nil {
					t.Fatal("fixture must start from valid committed State", err)
				}
				before, err := b.store.Load(ctx)
				if err != nil {
					t.Fatal("invalid persisted receipt fixture", err)
				}
				binaryBefore, err := os.ReadFile(filepath.Join(root, "state.json"))
				if err != nil {
					t.Fatal(err)
				}
				protectedBefore, err := os.ReadDir(filepath.Join(root, "credentials"))
				if err != nil {
					t.Fatal(err)
				}
				credentials := map[string][]byte{}
				for _, item := range protectedBefore {
					if item.IsDir() {
						t.Fatal("unexpected private credential directory")
					}
					contents, err := os.ReadFile(filepath.Join(root, "credentials", item.Name()))
					if err != nil {
						t.Fatal(err)
					}
					credentials[item.Name()] = contents
				}
				lockedCalls := 0
				admission := func(admissionCtx context.Context, desired domain.Link) error {
					lockedCalls++
					if desired != link || admissionCtx.Err() != nil {
						t.Fatal("wrong QUIC receiver identity or canceled admission")
					}
					current, err := b.store.Load(admissionCtx)
					if err != nil {
						t.Fatal(err)
					}
					receipt, present := current.FindRemovalReceipt(link.ID)
					if !present || receipt != exactReceipt {
						return errors.New("previous Native WireGuard retirement receipt was modified before locked admission")
					}
					if !reflect.DeepEqual(before, current) {
						return errors.New("protected State was modified before locked receiver admission")
					}
					return tc.cause
				}
				// The CLI's earlier read-only check succeeded; this call
				// enters canonical Engine with that exact accepted offer.
				_, err = engine.EnsureWithQUICCredentialAdmitted(ctx, link,
					[]byte("fixture new QUIC recipient key"),
					managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil, admission)
				immediate, readErr := b.store.Load(ctx)
				if readErr != nil {
					t.Fatal(readErr)
				}
				receipt, present := immediate.FindRemovalReceipt(link.ID)
				if !present || receipt != exactReceipt {
					t.Fatal("QUIC Import erased original Native WireGuard removal receipt before receiver readmission")
				}
				if tc.cause != nil {
					if !errors.Is(err, tc.cause) {
						t.Fatalf("changed local binding was not rejected under lock: %v", err)
					}
				} else if stlerr.CodeOf(err) != stlerr.CodeConflict {
					t.Fatalf("valid receiver reused retired Native WireGuard Link ID: %v", err)
				}
				if lockedCalls != 1 {
					t.Fatalf("unexpected QUIC early readmissions with reserved identity: %d", lockedCalls)
				}
				evidence := stlerr.EvidenceOf(err)
				if evidence == nil || evidence.HostMutation != "not_attempted" ||
					evidence.CredentialProvision != "" {
					t.Fatalf("rejected QUIC identity has unsafe effect evidence: %+v", evidence)
				}
				after, err := b.store.Load(ctx)
				if err != nil || !reflect.DeepEqual(before, after) ||
					after.RemovalReceipts[0] != exactReceipt {
					t.Fatalf("rejected QUIC import invalidated Native WireGuard retirement: %v", err)
				}
				binaryAfter, err := os.ReadFile(filepath.Join(root, "state.json"))
				if err != nil || !bytes.Equal(binaryBefore, binaryAfter) {
					t.Fatal("rejected QUIC import wrote any durable State")
				}
				protectedAfter, err := os.ReadDir(filepath.Join(root, "credentials"))
				if err != nil || len(protectedAfter) != len(protectedBefore) {
					t.Fatal("rejected QUIC import changed number of protected keys")
				}
				for _, item := range protectedAfter {
					content, err := os.ReadFile(filepath.Join(root, "credentials", item.Name()))
					if err != nil || !bytes.Equal(content, credentials[item.Name()]) {
						t.Fatal("rejected QUIC Import changed or adopted a protected credential")
					}
				}
				if b.applyCount != 0 || b.rollbackCount != 0 ||
					slices.Contains(b.events, "key") ||
					slices.Contains(b.events, "stage") ||
					slices.Contains(b.events, "apply") {
					t.Fatalf("rejected QUIC Import started host/credential changes: %v", b.events)
				}
			})
		}
	}
}
