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

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostaddress"
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
				return tc.cause
			}
			_, err = engine.EnsureWithQUICCredentialAdmitted(context.Background(), link,
				[]byte("private fixture credential"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil, admission)
			if !errors.Is(err, tc.cause) || calls != 1 {
				t.Fatalf("QUIC failed to perform locked admission: %d %v", calls, err)
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
