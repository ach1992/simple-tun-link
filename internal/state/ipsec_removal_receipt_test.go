package state

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestIPsecRemovalReceiptRejectsAmbiguousAuthorization(t *testing.T) {
	digest := sha256.Sum256([]byte("test-only-domain-separation"))
	canonical := hex.EncodeToString(digest[:])
	id := domain.LinkID("lnk_00112233445566778899aabbccddeeff")
	makeSnapshot := func() Snapshot {
		s := EmptySnapshot()
		s.IPsecRemovalReceipts = []IPsecRemovalReceipt{{LinkID: id, PSKSHA256: canonical}}
		return s
	}
	if err := validateSnapshot(makeSnapshot()); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*Snapshot){
		"bad-hex":        func(s *Snapshot) { s.IPsecRemovalReceipts[0].PSKSHA256 = "bad" },
		"uppercase-hex":  func(s *Snapshot) { s.IPsecRemovalReceipts[0].PSKSHA256 = "BAD" + canonical[3:] },
		"duplicate":      func(s *Snapshot) { s.IPsecRemovalReceipts = append(s.IPsecRemovalReceipts, s.IPsecRemovalReceipts[0]) },
		"invalid-linkid": func(s *Snapshot) { s.IPsecRemovalReceipts[0].LinkID = "../foreign" },
		"committed-link-overlap": func(s *Snapshot) {
			_, l := committedIPsecRecoveryFixture(t)
			l.ID = id
			s.Upsert(LinkRecord{Desired: l})
		},
		"pending-wireguard-overlap": func(s *Snapshot) {
			pending := validPendingForLifecycleTest(t)
			pending.Link.ID = id
			s.PendingSenders = append(s.PendingSenders, pending)
		},
		"retired-pending-wireguard-overlap": func(s *Snapshot) {
			s.IPsecRemovalReceipts[0].Retired = true
			pending := validPendingForLifecycleTest(t)
			pending.Link.ID = id
			s.PendingSenders = append(s.PendingSenders, pending)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := makeSnapshot()
			alter(&s)
			if err := validateSnapshot(s); err == nil {
				t.Fatal("ambiguous IPsec credential retirement authorization was accepted")
			}
		})
	}
}

// A verified-absent receipt carries *no digest*. It authorizes only
// receipt-bound read-only confirmation; a present-key digest uses the
// original strict SHA-256 representation. Both identities are exclusive.
func TestIPsecRemovalReceiptValidatedAbsentCredentialMode(t *testing.T) {
	id := domain.LinkID("lnk_01010101010101010101010101010101")
	clean := EmptySnapshot()
	clean.IPsecRemovalReceipts = []IPsecRemovalReceipt{{LinkID: id, VerifiedAbsent: true}}
	if err := validateSnapshot(clean); err != nil {
		t.Fatalf("verified-absent receipt rejected: %v", err)
	}
	clean.IPsecRemovalReceipts[0].Retired = true
	if err := validateSnapshot(clean); err != nil {
		t.Fatalf("retired verified-absent receipt rejected: %v", err)
	}
	for _, tc := range []struct {
		name  string
		alter func(*IPsecRemovalReceipt)
	}{
		{"digest-and-absent", func(r *IPsecRemovalReceipt) {
			r.PSKSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		}},
		{"absent-not-declared", func(r *IPsecRemovalReceipt) { r.VerifiedAbsent = false }},
		{"duplicate", func(r *IPsecRemovalReceipt) { r.LinkID = "../foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := clean
			candidate.IPsecRemovalReceipts = append([]IPsecRemovalReceipt(nil), clean.IPsecRemovalReceipts...)
			tc.alter(&candidate.IPsecRemovalReceipts[0])
			if err := validateSnapshot(candidate); err == nil {
				t.Fatal("ambiguous receipt identity accepted")
			}
		})
	}
}
