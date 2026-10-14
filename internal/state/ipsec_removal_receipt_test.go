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
