package state

import (
    "context"
    "net/netip"
    "path/filepath"
    "strings"
    "testing"

    "github.com/ach1992/simple-tun-link/internal/domain"
)

func pendingIPsecFixture() PendingIPsec {
    return PendingIPsec{
        Link: domain.Link{
            ID: "lnk_22222222222222222222222222222222",
            Backend: domain.BackendIPsec, Encapsulation: domain.EncapNATT,
            Underlay: domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("192.0.2.11")},
            Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.84.20.0/31"), Peer: netip.MustParsePrefix("10.84.20.1/31")},
        },
        Origin: "sender", HandoffSHA256: strings.Repeat("c", 64),
    }
}

func TestPendingIPsecDurableAndConflictValidation(t *testing.T) {
    ctx := context.Background()
    store := NewFileStore(filepath.Join(t.TempDir(), "state"))
    entry := pendingIPsecFixture()
    if err := store.Update(ctx, func(s *Snapshot) error {
        s.PendingIPsec = append(s.PendingIPsec, entry)
        return nil
    }); err != nil { t.Fatal(err) }
    got, err := store.Load(ctx)
    if err != nil { t.Fatal(err) }
    saved, exists := got.FindPendingIPsec(entry.Link.ID)
    if !exists || saved != entry || len(got.Links) != 0 { t.Fatal("public pending state did not survive reload") }
    if err := store.Update(ctx, func(s *Snapshot) error {
        s.Upsert(LinkRecord{Desired: entry.Link})
        return nil
    }); err == nil { t.Fatal("pending and committed identity coexisted") }
}

func TestPendingIPsecValidationRejectsCorruptPublicIntent(t *testing.T) {
    for name, alter := range map[string]func(*Snapshot){
        "duplicate": func(s *Snapshot) { s.PendingIPsec = append(s.PendingIPsec, s.PendingIPsec[0]) },
        "invalid-backend": func(s *Snapshot) { s.PendingIPsec[0].Link.Backend = domain.BackendGRE },
        "invalid-endpoint": func(s *Snapshot) { s.PendingIPsec[0].Link.Underlay.Local = netip.MustParseAddr("0.0.0.0") },
        "different-subnet": func(s *Snapshot) { s.PendingIPsec[0].Link.Addresses.Peer = netip.MustParsePrefix("10.84.22.1/31") },
        "noncanonical-digest": func(s *Snapshot) { s.PendingIPsec[0].HandoffSHA256 = strings.Repeat("C", 64) },
        "missing-digest": func(s *Snapshot) { s.PendingIPsec[0].HandoffSHA256 = "" },
        "invalid-role": func(s *Snapshot) { s.PendingIPsec[0].Origin = "unexpected" },
    } {
        t.Run(name, func(t *testing.T) {
            snapshot := EmptySnapshot()
            snapshot.PendingIPsec = []PendingIPsec{pendingIPsecFixture()}
            alter(&snapshot)
            if err := validateSnapshot(snapshot); err == nil { t.Fatal("invalid IPsec staging record accepted") }
        })
    }
}
