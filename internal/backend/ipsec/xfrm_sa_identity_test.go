package ipsec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func fixtureMatchingSA(p Profile, legacy bool) string {
	a, b := p.Link.Underlay.Local, p.Link.Underlay.Peer
	id := fmt.Sprintf("0x%x", p.InterfaceID)
	if legacy {
		return fmt.Sprintf("src %s dst %s\n\tproto esp spi 0x12345678 reqid 17 mode tunnel\n\tif_id %s\n"+
			"src %s dst %s\n\tproto esp spi 0x12345679 reqid 17 mode tunnel\n\tif_id %s\n",
			a, b, id, b, a, id)
	}
	return fmt.Sprintf("[{\"src\":%q,\"dst\":%q,\"proto\":\"esp\",\"spi\":\"0x12345678\",\"reqid\":17,\"mode\":\"tunnel\",\"if_id\":%q,\"aead\":{\"key\":\"NEVER_PRINT_KEY\"}},"+
		"{\"src\":%q,\"dst\":%q,\"proto\":\"esp\",\"spi\":\"0x12345679\",\"reqid\":17,\"mode\":\"tunnel\",\"if_id\":%q}]",
		a.String(), b.String(), id, b.String(), a.String(), id)
}

func TestExactScopedChildSARequiresCompleteBidirectionalPeerIdentity(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		p, err := NewProfile(testIPsecLink(t, encap))
		if err != nil {
			t.Fatal(err)
		}
		for _, legacy := range []bool{false, true} {
			name := "json"
			if legacy {
				name = "legacy"
			}
			t.Run(string(encap)+"/"+name, func(t *testing.T) {
				good := fixtureMatchingSA(p, legacy)
				if present, err := matchingProfileSA(context.Background(), []byte(good), p); err != nil || !present {
					t.Fatalf("valid two-direction SA not verified: present=%t err=%v", present, err)
				}
				cases := []struct {
					name, raw string
					unknown   bool
				}{
					{"empty", "[]", false},
				}
				if legacy {
					idx := strings.Index(good, "src "+p.Link.Underlay.Peer.String())
					if idx < 1 {
						t.Fatal("no inbound fixture")
					}
					cases = append(cases,
						struct {
							name, raw string
							unknown   bool
						}{"outbound only", good[:idx], true},
						struct {
							name, raw string
							unknown   bool
						}{"wrong peer source", strings.Replace(good, "src "+p.Link.Underlay.Peer.String(), "src 192.0.2.99", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"wrong local destination", strings.Replace(good, "dst "+p.Link.Underlay.Local.String()+"\n", "dst 192.0.2.99\n", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"wrong request identity", strings.Replace(good, "reqid 17 mode tunnel", "reqid 19 mode tunnel", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"transport mode", strings.Replace(good, "mode tunnel", "mode transport", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"no spi", strings.Replace(good, "spi 0x12345678", "spi 0x0", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"non-esp SA", strings.Replace(good, "proto esp", "proto ah", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"broken later record", good + "src 192.0.2.10 dst 192.0.2.11\n", true})
				} else {
					one := strings.SplitN(good, "},{", 2)[0] + "]"
					cases = append(cases,
						struct {
							name, raw string
							unknown   bool
						}{"outbound only", one, true},
						struct {
							name, raw string
							unknown   bool
						}{"wrong peer source", strings.Replace(good, "\"src\":\""+p.Link.Underlay.Peer.String()+"\"", "\"src\":\"192.0.2.99\"", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"wrong local destination", strings.Replace(good, "\"dst\":\""+p.Link.Underlay.Local.String()+"\"", "\"dst\":\"192.0.2.99\"", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"wrong request identity", strings.Replace(good, "\"reqid\":17", "\"reqid\":18", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"missing request identity", strings.Replace(good, "\"reqid\":17,", "", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"transport mode", strings.Replace(good, "\"mode\":\"tunnel\"", "\"mode\":\"transport\"", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"no spi", strings.Replace(good, "\"spi\":\"0x12345678\"", "\"spi\":0", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"non-esp SA", strings.Replace(good, "\"proto\":\"esp\"", "\"proto\":\"ah\"", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"duplicate identity field", strings.Replace(good, "\"mode\":\"tunnel\"", "\"mode\":\"tunnel\",\"mode\":\"tunnel\"", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"noncanonical security field case", strings.Replace(good, "\"mode\":\"tunnel\"", "\"MODE\":\"transport\",\"mode\":\"tunnel\"", 1), true},
						struct {
							name, raw string
							unknown   bool
						}{"broken later record", strings.TrimSuffix(good, "]") + ",{\"invalid\":\"record\"}]", true},
						struct {
							name, raw string
							unknown   bool
						}{"additional wrong same-ID SA",
							strings.TrimSuffix(good, "]") + "," + fmt.Sprintf("{\"src\":\"192.0.2.99\",\"dst\":%q,\"proto\":\"esp\",\"mode\":\"tunnel\",\"spi\":42,\"reqid\":17,\"if_id\":%q}]", p.Link.Underlay.Peer.String(), fmt.Sprintf("0x%x", p.InterfaceID)), true})
				}
				for _, tc := range cases {
					t.Run(tc.name, func(t *testing.T) {
						present, err := matchingProfileSA(context.Background(), []byte(tc.raw), p)
						if present || (err != nil) != tc.unknown {
							t.Fatalf("unsafe SA decision: present=%t err=%v; want unknown=%t", present, err, tc.unknown)
						}
						if err != nil && strings.Contains(err.Error(), "NEVER_PRINT_KEY") {
							t.Fatal("kernel encryption bytes exposed")
						}
					})
				}
			})
		}
	}
}

type scopedSAAdmission func(context.Context) error

func (f scopedSAAdmission) Authorize(ctx context.Context) error { return f(ctx) }

func TestOperationalSAReadOnlyUsesExactPair(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	f := goodXFRMFixture()
	b := &OperationalBackend{OperationalOptions: OperationalOptions{
		Admission: scopedSAAdmission(func(context.Context) error { return nil }),
		XFRM:      XFRMVacancyInspector{Runner: f.Run, IPBinary: "ip"}, IPBinary: "ip",
	}}
	f.rows["ip -json xfrm state"] = []byte(fixtureMatchingSA(p, false))
	sa, err := b.hasIPsecSA(context.Background(), p)
	if err != nil || !sa || len(f.called) != 1 || f.called[0] != "ip -json xfrm state" {
		t.Fatalf("verified SA read-only check failed: %t %v %v", sa, err, f.called)
	}
	f.called = nil
	f.rows["ip -json xfrm state"] = []byte(strings.SplitN(fixtureMatchingSA(p, true), "src "+p.Link.Underlay.Peer.String(), 2)[0])
	if sa, err = b.hasIPsecSA(context.Background(), p); sa || err == nil {
		t.Fatal("incomplete SA was accepted or misclassified absent")
	}
	f.rows["ip -json xfrm state"] = []byte("[]")
	if sa, err = b.hasIPsecSA(context.Background(), p); sa || err != nil {
		t.Fatal("verified empty SA was not accepted as absent")
	}
	f.fail = "ip -json xfrm state"
	if sa, err = b.hasIPsecSA(context.Background(), p); sa || err == nil ||
		strings.Contains(err.Error(), "sensitive") {
		t.Fatal("unknown XFRM state or sensitive error leaked")
	}
}

func TestLateSACheckBeforeCanonicalInitiate(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                     string
		present, unknown, cancel bool
		wantStart                int
	}{
		{"peer established SA after menu status", true, false, false, 0},
		{"verified absence", false, false, false, 1},
		{"unverifiable inventory", false, true, false, 0},
		{"cancelled", false, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			reads, starts := 0, 0
			err := connectIPsecIfSAAbsent(ctx, p, func(context.Context, Profile) (bool, error) {
				reads++
				if tc.unknown {
					return false, errors.New("SENSITIVE_DO_NOT_PRINT")
				}
				return tc.present, nil
			}, func(context.Context, Profile) error { starts++; return nil })
			if (err != nil) != (tc.unknown || tc.cancel) || starts != tc.wantStart ||
				(tc.cancel && reads != 0) || (err != nil && strings.Contains(err.Error(), "SENSITIVE_DO_NOT_PRINT")) {
				t.Fatalf("unsafe Connect action: reads=%d starts=%d err=%v", reads, starts, err)
			}
		})
	}
}
