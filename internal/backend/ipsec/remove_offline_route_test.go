package ipsec

import (
	"context"
	"net/netip"
	"os"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type unreachableIPsecUnderlay struct{ calls int }

func (r *unreachableIPsecUnderlay) Resolve(context.Context, netip.Addr) (HostRoute, error) {
	r.calls++
	panic("IPsec Remove must not query a disconnected underlay")
}

func TestIPsecRemovePlanDoesNotUseCreationRoute(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		t.Run(string(encap), func(t *testing.T) {
			link := testIPsecLink(t, encap)
			profile, err := NewProfile(link)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			keys, err := NewPSKStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.PutNew(link.ID, []byte("0123456789abcdef0123456789abcdef")); err != nil {
				t.Fatal(err)
			}
			offline := &unreachableIPsecUnderlay{}
			b := &OperationalBackend{OperationalOptions: OperationalOptions{Routes: offline, Keys: keys}}
			obs := operationalObservation{Profile: profile, Connection: true, Shared: true}
			req := core.Request{Operation: core.OperationRemove, Link: link, Prior: &link, OwnedResources: profile.ResourceClaims()}
			planned, err := b.Plan(context.Background(), req, obs)
			if err != nil {
				t.Fatalf("IPsec removal planning blocked despite committed owned resources: %v", err)
			}
			p, ok := planned.(operationalPlan)
			if !ok || !p.Remove || offline.calls != 0 {
				t.Fatalf("IPsec Remove reached the original peer route or lacked a cleanup plan: %+v calls=%d", p, offline.calls)
			}
		})
	}
}
