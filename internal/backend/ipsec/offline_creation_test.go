package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type offlineIPsecRoute struct{ calls int }

func (r *offlineIPsecRoute) Resolve(context.Context, netip.Addr) (HostRoute, error) {
	r.calls++
	return HostRoute{}, errors.New("no peer route")
}

type assignedIPsecReader struct {
	calls   []string
	address string
}

func (r *assignedIPsecReader) RunBounded(_ context.Context, _ CaptureLimits, binary string, args ...string) (CommandResult, error) {
	call := binary + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if call != "ip -json address show" {
		return CommandResult{}, errors.New("unexpected host command")
	}
	return CommandResult{Stdout: []byte(`[{"ifname":"ens3","addr_info":[{"family":"inet","local":"` + r.address + `"}]}]`)}, nil
}
func TestIPsecESPAndNATTCreateResolveAssignedLocalDeviceWithOfflinePeer(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		t.Run(string(encap), func(t *testing.T) {
			link := testIPsecLink(t, encap)
			for _, address := range []string{link.Underlay.Local.String(), "192.0.2.99"} {
				routes := &offlineIPsecRoute{}
				reader := &assignedIPsecReader{address: address}
				b := &OperationalBackend{OperationalOptions: OperationalOptions{Routes: routes, Runner: reader, IPBinary: "ip"}}
				got, err := b.resolveLocalUnderlay(context.Background(), link)
				if address == link.Underlay.Local.String() {
					if err != nil || got.Device != "ens3" || got.Source != link.Underlay.Local {
						t.Fatalf("cannot locally configure XFRM: %v %+v", err, got)
					}
				} else if err == nil {
					t.Fatal("unassigned IPsec underlay admitted")
				}
				wantRouteReads := 1
				// A bad local identity is denied from local inventory
				// before any (read-only) route suggestion is requested.
				if address != link.Underlay.Local.String() {
					wantRouteReads = 0
				}
				if routes.calls != wantRouteReads || len(reader.calls) != 1 || reader.calls[0] != "ip -json address show" {
					t.Fatal("IPsec route suggestion escaped local identity gate", routes.calls, reader.calls)
				}
			}
		})
	}
}

// A matching kernel route source cannot bypass the IPsec protected local
// address inventory. A wrong route device must not be adopted as XFRM parent.
type ipsecIncorrectRoute struct{ source netip.Addr }

func (r ipsecIncorrectRoute) Resolve(_ context.Context, p netip.Addr) (HostRoute, error) {
	return HostRoute{Source: r.source, Device: "foreign0"}, nil
}
func TestIPsecRouteSuggestionMustMatchUniqueLocalParent(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		link := testIPsecLink(t, encap)
		for _, address := range []string{link.Underlay.Local.String(), "192.0.2.88"} {
			b := &OperationalBackend{OperationalOptions: OperationalOptions{
				Routes: ipsecIncorrectRoute{source: link.Underlay.Local},
				Runner: &assignedIPsecReader{address: address}, IPBinary: "ip"}}
			got, err := b.resolveLocalUnderlay(context.Background(), link)
			if address == link.Underlay.Local.String() {
				if err != nil || got.Device != "ens3" || got.Source != link.Underlay.Local {
					t.Fatalf("IPsec adopted route hint: %+v %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("IPsec accepted unassigned route source: %+v", got)
			}
		}
	}
}
