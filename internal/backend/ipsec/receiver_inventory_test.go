package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostaddress"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type receiverInventoryReader struct {
	payload string
	cause   error
	calls   int
}

func (r *receiverInventoryReader) RunBounded(ctx context.Context, limits CaptureLimits, name string, args ...string) (CommandResult, error) {
	r.calls++
	if name != "ip" || strings.Join(args, " ") != "-json address show" ||
		limits.Stdout != 256<<10 || limits.Stderr != 1024 {
		return CommandResult{}, errors.New("wrong inventory command")
	}
	if r.cause != nil {
		return CommandResult{}, errors.Join(r.cause, errors.New("PRIVATE_IPSEC_RUNNER_OUTPUT_DO_NOT_EXPOSE"))
	}
	return CommandResult{Stdout: []byte(r.payload)}, nil
}

func TestIPsecLocalInventoryPropagatesTypedCausesBothEncapsulations(t *testing.T) {
	cases := []struct {
		name, raw     string
		cause, expect error
	}{
		{"canceled", "", context.Canceled, context.Canceled},
		{"deadline", "", context.DeadlineExceeded, context.DeadlineExceeded},
		{"bounded capture", "", ErrBoundedOutput, ErrBoundedOutput},
		{"untrusted OS failure", "", errors.New("opaque-command-failure"), nil},
		{"malformed inventory", `[{"ifname":"eth0","addr_info":null}]`, nil, nil},
		{"missing assigned receiver", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.99"}]}]`, nil, hostaddress.ErrNotAssigned},
		{"ambiguous assigned receiver", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]},{"ifname":"eth1","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`, nil, hostaddress.ErrAmbiguous},
		{"complete local binding", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`, nil, nil},
	}
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		for _, tc := range cases {
			t.Run(string(encap)+"/"+tc.name, func(t *testing.T) {
				link := testIPsecLink(t, encap)
				// Address is fixed in each fixture: both ESP and NAT-T must
				// require the same uniquely assigned LOCAL underlay.
				link.Underlay.Local = netip.MustParseAddr("192.0.2.10")
				reader := &receiverInventoryReader{payload: tc.raw, cause: tc.cause}
				route := &offlineIPsecRoute{}
				b := &OperationalBackend{OperationalOptions: OperationalOptions{Runner: reader, Routes: route, IPBinary: "ip"}}
				got, err := b.resolveLocalUnderlay(context.Background(), link)
				if reader.calls != 1 {
					t.Fatal("IPsec inventory was not read exactly once")
				}
				if tc.name == "complete local binding" {
					if err != nil || got.Source != link.Underlay.Local || got.Device != "eth0" {
						t.Fatalf("correct local binding was rejected: result=%+v err=%v", got, err)
					}
					return
				}
				if err == nil || got != (HostRoute{}) {
					t.Fatalf("failed to reject unsafe local inventory: route=%+v err=%v", got, err)
				}
				if tc.expect != nil && !errors.Is(err, tc.expect) {
					t.Fatalf("lost inventory cause %v: %v", tc.expect, err)
				}
				if tc.expect == nil && (errors.Is(err, hostaddress.ErrNotAssigned) || errors.Is(err, hostaddress.ErrAmbiguous)) {
					t.Fatalf("incomplete inventory misclassified as wrong host: %v", err)
				}
				public := stlerr.LocalUnderlayUnverified("ipsec_validate", string(link.ID), string(link.Backend), err)
				if strings.Contains(public.Error(), "PRIVATE_IPSEC_RUNNER_OUTPUT_DO_NOT_EXPOSE") ||
					strings.Contains(public.Error(), "opaque-command-failure") {
					t.Fatal("IPsec untrusted error escaped secret-safe public wrapper")
				}
				if route.calls != 0 {
					t.Fatal("IPsec tried a route hint after local binding refusal")
				}
			})
		}
	}
}

func TestIPsecBoundedRunnerKeepsTypedOverflowAndInterruptions(t *testing.T) {
	r := BoundedExecRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.RunBounded(ctx, CaptureLimits{Stdout: 128, Stderr: 128}, "true"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled execution lost identity: %v", err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := r.RunBounded(ctx, CaptureLimits{Stdout: 128, Stderr: 128}, "true"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired execution lost identity: %v", err)
	}
	_, err := r.RunBounded(context.Background(), CaptureLimits{Stdout: 64, Stderr: 128}, "sh", "-c", "head -c 2048 /dev/zero")
	if !errors.Is(err, ErrBoundedOutput) {
		t.Fatalf("real bounded runner overflow lost identity: %v", err)
	}
}
