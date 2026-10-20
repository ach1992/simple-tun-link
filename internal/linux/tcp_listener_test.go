package linux

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type tcpProbeRunner struct {
	stdout []byte
	err    error
	called bool
}

func (f *tcpProbeRunner) Run(_ context.Context, exe string, args ...string) (CommandResult, error) {
	if exe != "ss" || !reflect.DeepEqual(args, []string{"-H", "-t", "-l", "-n"}) {
		return CommandResult{}, errors.New("unexpected TCP probe command")
	}
	f.called = true
	return CommandResult{Stdout: f.stdout}, f.err
}

func TestTCPListenerProbeTreatsAllAddressesAsExclusive(t *testing.T) {
	fake := &tcpProbeRunner{stdout: []byte("LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 128 [::]:8443 [::]:*\nLISTEN 0 128 127.0.0.1:3210 0.0.0.0:*\n")}
	p := TCPListenerProbe{Runner: fake}
	for _, tt := range []struct {
		port string
		want bool
	}{
		{"443", true}, {"8443", true}, {"3210", true}, {"9443", false},
	} {
		got, err := p.InspectResource(context.Background(), domain.ResourceClaim{
			Kind: domain.ResourceTCPListenPort, Key: tt.port,
		})
		if err != nil || (len(got) > 0) != tt.want {
			t.Fatalf("port %s: conflicts=%+v error=%v", tt.port, got, err)
		}
		if tt.want && (len(got) != 1 || got[0].Owner != "" || got[0].Source != "ss-tcp") {
			t.Fatalf("physical listener accidentally claimed as STL-owned: %+v", got)
		}
	}
	if !fake.called {
		t.Fatal("TCP listeners never inspected")
	}
}

func TestTCPProbeFailClosedOnUnknownInventoryAndUnsupportedClaims(t *testing.T) {
	for _, ss := range []string{"LISTEN 0 4096 *:* *:*", "LISTEN 0 10 [::]:x [::]:*", "ESTAB 0 0 127.0.0.1:443 1.2.3.4:22", "LISTEN 0 128 malformed"} {
		fake := &tcpProbeRunner{stdout: []byte(ss)}
		if _, err := (TCPListenerProbe{Runner: fake}).InspectResource(context.Background(), domain.ResourceClaim{Kind: domain.ResourceTCPListenPort, Key: "443"}); err == nil {
			t.Fatalf("unknown ss output accepted as vacancy: %q", ss)
		}
	}
	fake := &tcpProbeRunner{err: errors.New("inspection permission denied")}
	if _, err := (TCPListenerProbe{Runner: fake}).InspectResource(context.Background(), domain.ResourceClaim{Kind: domain.ResourceTCPListenPort, Key: "443"}); err == nil {
		t.Fatal("missing ss inspection accepted as TCP vacancy")
	}
	if _, err := (TCPListenerProbe{}).InspectResource(context.Background(), domain.ResourceClaim{Kind: domain.ResourceTCPListenPort, Key: "443"}); err == nil {
		t.Fatal("absent runner accepted")
	}
	if _, err := (TCPListenerProbe{Runner: fake}).InspectResource(context.Background(), domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: "443"}); err == nil {
		t.Fatal("UDP claim passed through TCP inspector")
	}
	for _, bad := range []string{"", "0", "65536", "0443", "abc", "-1"} {
		if err := (domain.ResourceClaim{Kind: domain.ResourceTCPListenPort, Key: bad}).Validate(); err == nil {
			t.Fatalf("invalid canonical TCP reservation %q accepted", bad)
		}
	}
}
