//go:build linux

package diagnostics

import (
	"context"
	"errors"
	"strings"
	"testing"

	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type ipsecSAGuardInspector struct {
	state ipsecbackend.DiagnosticState
	err   error
}

func (f ipsecSAGuardInspector) DiagnosticState(context.Context, domain.Link) (ipsecbackend.DiagnosticState, error) {
	return f.state, f.err
}

// A locally installed XFRM Link with no negotiated SA is not an ICMP failure.
// It must produce the specific, secret-free action and send zero probes.
func TestIPsecMissingSAPreventsProbeAndProvidesConnectGuidance(t *testing.T) {
	link := diagnosticLink()
	link.Backend, link.Encapsulation = domain.BackendIPsec, domain.EncapESP
	link.DisplayName = "private_key=NEVER_PRINT"
	profile, err := ipsecbackend.NewProfile(link)
	if err != nil {
		t.Fatal(err)
	}
	inspector := ipsecSAGuardInspector{state: ipsecbackend.DiagnosticState{
		Interface: profile.InterfaceName, IfIndex: 18, XFRMID: profile.InterfaceID,
		ConnectionConfigured: true, SecurityAssociationPresent: false,
	}}
	runner := &fakeGREProbeRunner{}
	_, err = ObserveIPsec(context.Background(), link, inspector, runner, 0)
	public := stlerr.Public(err)
	if err == nil || public.Code != stlerr.CodeInspect ||
		public.ReasonCode != "ipsec_sa_not_established" ||
		!strings.Contains(public.NextStep, "Connect IPsec") ||
		strings.Contains(public.Error()+public.NextStep, "NEVER_PRINT") ||
		len(runner.calls) != 0 {
		t.Fatalf("missing SA was not a probe-blocking, actionable state: code=%s reason=%q probes=%d", public.Code, public.ReasonCode, len(runner.calls))
	}
	inspector.err = errors.New("PSK=NEVER_PRINT")
	_, err = ObserveIPsec(context.Background(), link, inspector, runner, 0)
	public = stlerr.Public(err)
	if err == nil || public.ReasonCode == "ipsec_sa_not_established" ||
		strings.Contains(public.Error()+public.NextStep, "NEVER_PRINT") ||
		len(runner.calls) != 0 {
		t.Fatal("unverified VICI inventory was misreported as a known missing SA or probed")
	}
}
