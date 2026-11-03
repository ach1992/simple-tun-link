package linux

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type capabilityRunner struct {
	fail   map[string]bool
	output map[string][]byte
}

func (r capabilityRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if r.fail[key] {
		return CommandResult{}, errors.New("private diagnostic that must not be exposed")
	}
	if value, ok := r.output[key]; ok {
		return CommandResult{Stdout: value}, nil
	}
	if key == "ip -json -details link show type ipip" {
		return CommandResult{Stdout: []byte("[]")}, nil
	}
	return CommandResult{}, nil
}

func TestCapabilityProbeDegradesPerBackend(t *testing.T) {
	runner := capabilityRunner{fail: map[string]bool{
		"ip fou show":      true,
		"wg show all dump": true,
	}}
	report, err := (CapabilityProbe{Runner: runner}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report[CapabilityGRENative].Available || !report[CapabilityIPIPNative].Available {
		t.Fatal("native GRE/IPIP should remain available when FOU is missing")
	}
	if report[CapabilityGREFOU].Available || report[CapabilityGREGUE].Available || report[CapabilityIPIPFOU].Available || report[CapabilityIPIPGUE].Available {
		t.Fatal("FOU/GUE modes should be unavailable when the FOU probe fails")
	}
	if report[CapabilityWireGuard].Available {
		t.Fatal("WireGuard should require wg tooling")
	}
	if !report[CapabilityIPsecXFRM].Available {
		t.Fatal("IPsec/XFRM should remain independently available")
	}
}

func TestCapabilityProbeDoesNotExposeProbeErrors(t *testing.T) {
	runner := capabilityRunner{fail: map[string]bool{"swanctl --help": true}}
	report, err := (CapabilityProbe{Runner: runner}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := report[CapabilityIPsecXFRM].Reason
	if got == "" || strings.Contains(got, "private diagnostic") {
		t.Fatalf("unsafe or empty reason %q", got)
	}
}

func TestCapabilityProbePropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (CapabilityProbe{Runner: capabilityRunner{}}).Probe(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestSharedFOUModuleProbeIsNotPermanentUnsupportedEvidence(t *testing.T) {
	r := capabilityRunner{fail: map[string]bool{"ip fou show": true}}
	report, err := (CapabilityProbe{Runner: r}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, cap := range []Capability{CapabilityGREFOU, CapabilityGREGUE, CapabilityIPIPFOU, CapabilityIPIPGUE} {
		got := report[cap]
		if got.Available || got.ReasonCode != "fou_module_present_probe_failed" ||
			!strings.Contains(got.Reason, "may not be loaded") {
			t.Fatalf("FOU shared module evidence lost for %s: %+v", cap, got)
		}
	}
}

func TestNoModinfoDoesNotFalselyProveFOUUnsupported(t *testing.T) {
	r := capabilityRunner{fail: map[string]bool{
		"ip fou show": true, "modinfo -F filename fou": true,
		"swanctl --help": true,
	}}
	report, err := (CapabilityProbe{Runner: r}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := report[CapabilityGREFOU]; got.Available || got.ReasonCode != "fou_probe_unconfirmed" {
		t.Fatalf("inconclusive FOU was declared supported or permanent unsupported: %+v", got)
	}
	if got := report[CapabilityIPsecXFRM]; got.Available ||
		got.ReasonCode != "swanctl_probe_unconfirmed" ||
		strings.Contains(got.Reason, "private diagnostic") {
		t.Fatalf("IPsec prerequisite cause was not separated: %+v", got)
	}
}

// iproute2 on a kernel with an unloaded ipip module has returned [{},{},{}]
// with exit 0. Menu capability hints must not call this "ready".
func TestIPIPCapabilityRequiresTrustworthyInventoryNotJustExitZero(t *testing.T) {
	key := "ip -json -details link show type ipip"
	for _, tc := range []struct {
		name, inventory string
		ready           bool
	}{
		{"kernel placeholders", "[{},{},{}]", false},
		{"null", "null", false},
		{"missing endpoint", `[{"ifindex":1,"ifname":"ipip1","linkinfo":{"info_kind":"ipip","info_data":{}}}]`, false},
		{"valid empty", "[]", true},
		{"valid wildcard", `[{"ifindex":1,"ifname":"tunl0","linkinfo":{"info_kind":"ipip","info_data":{"local":"any","remote":"any"}}}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := CapabilityProbe{Runner: capabilityRunner{output: map[string][]byte{key: []byte(tc.inventory)}}}
			report, err := p.Probe(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, cap := range []Capability{CapabilityIPIPNative, CapabilityIPIPFOU, CapabilityIPIPGUE} {
				got := report[cap]
				if got.Available != tc.ready || (!tc.ready && got.ReasonCode == "") {
					t.Fatalf("menu overclaimed %s for %s: %+v", cap, tc.name, got)
				}
			}
		})
	}
}
