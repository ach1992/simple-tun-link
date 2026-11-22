//go:build linux

package spoofhost

import (
	"errors"
	"net/netip"
	"testing"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

func TestPrivateICMPProofBindsToExactRouteGeneration(t *testing.T) {
	link := ingressFixture(t, "auto")
	a := newAgent(t.TempDir(), link, Material{}, nil)
	source1 := netip.MustParseAddr("198.18.0.11")
	source2 := netip.MustParseAddr("198.18.0.99")
	a.inventory = carrier.Inventory{Addresses: []netip.Addr{source1, source2}}
	if err := a.cursor.ReplaceInventory(a.inventory); err != nil {
		t.Fatal(err)
	}
	a.session = &carrier.Session{}
	a.connected = true
	destination := a.peerEndpoint()
	first := carrier.SourcePath{Source: source1, Profile: carrier.ProfileUDP, Destination: destination}
	sameDestinationNewSource := carrier.SourcePath{Source: source2, Profile: carrier.ProfileUDP, Destination: destination}
	sameDestinationNewProfile := carrier.SourcePath{Source: source2, Profile: carrier.ProfileICMP, Destination: destination}

	if !a.confirmedPath(first) {
		t.Fatal("first authenticated route not admitted")
	}
	old := privateProbeResult{session: a.session, path: first, generation: a.selectedPathGeneration}
	if !a.acceptPrivateProbeResult(old) || a.status.PrivateL3Status != "VERIFIED_ICMP" {
		t.Fatal("fresh private path was not verified")
	}
	initialSuccess := a.status.PrivateICMPLastSuccessAt
	if initialSuccess.IsZero() {
		t.Fatal("initial private proof timestamp missing")
	}

	if !a.confirmedPath(sameDestinationNewSource) {
		t.Fatal("source change was not authenticated")
	}
	if a.status.PrivateL3Status != "UNVERIFIED" || !a.status.PrivateICMPLastSuccessAt.IsZero() ||
		a.status.PrivateICMPError != "" {
		t.Fatal("Source switch retained prior private-L3 evidence")
	}
	if a.acceptPrivateProbeResult(old) {
		t.Fatal("late prior Source proof admitted")
	}
	source2Evidence := privateProbeResult{session: a.session, path: sameDestinationNewSource, generation: a.selectedPathGeneration}
	if !a.acceptPrivateProbeResult(source2Evidence) || a.status.PrivateL3Status != "VERIFIED_ICMP" {
		t.Fatal("fresh Source proof rejected")
	}
	if !a.confirmedPath(sameDestinationNewProfile) {
		t.Fatal("profile switch not authenticated")
	}
	if a.status.PrivateL3Status != "UNVERIFIED" {
		t.Fatal("profile switch retained old proof")
	}
	if a.acceptPrivateProbeResult(source2Evidence) {
		t.Fatal("late prior Profile proof admitted")
	}
	second := privateProbeResult{session: a.session, path: sameDestinationNewProfile, generation: a.selectedPathGeneration}
	if !a.acceptPrivateProbeResult(second) || a.status.PrivateL3Status != "VERIFIED_ICMP" {
		t.Fatal("fresh Profile proof rejected")
	}
	if !a.confirmedPath(first) {
		t.Fatal("return to original route not admitted")
	}
	if a.acceptPrivateProbeResult(old) {
		t.Fatal("old proof resurrected after returning to original route")
	}
	fresh := privateProbeResult{session: a.session, path: first, generation: a.selectedPathGeneration}
	fresh.err = errors.New("independent private ICMP blocked")
	if !a.acceptPrivateProbeResult(fresh) || a.status.PrivateL3Status != "ICMP_PROBE_FAILED" {
		t.Fatal("private-layer ICMP failure not independently reported")
	}
	if !a.confirmedPath(first) || a.status.PrivateL3Status != "ICMP_PROBE_FAILED" {
		t.Fatal("unchanged, still connected route unexpectedly discarded current evidence")
	}
	a.connected = false
	if !a.confirmedPath(first) || a.status.PrivateL3Status != "UNVERIFIED" {
		t.Fatal("reconnected route reused old proof despite a connectivity break")
	}
	if a.acceptPrivateProbeResult(fresh) {
		t.Fatal("pre-reconnection result was adopted")
	}
}
