//go:build linux

package spoofhost

import (
	"net/netip"
	"testing"
	"time"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

func TestMTUProbeRequiresTwoFailuresBeforeFallback(t *testing.T) {
	p := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.11"), Profile: carrier.ProfileUDP, Destination: netip.MustParseAddrPort("10.244.62.222:48002")}
	a := &Agent{mtuState: adaptiveMTUState{route: p, status: "PROBING_DF"}}
	now := time.Now()
	a.handleMTUMiss(1280, p, now)
	if a.mtuState.probeIndex != 0 {
		t.Fatal("one transient miss incorrectly changed MTU target")
	}
	a.handleMTUMiss(1280, p, now)
	if a.mtuState.probeIndex != 1 || mtuProbeSizes[a.mtuState.probeIndex] != 1200 {
		t.Fatal("second failed request did not advance one MTU candidate")
	}
	a.handleMTUMiss(1280, p, now)
	if a.mtuState.probeIndex != 1 {
		t.Fatal("stale reply changed current candidate")
	}
	for i := 1; i < len(mtuProbeSizes); i++ {
		a.handleMTUMiss(mtuProbeSizes[i], p, now)
		a.handleMTUMiss(mtuProbeSizes[i], p, now)
	}
	if a.mtuState.status != "NO_VERIFIED_MTU" || a.mtuState.confirmed != 0 {
		t.Fatal("no successful DF probe was incorrectly marked verified")
	}
}
