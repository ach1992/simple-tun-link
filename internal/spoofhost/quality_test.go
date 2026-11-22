package spoofhost

import (
	"net/netip"
	"testing"
	"time"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

func TestPathQualityMustProveSustainedImprovementBeforeSwitch(t *testing.T) {
	a := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.11"), Profile: carrier.ProfileUDP, Destination: netip.MustParseAddrPort("10.244.62.198:48002")}
	b := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.99"), Profile: carrier.ProfileICMP, Destination: netip.MustParseAddrPort("10.244.62.212:48012")}
	now := time.Now()
	var q pathQualityState
	for i := 0; i < 4; i++ {
		q.reportSuccess(a, 90*time.Millisecond, now)
	}
	if q.shouldSwitch(a, b, now) {
		t.Fatal("unproven path selected")
	}
	q.reportSuccess(b, 15*time.Millisecond, now)
	if q.shouldSwitch(a, b, now) {
		t.Fatal("single response should not trigger path switch")
	}
	for i := 0; i < 2; i++ {
		q.reportSuccess(b, 18*time.Millisecond, now)
	}
	if !q.shouldSwitch(a, b, now) {
		t.Fatal("sustained better path not selected")
	}
	q.switched(now)
	if q.shouldSwitch(a, b, now.Add(time.Second)) {
		t.Fatal("cooldown ignored")
	}
	if q.shouldSwitch(a, b, now.Add(35*time.Second)) {
		t.Fatal("stale verified path should not be selected")
	}
}
func TestPathQualityLossAndMissesOnlyTrackProvenRoutes(t *testing.T) {
	p := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.11"), Profile: carrier.ProfileUDP}
	var q pathQualityState
	q.reportMiss(p)
	if len(q.metrics) != 0 {
		t.Fatal("unverified scan polluted measured route metrics")
	}
	q.reportSuccess(p, 100*time.Millisecond, time.Now())
	q.reportMiss(p)
	if got := q.forPath(p).lossPercent(); got != 50 {
		t.Fatalf("loss expected 50 got %v", got)
	}
	if q.forPath(p).ConsecutiveSuccesses != 0 {
		t.Fatal("miss did not reset quality confidence")
	}
}

// A peer can authenticate incoming frames over a backup while our selected
// outgoing source/port is blackholed. That must not mask active-path failure.
func TestActivePathRoundTripExpiryIgnoresOtherAuthenticatedIncomingTraffic(t *testing.T) {
	now := time.Now()
	a := &Agent{connected: true, lastAuth: now, lastSelectedProbeAck: now.Add(-12 * time.Second)}
	if !a.activeRouteUnresponsive(now) {
		t.Fatal("fresh inbound traffic masked selected-path failure")
	}
	a.lastSelectedProbeAck = now.Add(-4 * time.Second)
	if a.activeRouteUnresponsive(now) {
		t.Fatal("healthy active path falsely expired")
	}
	a.lastAuth = now.Add(-10 * time.Second)
	if !a.activeRouteUnresponsive(now) {
		t.Fatal("total authenticated silence not detected")
	}
	a.connected = false
	if a.activeRouteUnresponsive(now) {
		t.Fatal("already recovering path expired twice")
	}
}
