//go:build linux

package spoofhost

import (
	"context"
	"fmt"
	"time"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Each candidate is an *inner* IPv4 payload length. The encrypted probe's
// transport frame has the exact same size as an encrypted private IP packet
// of that length, with IPv4 DF set on the outer header.
var mtuProbeSizes = [...]int{1280, 1200, 1100, 1024, 960, 900, 800, 700, 576}

type adaptiveMTUState struct {
	route                carrier.SourcePath
	probeIndex           int
	pending              bool
	consecutiveSuccesses int
	consecutiveFailures  int
	confirmed            int
	status               string
	nextProbeAt          time.Time
}

func (a *Agent) autoMTUTick(now time.Time) {
	if a.link.Spoof.PrivateMTU.Mode != domain.MTUAuto || !a.connected || a.tun == nil ||
		!a.chosen.IsValid() || a.chosenProfile == "" {
		return
	}
	path := carrier.SourcePath{Source: a.chosen, Profile: a.chosenProfile,
		Destination: a.effectiveDestination(a.chosenDestination)}
	if a.mtuState.route != path {
		a.mtuState = adaptiveMTUState{route: path, status: "PROBING_DF"}
	}
	st := &a.mtuState
	if st.pending || st.confirmed > 0 || st.probeIndex >= len(mtuProbeSizes) || now.Before(st.nextProbeAt) {
		return
	}
	candidate := mtuProbeSizes[st.probeIndex]
	if err := a.sendMTUProbe(path, candidate); err != nil {
		a.handleMTUMiss(candidate, path, now)
		a.status.LastError = fmt.Sprintf("Spoof authenticated DF MTU probe size %d not transmitted: %v", candidate, err)
	} else {
		st.pending = true
		st.status = "PROBING_DF"
	}
}
func (a *Agent) handleMTUReply(size int, path carrier.SourcePath, now time.Time) {
	st := &a.mtuState
	if st.route != path || st.probeIndex >= len(mtuProbeSizes) ||
		mtuProbeSizes[st.probeIndex] != size {
		return
	}
	st.pending = false
	st.consecutiveFailures = 0
	st.consecutiveSuccesses++
	if st.consecutiveSuccesses < 2 {
		st.nextProbeAt = now.Add(600 * time.Millisecond)
		return
	}
	if a.tun == nil {
		return
	}
	if a.tun.MTU() != size {
		if err := a.tun.SetMTU(context.Background(), size, linux.SetLinkMTUByIndex); err != nil {
			a.record(fmt.Errorf("verified Spoof path %s MTU %d but cannot update original TUN: %w", path, size, err))
			st.status = "KERNEL_MTU_APPLY_FAILED"
			st.nextProbeAt = now.Add(5 * time.Second)
			return
		}
	}
	st.confirmed = size
	st.status = "VERIFIED_DF_DELIVERY"
}
func (a *Agent) handleMTUMiss(size int, path carrier.SourcePath, now time.Time) {
	st := &a.mtuState
	if st.route != path || st.probeIndex >= len(mtuProbeSizes) ||
		mtuProbeSizes[st.probeIndex] != size {
		return
	}
	st.pending = false
	st.consecutiveFailures++
	st.consecutiveSuccesses = 0
	st.nextProbeAt = now.Add(600 * time.Millisecond)
	if st.consecutiveFailures >= 2 {
		st.consecutiveFailures = 0
		st.probeIndex++
		if st.probeIndex >= len(mtuProbeSizes) {
			st.status = "NO_VERIFIED_MTU"
			// Do not infer a working path from a failed local send or assume
			// that 576 bytes must be deliverable in a blocked real network.
		}
	}
}
func (a *Agent) mtuStatus() (string, int) {
	switch a.link.Spoof.PrivateMTU.Mode {
	case domain.MTUManual:
		return "MANUAL_UNVERIFIED", 0
	case domain.MTUAuto:
		if a.mtuState.status != "" {
			return a.mtuState.status, a.mtuState.confirmed
		}
		return "NOT_YET_PROBED", 0
	default:
		return "LEGACY_FIXED", 0
	}
}
