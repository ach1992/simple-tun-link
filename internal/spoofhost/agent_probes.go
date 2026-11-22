//go:build linux

package spoofhost

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

type pendingProbe struct {
	path    carrier.SourcePath
	sent    time.Time
	mtuSize int
}

// Probe nonces are AEAD-authenticated and session-local. Exact responses
// prove that this endpoint's own chosen Source/profile/real destination got
// to the actual paired peer; an unverified outer header proves nothing.
func (a *Agent) sendProbe(route carrier.SourcePath) error {
	return a.sendSizedProbe(route, 0)
}
func (a *Agent) sendMTUProbe(route carrier.SourcePath, innerMTU int) error {
	if innerMTU < 576 || innerMTU > 1280 {
		return errors.New("MTU probe outside supported candidate window")
	}
	return a.sendSizedProbe(route, innerMTU)
}
func (a *Agent) sendSizedProbe(route carrier.SourcePath, innerMTU int) error {
	if a.session == nil || a.sender == nil || !a.knownSource(route) {
		return nil
	}
	// In-flight probes must be sized for the operator-configured packet
	// rate and the 7-second acknowledgement window, otherwise a simple
	// Source rotation fills an arbitrary 96-packet cap before the complete
	// Source/profile/destination matrix can be attempted.
	rate := max(a.discoveryRate(), a.backgroundRate())
	maxInt := int(^uint(0) >> 1)
	limit := maxInt
	if rate <= (maxInt-128)/7 {
		limit = 128 + 7*rate
	}
	if len(a.probes) >= limit {
		return errors.New("authenticated Spoof probe window full at configured packet rate; pending acknowledgements must expire")
	}
	if a.probes == nil {
		a.probes = make(map[uint64]pendingProbe)
	}
	route.Destination = a.effectiveDestination(route.Destination)
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := binary.BigEndian.Uint64(nonce[:])
	if id == 0 {
		return errors.New("invalid probe nonce")
	}
	payload := nonce[:]
	if innerMTU > 0 {
		// An inner IPv4 datagram of length N and this N-byte authenticated
		// Keepalive have the same encrypted outer wire size.
		full := make([]byte, innerMTU)
		copy(full, nonce[:])
		payload = full
	}
	encoded, err := a.session.Seal(carrier.KindKeepalive, payload)
	if err != nil {
		return err
	}
	now := time.Now()
	a.probes[id] = pendingProbe{path: route, sent: now, mtuSize: innerMTU}
	if innerMTU > 0 {
		err = a.sender.SendProbeDFTo(route.Source, route.Profile, route.Destination, encoded)
	} else {
		err = a.sender.SendProfileTo(route.Source, route.Profile, route.Destination, encoded)
	}
	if err != nil {
		delete(a.probes, id)
		return err
	}
	a.status.ScannedProbes++
	return nil
}

// decodeObservedRoute decodes only authenticated peer feedback. An endpoint
// absent from the operator's immutable pairing or removed local Source list
// is never eligible, even if the sender claimed the observation.
func (a *Agent) decodeObservedRoute(payload []byte) (carrier.SourcePath, bool) {
	if len(payload) != 5 && len(payload) != 11 && len(payload) != 19 {
		return carrier.SourcePath{}, false
	}
	address, ok := netip.AddrFromSlice(payload[:4])
	if !ok || !address.Is4() {
		return carrier.SourcePath{}, false
	}
	path := carrier.SourcePath{Source: address, Profile: carrier.ProfileFromID(payload[4]), Destination: a.peerEndpoint()}
	if len(payload) >= 11 {
		dst, ok := netip.AddrFromSlice(payload[5:9])
		if !ok {
			return carrier.SourcePath{}, false
		}
		path.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(payload[9:11]))
	}
	return path, a.knownSource(path)
}

func (a *Agent) rememberVerifiedPath(path carrier.SourcePath) {
	if !a.knownSource(path) {
		return
	}
	path.Destination = a.effectiveDestination(path.Destination)
	updated, changed := rememberPath(a.historicalPaths, path)
	if !changed {
		return
	}
	a.historicalPaths = updated
	if err := writeHistory(a.root, a.link.ID, updated); err != nil {
		a.record(fmt.Errorf("persist confirmed Spoof backup route: %w", err))
	}
}

func (a *Agent) handleProbeAck(payload []byte) bool {
	if len(payload) != 19 {
		return false
	}
	id := binary.BigEndian.Uint64(payload[11:19])
	pending, ok := a.probes[id]
	if !ok {
		return false
	}
	delete(a.probes, id)
	route, valid := a.decodeObservedRoute(payload)
	if !valid || pending.path != route {
		return false
	}
	now := time.Now()
	a.quality.reportSuccess(route, now.Sub(pending.sent), now)
	if pending.mtuSize > 0 {
		a.handleMTUReply(pending.mtuSize, route, now)
	}
	a.rememberVerifiedPath(route)
	chosen := carrier.SourcePath{Source: a.chosen, Profile: a.chosenProfile, Destination: a.chosenDestination}
	if a.connected && route == chosen {
		a.lastSelectedProbeAck = now
	}
	if !a.connected {
		if a.confirmedPath(route) {
			a.connected = true
			a.lastSelectedProbeAck = now
			a.stage = "CONNECTED"
			a.status.LastError = ""
			a.quality.switched(now)
			fmt.Fprintln(a.diagnosticOutput(), "spoof link", a.link.ID, "authenticated previously unresponsive path restored:", route)
			return true
		}
	} else if a.quality.shouldSwitch(chosen, route, now) && a.confirmedPath(route) {
		a.quality.switched(now)
		a.lastSelectedProbeAck = now
		a.stage = "CONNECTED"
		fmt.Fprintln(a.diagnosticOutput(), "spoof link", a.link.ID, "quality-confirmed better path:", route)
	}
	return true
}

// diagnosticOutput remains stderr (not stdout/status), same as other agent
// logging. Kept explicit for reuse in bounded recovery transitions.
func (a *Agent) diagnosticOutput() *os.File { return os.Stderr }

func (a *Agent) reapProbeTimeouts(now time.Time) {
	for nonce, record := range a.probes {
		if now.Sub(record.sent) >= 7*time.Second {
			delete(a.probes, nonce)
			if record.mtuSize > 0 {
				a.handleMTUMiss(record.mtuSize, record.path, now)
			} else {
				a.quality.reportMiss(record.path)
			}
		}
	}
}

// An adaptive rate is per enabled Link, not a restriction on Source-file
// size. Zero configuration selects a documented bounded default.
func (a *Agent) discoveryRate() int {
	if a.link.Spoof.DiscoveryPPS > 0 {
		return a.link.Spoof.DiscoveryPPS
	}
	return 64
}
func (a *Agent) backgroundRate() int {
	if a.link.Spoof.BackgroundPPS > 0 {
		return a.link.Spoof.BackgroundPPS
	}
	return 6
}
func (a *Agent) scanBudget(now time.Time, background bool) int {
	rate := a.discoveryRate()
	last := &a.lastDiscoveryBudget
	credit := &a.discoveryCredits
	maxBurst := 128.0
	if background {
		rate = a.backgroundRate()
		last = &a.lastBackgroundBudget
		credit = &a.backgroundCredits
		maxBurst = 16.0
	}
	if last.IsZero() {
		*last = now.Add(-700 * time.Millisecond)
	}
	elapsed := now.Sub(*last)
	*last = now
	if elapsed < 0 {
		elapsed = 0
	}
	// Rate and burst are independent; stale timer wakeups do not dump
	// unlimited packets after suspend/reboot/high-CPU pauses.
	*credit += elapsed.Seconds() * float64(rate)
	if *credit > maxBurst {
		*credit = maxBurst
	}
	budget := int(*credit)
	*credit -= float64(budget)
	return budget
}
func (a *Agent) backgroundProbeTick(now time.Time) {
	if a.sender == nil || a.session == nil {
		return
	}
	budget := a.scanBudget(now, true)
	for i := 0; i < budget; i++ {
		var route carrier.SourcePath
		// Retest remembered backups periodically, not only once per huge
		// full Source x profile x destination traversal.
		if len(a.historicalPaths) > 1 && a.backgroundCounter%4 == 0 {
			route = a.historicalPaths[a.backupPosition%len(a.historicalPaths)]
			a.backupPosition++
		} else {
			choices, err := a.cursor.NextRouteBatch(a.enabledProfiles(), a.peerEndpoints(), 1)
			if err != nil {
				a.record(err)
				return
			}
			route = choices[0]
		}
		a.backgroundCounter++
		if !a.knownSource(route) {
			continue
		}
		route.Destination = a.effectiveDestination(route.Destination)
		if route.Source == a.chosen && route.Profile == a.chosenProfile &&
			route.Destination == a.chosenDestination {
			continue
		}
		if err := a.sendProbe(route); err != nil {
			a.status.LastError = fmt.Sprint("background probe: ", err)
		}
	}
}
func (a *Agent) recoveryProbeTick(now time.Time) {
	if a.session == nil || a.sender == nil {
		return
	}
	budget := a.scanBudget(now, false)
	if budget == 0 {
		return
	}
	paths, err := a.nextCandidatePathsWithBudget(budget)
	if err != nil {
		a.record(err)
		return
	}
	for _, route := range paths {
		if err = a.sendProbe(route); err != nil {
			a.status.LastError = fmt.Sprint("recovery probe: ", err)
		}
	}
}
