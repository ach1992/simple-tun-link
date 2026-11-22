//go:build linux

package spoofhost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// RuntimeStatus is diagnostic evidence written by the original helper.
// A locally started helper is not evidence of a viable remote session.
type RuntimeStatus struct {
	SchemaVersion          int           `json:"schema_version"`
	LinkID                 domain.LinkID `json:"link_id"`
	PID                    int           `json:"pid"`
	State                  string        `json:"state"`
	SelectedSource         string        `json:"selected_source,omitempty"`
	SelectedProfile        string        `json:"selected_profile,omitempty"`
	SelectedDestination    string        `json:"selected_destination,omitempty"`
	RecentWorkingPaths     int           `json:"recent_working_paths"`
	ScannedProbes          uint64        `json:"scanned_probes"`
	SelectedRTTMs          float64       `json:"selected_rtt_ms,omitempty"`
	SelectedJitterMs       float64       `json:"selected_jitter_ms,omitempty"`
	SelectedLossPercent    float64       `json:"selected_loss_percent,omitempty"`
	TunnelMTU              int           `json:"tunnel_mtu,omitempty"`
	MTUStatus              string        `json:"mtu_status,omitempty"`
	VerifiedMTU            int           `json:"verified_mtu,omitempty"`
	UnackedProbes          int           `json:"unacked_probes"`
	RecoveryStage          string        `json:"recovery_stage,omitempty"`
	ActiveReceiveProfiles  []string      `json:"active_receive_profiles,omitempty"`
	UnavailableReceivers   []string      `json:"unavailable_receivers,omitempty"`
	SourceCandidates       int           `json:"source_candidates"`
	SourceScanPosition     int           `json:"source_scan_position"`
	SourceScanProfileIndex int           `json:"source_scan_profile_index"`
	SourceScanPasses       uint64        `json:"source_scan_passes"`
	Authenticated          bool          `json:"authenticated"`
	BilateralConfirmed     bool          `json:"bilateral_confirmed"`
	SentPrivatePackets     uint64        `json:"sent_private_packets"`
	ReceivedPrivatePackets uint64        `json:"received_private_packets"`
	LastError              string        `json:"last_error,omitempty"`
	UpdatedAt              time.Time     `json:"updated_at"`
	LastAuthenticatedAt    time.Time     `json:"last_authenticated_at,omitempty"`
}
type Agent struct {
	root                 string
	link                 domain.Link
	material             Material
	tun                  *carrier.PrivateTUN
	receiver             carrier.FrameReceiver
	sender               *carrier.RawSender
	inventory            carrier.Inventory
	cursor               carrier.DiscoveryCursor
	chosen               netip.Addr
	chosenProfile        string
	chosenDestination    netip.AddrPort
	profiles             []string
	historicalPaths      []carrier.SourcePath
	quality              pathQualityState
	mtuState             adaptiveMTUState
	probes               map[uint64]pendingProbe
	lastDiscoveryBudget  time.Time
	lastBackgroundBudget time.Time
	discoveryCredits     float64
	backgroundCredits    float64
	backgroundCounter    uint64
	backupPosition       int
	warmPaths            []carrier.SourcePath
	warmPosition         int
	warmPass             int
	warmEnabled          bool
	stage                string
	handshake            *carrier.Handshake
	session              *carrier.Session
	attempt              [16]byte
	pendingKind          carrier.FrameKind
	pendingPayload       []byte
	pendingAt            time.Time
	lastAuth             time.Time
	lastSelectedProbeAck time.Time
	lastSentKeepalive    time.Time
	lastPendingSend      time.Time
	lastSourceRefresh    time.Time
	connected            bool
	bindPeer             func(*carrier.Session) error
	status               RuntimeStatus
}

func newAgent(root string, link domain.Link, material Material, bind func(*carrier.Session) error) *Agent {
	return &Agent{root: root, link: link, material: material, bindPeer: bind,
		status: RuntimeStatus{SchemaVersion: 1, LinkID: link.ID, PID: os.Getpid(), State: "WAITING_FOR_PEER"}}
}
func (a *Agent) localEndpoint() netip.AddrPort {
	bind := a.link.Spoof.BindIPv4
	if !bind.IsValid() {
		bind = a.link.Underlay.Local
	}
	return netip.AddrPortFrom(bind, a.link.Spoof.ListenPort)
}
func (a *Agent) peerEndpoint() netip.AddrPort {
	return netip.AddrPortFrom(a.link.Underlay.Peer, a.link.Spoof.PeerPort)
}
func (a *Agent) peerEndpoints() []netip.AddrPort {
	primary := a.peerEndpoint()
	more, _ := domain.ParseSpoofAlternates(a.link.Spoof.PeerAlternates, primary)
	return append([]netip.AddrPort{primary}, more...)
}
func (a *Agent) localEndpoints() []netip.AddrPort {
	primary := a.localEndpoint()
	more, _ := domain.ParseSpoofAlternates(a.link.Spoof.LocalAlternates, primary)
	return append([]netip.AddrPort{primary}, more...)
}
func (a *Agent) allowedDestination(ep netip.AddrPort) bool {
	if !ep.IsValid() {
		return true
	} // pre-extension primary history
	return slices.Contains(a.peerEndpoints(), ep)
}
func (a *Agent) effectiveDestination(ep netip.AddrPort) netip.AddrPort {
	if ep.IsValid() {
		return ep
	}
	return a.peerEndpoint()
}
func (a *Agent) handshakeConfig(attempt [16]byte) carrier.HandshakeConfig {
	creator := netip.AddrPortFrom(a.link.Underlay.Local, a.link.Spoof.ListenPort)
	recipient := a.peerEndpoint()
	aIP, bIP := a.link.Addresses.Local.Addr(), a.link.Addresses.Peer.Addr()
	creatorAlts, recipientAlts := a.link.Spoof.LocalAlternates, a.link.Spoof.PeerAlternates
	if a.material.Role() == "recipient" {
		creator, recipient = recipient, creator
		aIP, bIP = bIP, aIP
		creatorAlts, recipientAlts = recipientAlts, creatorAlts
	}
	c := carrier.HandshakeConfig{
		Role: carrier.Role(a.material.Role()), LinkID: a.link.ID, Attempt: attempt,
		CreatorEndpoint: creator, RecipientEndpoint: recipient,
		CreatorAlternates: creatorAlts, RecipientAlternates: recipientAlts,
		CreatorPrivateIP: aIP, RecipientPrivateIP: bIP,
		LocalPrivateKey: a.material.StaticPrivateKey(), BootstrapSecret: a.material.BootstrapKey(),
	}
	if a.material.Role() == "recipient" {
		public, err := decodePublic(a.link.Spoof.PeerPublicKey)
		if err == nil {
			c.PeerPublicKey = public[:]
		}
	}
	return c
}
func decodePublic(encoded string) ([32]byte, error) {
	var out [32]byte
	// This value has already passed domain Link validation.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return out, errors.New("invalid pinned Spoof public key")
	}
	copy(out[:], raw)
	return out, nil
}
func (a *Agent) record(err error) {
	if err != nil {
		a.status.LastError = err.Error()
		fmt.Fprintln(os.Stderr, "spoof link", a.link.ID, "diagnostic:", err)
	}
}
func (a *Agent) publishStatus() {
	if len(a.inventory.Addresses) == 0 || a.sender == nil {
		a.status.State = "NO_WORKING_PATH"
	} else if a.connected {
		a.status.State = "CONNECTED"
	} else if a.session != nil {
		if a.stage == "RETRY_PREVIOUSLY_WORKING" || a.stage == "EXHAUSTIVE_SOURCE_PROFILE_SCAN" {
			a.status.State = "RECONNECTING"
		} else {
			a.status.State = "AUTHENTICATING"
		}
	} else if a.handshake != nil {
		a.status.State = "DISCOVERING"
	} else {
		a.status.State = "WAITING_FOR_PEER"
	}
	a.status.SelectedSource = ""
	a.status.SelectedProfile = ""
	a.status.SelectedDestination = ""
	if a.chosen.IsValid() {
		a.status.SelectedSource = a.chosen.String()
		a.status.SelectedProfile = a.chosenProfile
		if a.chosenDestination.IsValid() {
			a.status.SelectedDestination = a.chosenDestination.String()
		}
	}
	a.status.RecentWorkingPaths = len(a.historicalPaths)
	a.status.UnackedProbes = len(a.probes)
	if a.tun != nil {
		a.status.TunnelMTU = a.tun.MTU()
	}
	a.status.MTUStatus, a.status.VerifiedMTU = a.mtuStatus()
	a.status.SelectedRTTMs, a.status.SelectedJitterMs, a.status.SelectedLossPercent = 0, 0, 0
	selected := carrier.SourcePath{Source: a.chosen, Profile: a.chosenProfile, Destination: a.chosenDestination}
	if q := a.quality.metrics[selected]; q != nil {
		a.status.SelectedRTTMs = q.RTTms
		a.status.SelectedJitterMs = q.Jitterms
		a.status.SelectedLossPercent = q.lossPercent()
	}
	a.status.RecoveryStage = a.stage
	a.status.SourceCandidates = len(a.inventory.Addresses)
	a.status.SourceScanPosition, a.status.SourceScanProfileIndex, a.status.SourceScanPasses = a.cursor.PathProgress()
	a.status.Authenticated = a.session != nil
	a.status.BilateralConfirmed = a.connected
	if !a.lastAuth.IsZero() {
		a.status.LastAuthenticatedAt = a.lastAuth.UTC()
	}
	a.status.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(a.status)
	if err != nil {
		a.record(err)
		return
	}
	filename, err := StatusPath(a.root, a.link.ID)
	if err != nil {
		a.record(err)
		return
	}
	dir := filepath.Dir(filename)
	f, err := os.CreateTemp(dir, ".spoof-status-*")
	if err != nil {
		a.record(err)
		return
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		a.record(err)
		return
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		a.record(err)
		return
	}
	if err = f.Close(); err != nil {
		a.record(err)
		return
	}
	if err = os.Rename(name, filename); err != nil {
		a.record(err)
	}
}
func ReadRuntimeStatus(root string, id domain.LinkID) (RuntimeStatus, error) {
	filename, err := StatusPath(root, id)
	if err != nil {
		return RuntimeStatus{}, err
	}
	fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return RuntimeStatus{}, err
	}
	file := os.NewFile(uintptr(fd), "spoof-status-readonly")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() < 1 || info.Size() > 8192 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return RuntimeStatus{}, errors.New("Spoof status untrusted file identity")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 {
		return RuntimeStatus{}, errors.New("Spoof status could not be read within size budget")
	}
	var v RuntimeStatus
	if json.Unmarshal(raw, &v) != nil || v.SchemaVersion != 1 || v.LinkID != id {
		return RuntimeStatus{}, errors.New("Spoof status schema/identity invalid")
	}
	return v, nil
}
func (a *Agent) refreshSources() {
	a.lastSourceRefresh = time.Now()
	inv, err := carrier.ReadSources(a.link.Spoof.SourceFile)
	if err != nil {
		if a.sender != nil {
			_ = a.sender.Close()
			a.sender = nil
		}
		a.inventory = carrier.Inventory{}
		_ = a.cursor.ReplaceInventory(a.inventory)
		a.chosen = netip.Addr{}
		a.chosenProfile = ""
		a.chosenDestination = netip.AddrPort{}
		if a.connected {
			a.beginRecovery()
			a.connected = false
			// Keep the original Noise session: local Source-file loss is not
			// evidence that the authenticated peer identity expired. This
			// permits prompt reconnection when a Source is restored.
		}
		a.record(err)
		return
	}
	if slices.Equal(inv.Addresses, a.inventory.Addresses) {
		a.inventory = inv
		return
	}
	openSender := carrier.OpenRawSender
	if a.link.Spoof.OuterProtocol == "icmp" {
		openSender = carrier.OpenICMPSender
	}
	replacement, err := openSender(a.peerEndpoint(), a.link.Spoof.ListenPort, inv, a.link.Spoof.Interface)
	if err == nil {
		err = replacement.AllowDestinations(a.peerEndpoints()[1:])
		if err != nil {
			_ = replacement.Close()
		}
	}
	if err != nil {
		a.record(err)
		if a.sender != nil {
			_ = a.sender.Close()
			a.sender = nil
		}
		a.inventory = carrier.Inventory{}
		_ = a.cursor.ReplaceInventory(a.inventory)
		return
	}
	old := a.sender
	a.sender = replacement
	a.inventory = inv
	if err := a.cursor.ReplaceInventory(inv); err != nil {
		a.record(err)
	}
	if !a.connected {
		a.beginRecovery()
	}
	if old != nil {
		_ = old.Close()
	}
	if a.chosen.IsValid() && !slices.Contains(inv.Addresses, a.chosen) {
		a.invalidateSelectedSource()
	}
}

// Source inventory and transport selection are independent from Noise
// identity. Losing an outgoing Source must not discard the existing
// authenticated session or force the peer to wait through a long reboot-
// tolerant liveness timeout before it can respond to fresh path probes.
func (a *Agent) invalidateSelectedSource() {
	a.beginRecovery()
	a.chosen = netip.Addr{}
	a.chosenProfile = ""
	a.chosenDestination = netip.AddrPort{}
	a.connected = false
	a.record(errors.New("previous selected Source disappeared; authenticating alternate routes in same Noise session"))
}

// The locally pinned profile is always honored. Auto is the only policy
// that actively tests/switches outer profiles on the same original Link.
func (a *Agent) enabledProfiles() []string {
	if len(a.profiles) > 0 {
		return a.profiles
	}
	policy := a.link.Spoof.OuterProtocol
	if a.link.Spoof.TxProfile != "" {
		policy = a.link.Spoof.TxProfile
	}
	profiles, err := carrier.TransmitProfiles(policy)
	if err != nil {
		return nil
	}
	a.profiles = profiles
	return profiles
}

func (a *Agent) beginRecovery() {
	a.warmPaths = a.warmPaths[:0]
	for _, path := range a.historicalPaths {
		if a.knownSource(path) {
			a.warmPaths = append(a.warmPaths, path)
		}
	}
	a.warmPosition = 0
	a.warmPass = 0
	a.warmEnabled = len(a.warmPaths) > 0
	if a.warmEnabled {
		a.stage = "RETRY_PREVIOUSLY_WORKING"
	} else {
		a.stage = "EXHAUSTIVE_SOURCE_PROFILE_SCAN"
	}
}

func (a *Agent) knownSource(path carrier.SourcePath) bool {
	if !path.Valid() || !a.cursor.Contains(path.Source) {
		return false
	}
	return slices.Contains(a.enabledProfiles(), path.Profile) && a.allowedDestination(path.Destination)
}

func (a *Agent) sendSelected(encoded []byte) error {
	if a.sender == nil {
		return errors.New("local Source file unavailable")
	}
	if a.chosen.IsValid() && a.chosenProfile != "" {
		return a.sender.SendProfileTo(a.chosen, a.chosenProfile, a.effectiveDestination(a.chosenDestination), encoded)
	}
	return a.sendCandidates(encoded)
}

func (a *Agent) nextCandidatePaths() ([]carrier.SourcePath, error) {
	return a.nextCandidatePathsWithBudget(carrier.DiscoveryBatchSize(len(a.inventory.Addresses)))
}
func (a *Agent) nextCandidatePathsWithBudget(budget int) ([]carrier.SourcePath, error) {
	if budget == 0 {
		return nil, errors.New("no local Source candidates")
	}
	// Each retained path is tried up to three times in separate passes
	// before falling back to the complete inventory x profile matrix.
	// "Three" is NOT a failure ceiling or a permanent disqualification:
	// complete scans repeat indefinitely, even for these same paths.
	if a.warmEnabled {
		if len(a.warmPaths) > 0 && a.warmPass < 3 {
			left := min(budget, len(a.warmPaths)-a.warmPosition)
			paths := append([]carrier.SourcePath(nil), a.warmPaths[a.warmPosition:a.warmPosition+left]...)
			a.warmPosition += left
			if a.warmPosition >= len(a.warmPaths) {
				a.warmPosition = 0
				a.warmPass++
			}
			a.stage = "RETRY_PREVIOUSLY_WORKING"
			return paths, nil
		}
		a.warmEnabled = false
	}
	a.stage = "EXHAUSTIVE_SOURCE_PROFILE_SCAN"
	return a.cursor.NextRouteBatch(a.enabledProfiles(), a.peerEndpoints(), budget)
}

func (a *Agent) sendCandidates(encoded []byte) error {
	if a.sender == nil {
		return errors.New("raw source sender unavailable")
	}
	budget := a.scanBudget(time.Now(), false)
	if budget == 0 {
		return nil
	}
	paths, err := a.nextCandidatePathsWithBudget(budget)
	if err != nil {
		return err
	}
	var first error
	sent := 0
	for _, path := range paths {
		if sent > 0 && len(paths) > 8 {
			time.Sleep(time.Millisecond)
		}
		if e := a.sender.SendProfileTo(path.Source, path.Profile, a.effectiveDestination(path.Destination), encoded); e != nil && first == nil {
			first = e
		}
		sent++
	}
	return first
}

func (a *Agent) confirmedPath(path carrier.SourcePath) bool {
	if !a.knownSource(path) {
		return false
	}
	a.chosen = path.Source
	a.chosenProfile = path.Profile
	a.chosenDestination = a.effectiveDestination(path.Destination)
	a.cursor.PreferredSucceeded(path.Source)
	return true
}

func (a *Agent) rememberCurrentPath() {
	path := carrier.SourcePath{Source: a.chosen, Profile: a.chosenProfile, Destination: a.chosenDestination}
	a.rememberVerifiedPath(path)
}

// applyAuthenticatedHint supports the original (Source,profile) feedback and
// the exact destination-bearing authenticated feedback. It is used only
// during initial bilateral confirmation; background quality probes have a
// separately verified nonce and never mutate the selected route blindly.
func (a *Agent) applyAuthenticatedHint(payload []byte) bool {
	if len(payload) == 4 {
		legacy := append(append([]byte(nil), payload...), carrier.ProfileID(a.link.Spoof.OuterProtocol))
		if a.link.Spoof.OuterProtocol == "" {
			legacy[4] = carrier.ProfileID(carrier.ProfileUDP)
		}
		payload = legacy
	}
	route, ok := a.decodeObservedRoute(payload)
	return ok && a.confirmedPath(route)
}

func (a *Agent) sendPending() error {
	if a.pendingPayload == nil {
		return nil
	}
	encoded, err := (carrier.Frame{LinkID: a.link.ID, Attempt: a.attempt,
		Kind: a.pendingKind, Payload: a.pendingPayload}).Encode()
	if err != nil {
		return err
	}
	a.lastPendingSend = time.Now()
	return a.sendCandidates(encoded)
}
func (a *Agent) startRecipient() error {
	if a.material.Role() != "recipient" {
		return nil
	}
	attempt, err := carrier.NewAttempt()
	if err != nil {
		return err
	}
	h, err := carrier.NewHandshake(a.handshakeConfig(attempt))
	if err != nil {
		return err
	}
	first, err := h.Start()
	if err != nil {
		return err
	}
	a.attempt = attempt
	a.handshake = h
	a.session = nil
	a.connected = false
	a.pendingAt = time.Now()
	a.lastPendingSend = time.Time{}
	a.pendingKind = carrier.KindHandshake1
	a.pendingPayload = first
	a.chosen = netip.Addr{}
	a.chosenProfile = ""
	a.chosenDestination = netip.AddrPort{}
	return a.sendPending()
}
func (a *Agent) forgetHandshake() {
	a.session = nil
	a.handshake = nil
	a.connected = false
	a.pendingPayload = nil
	a.lastPendingSend = time.Time{}
	a.chosen = netip.Addr{}
	a.chosenProfile = ""
	a.chosenDestination = netip.AddrPort{}
}
func (a *Agent) received(frame carrier.Frame, outer netip.AddrPort, outerProfile string) error {
	return a.receivedTo(frame, outer, a.localEndpoint(), outerProfile)
}
func (a *Agent) receivedTo(frame carrier.Frame, outer, realDestination netip.AddrPort, outerProfile string) error {
	if frame.LinkID != a.link.ID {
		return nil
	}
	if a.material.Role() == "creator" && frame.Kind == carrier.KindHandshake1 {
		if len(a.inventory.Addresses) == 0 || a.sender == nil {
			return nil
		}
		if a.connected && time.Since(a.lastAuth) < 8*time.Second {
			return nil
		}
		// A retry with the same Attempt must not rewrite the transcript.
		if a.handshake != nil && frame.Attempt == a.attempt {
			if time.Since(a.lastPendingSend) < 500*time.Millisecond {
				return nil
			}
			return a.sendPending()
		}
		h, err := carrier.NewHandshake(a.handshakeConfig(frame.Attempt))
		if err != nil {
			return err
		}
		reply, _, err := h.Handle(frame.Payload)
		if err != nil {
			return nil
		}
		// A fresh authenticated-enrollment attempt MUST discard the
		// previously confirmed outward Source. The old source may still
		// appear in sources.txt while its actual network path is dead.
		// Re-probe the bounded local inventory until an authenticated
		// KeepaliveAck identifies a working outgoing Source.
		if a.connected {
			a.beginRecovery()
		}
		a.chosen = netip.Addr{}
		a.chosenProfile = ""
		a.chosenDestination = netip.AddrPort{}
		a.handshake = h
		a.attempt = frame.Attempt
		a.pendingKind = carrier.KindHandshake2
		a.pendingPayload = reply
		a.pendingAt = time.Now()
		a.lastPendingSend = time.Time{}
		a.session = nil
		a.connected = false
		return a.sendPending()
	}
	if a.handshake != nil && frame.Attempt == a.attempt {
		if a.material.Role() == "recipient" && frame.Kind == carrier.KindHandshake2 && a.pendingKind == carrier.KindHandshake1 {
			reply, session, err := a.handshake.Handle(frame.Payload)
			if err != nil {
				return nil
			}
			a.session = session
			a.pendingKind = carrier.KindHandshake3
			a.pendingPayload = reply
			a.pendingAt = time.Now()
			// The other endpoint's claimed Source cannot be our own
			// transmitted-Source hint. Only authenticated feedback later
			// tells this endpoint which local Source/profile reached it.
			return a.sendPending()
		}
		if a.material.Role() == "creator" && frame.Kind == carrier.KindHandshake3 && a.pendingKind == carrier.KindHandshake2 {
			_, session, err := a.handshake.Handle(frame.Payload)
			if err != nil {
				return nil
			}
			// A may bind a previously unknown B only through the canonical Engine.
			// Do not accept private packet data before durable peer identity binding.
			if a.bindPeer == nil {
				return errors.New("Spoof creator Engine peer-binding callback missing")
			}
			if err = a.bindPeer(session); err != nil {
				return fmt.Errorf("Spoof authenticated enrollment: %w", err)
			}
			a.session = session
			a.pendingPayload = nil
			a.lastAuth = time.Now()
			return a.sendObservedControl(carrier.KindKeepalive, outer.Addr(), outerProfile, realDestination)
		}
	}
	if a.session == nil {
		return nil
	}
	kind, plain, err := a.session.OpenEncoded(frame)
	if err != nil {
		return nil
	}
	a.lastAuth = time.Now()
	if !a.connected && kind == carrier.KindData {
		return nil
	} // don't advertise an unconfirmed path
	switch kind {
	case carrier.KindKeepalive:
		if len(plain) == 8 || (len(plain) >= 576 && len(plain) <= 1280) {
			// MTU probes carry large authenticated padding, but only their
			// first eight bytes are the nonce to acknowledge. Echoing the
			// entire padding fails validation and would make PMTU always fail.
			if err = a.sendObservedControlWithNonce(carrier.KindKeepaliveAck, outer.Addr(), outerProfile, realDestination, plain[:8]); err != nil {
				return err
			}
		} else {
			if !a.connected {
				a.applyAuthenticatedHint(plain)
			}
			if err = a.sendObservedControl(carrier.KindKeepaliveAck, outer.Addr(), outerProfile, realDestination); err != nil {
				return err
			}
		}
	case carrier.KindKeepaliveAck:
		if len(plain) == 19 {
			a.handleProbeAck(plain)
		} else if !a.connected && a.applyAuthenticatedHint(plain) {
			a.rememberCurrentPath()
			a.connected = true
			a.lastSelectedProbeAck = time.Now()
			a.stage = "CONNECTED"
			a.status.LastError = ""
			fmt.Fprintln(os.Stderr, "spoof link", a.link.ID,
				"authenticated bilateral path confirmed:", a.chosen, a.chosenProfile, a.chosenDestination)
			if err = a.sendObservedControl(carrier.KindKeepaliveAck, outer.Addr(), outerProfile, realDestination); err != nil {
				return err
			}
		}
	case carrier.KindData:
		if err = a.tun.WritePacket(context.Background(), plain); err != nil {
			return err
		}
		a.status.ReceivedPrivatePackets++
	}
	return nil
}
func (a *Agent) sendControl(kind carrier.FrameKind, observedPeerSource netip.Addr, observedProfile string) error {
	return a.sendObservedControl(kind, observedPeerSource, observedProfile, netip.AddrPort{})
}
func (a *Agent) sendObservedControl(kind carrier.FrameKind, observedPeerSource netip.Addr,
	observedProfile string, observedRealDestination netip.AddrPort) error {
	return a.sendObservedControlWithNonce(kind, observedPeerSource, observedProfile, observedRealDestination, nil)
}
func (a *Agent) sendObservedControlWithNonce(kind carrier.FrameKind, observedPeerSource netip.Addr,
	observedProfile string, observedRealDestination netip.AddrPort, nonce []byte) error {
	if a.session == nil {
		return nil
	}
	// The observation is exchanged only inside Noise AEAD. The receiver
	// verifies it belongs to its own CURRENT source inventory and enabled
	// TX policy before selecting it. The hint is not an identity.
	payload := make([]byte, 5)
	if observedRealDestination.IsValid() {
		payload = make([]byte, 11)
	}
	if observedPeerSource.Is4() {
		copy(payload, observedPeerSource.AsSlice())
	}
	payload[4] = carrier.ProfileID(observedProfile)
	if observedRealDestination.IsValid() {
		copy(payload[5:9], observedRealDestination.Addr().AsSlice())
		payload[9] = byte(observedRealDestination.Port() >> 8)
		payload[10] = byte(observedRealDestination.Port())
	}
	if len(nonce) != 0 {
		if len(nonce) != 8 || !observedRealDestination.IsValid() {
			return errors.New("invalid authenticated path probe acknowledgement")
		}
		payload = append(payload, nonce...)
	}
	encrypted, err := a.session.Seal(kind, payload)
	if err != nil {
		return err
	}
	return a.sendSelected(encrypted)
}

// An active outward route must have its own authenticated round-trip proof.
// Other incoming authenticated traffic is not evidence that this path works.
func (a *Agent) activeRouteUnresponsive(now time.Time) bool {
	if !a.connected {
		return false
	}
	return (!a.lastAuth.IsZero() && now.Sub(a.lastAuth) > 8*time.Second) ||
		(!a.lastSelectedProbeAck.IsZero() && now.Sub(a.lastSelectedProbeAck) > 11*time.Second)
}

func (a *Agent) tick() {
	now := time.Now()
	if time.Since(a.lastSourceRefresh) >= 2*time.Second {
		a.refreshSources()
	}
	a.reapProbeTimeouts(now)
	if len(a.inventory.Addresses) == 0 || a.sender == nil {
		return
	}
	if a.session != nil && !a.lastAuth.IsZero() {
		silence := now.Sub(a.lastAuth)
		// Begin recovery early, but keep the authenticated session and
		// try backups while a rebooted/CPU-saturated peer is recovering.
		if a.activeRouteUnresponsive(now) {
			a.connected = false
			a.beginRecovery()
			// Receiving other authenticated packets is not proof that the
			// currently selected outgoing route can still reach the peer.
			a.chosen = netip.Addr{}
			a.chosenProfile = ""
			a.chosenDestination = netip.AddrPort{}
			a.record(errors.New("selected Spoof path lost authenticated round-trip evidence; probing historical backups"))
		}
		if !a.connected {
			if silence < 60*time.Second {
				a.recoveryProbeTick(now)
				return
			}
			a.record(errors.New("peer remains unreachable; initiating fresh authenticated Noise exchange without re-pair"))
			a.forgetHandshake()
			a.beginRecovery()
		} else {
			if now.Sub(a.lastSentKeepalive) >= 3*time.Second {
				a.lastSentKeepalive = now
				selected := carrier.SourcePath{Source: a.chosen, Profile: a.chosenProfile, Destination: a.chosenDestination}
				if err := a.sendProbe(selected); err != nil {
					a.record(err)
				}
			}
			a.backgroundProbeTick(now)
			a.autoMTUTick(now)
			return
		}
	}
	if a.material.Role() == "recipient" && a.handshake == nil {
		if err := a.startRecipient(); err != nil {
			a.record(err)
		}
		return
	}
	if a.handshake != nil && now.Sub(a.pendingAt) > 13*time.Second {
		a.forgetHandshake()
		if a.material.Role() == "recipient" {
			if err := a.startRecipient(); err != nil {
				a.record(err)
			}
		}
		return
	}
	if a.pendingPayload != nil {
		if err := a.sendPending(); err != nil {
			a.record(err)
		}
	}
	if a.session != nil && now.Sub(a.lastSentKeepalive) > 800*time.Millisecond {
		a.lastSentKeepalive = now
		if err := a.sendControl(carrier.KindKeepalive, netip.Addr{}, ""); err != nil {
			a.record(err)
		}
	}
}

type receivedFrame struct {
	frame           carrier.Frame
	outer           netip.AddrPort
	realDestination netip.AddrPort
	profile         string
}

func (a *Agent) run(ctx context.Context) error {
	initialMTU := 1280
	if a.link.Spoof.PrivateMTU.Mode == domain.MTUManual {
		initialMTU = a.link.Spoof.PrivateMTU.Bytes
	}
	tun, err := carrier.OpenPrivateTUN(ctx, a.link.ID, initialMTU, a.link.Addresses.Local.Addr(), a.link.Addresses.Peer.Addr())
	if err != nil {
		return err
	}
	a.tun = tun
	defer tun.Close()
	var receiver carrier.FrameReceiver
	if len(a.localEndpoints()) == 1 {
		receiver, err = carrier.OpenFrameReceiver(a.localEndpoint(), a.link.Spoof.OuterProtocol, a.link.Spoof.Interface)
	} else {
		receiver, err = carrier.OpenMultiEndpointReceiver(a.localEndpoints(), a.link.Spoof.OuterProtocol, a.link.Spoof.Interface)
	}
	if err != nil {
		return err
	}
	a.receiver = receiver
	defer receiver.Close()
	defer func() {
		if a.sender != nil {
			_ = a.sender.Close()
		}
	}()
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	history, historyErr := readHistory(a.root, a.link.ID)
	if historyErr != nil {
		a.record(fmt.Errorf("load prior confirmed Spoof paths: %w", historyErr))
	}
	a.historicalPaths = history
	if len(history) > 0 {
		a.beginRecovery()
	}
	if r, ok := receiver.(interface {
		AvailableProfiles() []string
		FailedProfiles() []string
	}); ok {
		a.status.ActiveReceiveProfiles = r.AvailableProfiles()
		a.status.UnavailableReceivers = r.FailedProfiles()
		if len(a.status.UnavailableReceivers) > 0 {
			fmt.Fprintln(os.Stderr, "spoof link", a.link.ID, "unavailable auto receive profiles:", a.status.UnavailableReceivers)
		}
	} else {
		profile := a.link.Spoof.OuterProtocol
		if profile == "" {
			profile = carrier.ProfileUDP
		}
		a.status.ActiveReceiveProfiles = []string{profile}
	}
	a.refreshSources()
	a.publishStatus()
	defer func() { a.connected = false; a.status.State = "STOPPED"; a.publishStatus() }()
	packets := make(chan []byte, 128)
	frames := make(chan receivedFrame, 128)
	readErrors := make(chan error, 2)
	go func() {
		for ctx.Err() == nil {
			packet, err := tun.ReadPacket(ctx)
			if err != nil {
				if ctx.Err() == nil {
					select {
					case readErrors <- err:
					default:
					}
				}
				return
			}
			select {
			case packets <- packet:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for ctx.Err() == nil {
			_ = receiver.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			var n int
			var outer netip.AddrPort
			var outerProfile string
			var err error
			realDestination := a.localEndpoint()
			if rp, ok := receiver.(carrier.PathFrameReceiver); ok {
				n, outer, realDestination, outerProfile, err = rp.ReadPathFrame(buffer)
			} else if rp, ok := receiver.(carrier.ProfileFrameReceiver); ok {
				n, outer, outerProfile, err = rp.ReadProfileFrame(buffer)
			} else {
				n, outer, err = receiver.ReadFrame(buffer)
				outerProfile = a.link.Spoof.OuterProtocol
				if outerProfile == "" {
					outerProfile = carrier.ProfileUDP
				}
			}
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				if ctx.Err() == nil {
					select {
					case readErrors <- fmt.Errorf("real Spoof receive socket: %w", err):
					default:
					}
				}
				return
			}
			frame, err := carrier.DecodeFrame(buffer[:n])
			if err != nil || frame.LinkID != a.link.ID {
				continue
			}
			select {
			case frames <- receivedFrame{frame: frame, outer: outer, realDestination: realDestination, profile: outerProfile}:
			case <-ctx.Done():
				return
			}
		}
	}()
	tick := time.NewTicker(700 * time.Millisecond)
	defer tick.Stop()
	report := time.NewTicker(2 * time.Second)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-readErrors:
			return fmt.Errorf("Spoof helper reader: %w", err)
		case packet := <-packets:
			if !a.connected || a.session == nil {
				continue
			}
			encoded, err := a.session.Seal(carrier.KindData, packet)
			if err != nil {
				a.record(err)
				continue
			}
			if err = a.sendSelected(encoded); err != nil {
				a.record(err)
				continue
			}
			a.status.SentPrivatePackets++
		case incoming := <-frames:
			if err = a.receivedTo(incoming.frame, incoming.outer, incoming.realDestination, incoming.profile); err != nil {
				a.record(err)
			}
		case <-tick.C:
			a.tick()
		case <-report.C:
			a.publishStatus()
		}
	}
}

// RunAgent runs a per-Link managed helper under the original transient
// systemd service. It cannot create or commit an independent Link/state.
func RunAgent(ctx context.Context, root string, id domain.LinkID, bindPeer func(*carrier.Session) error) error {
	conf, err := ReadConfig(root, id)
	if err != nil {
		return err
	}
	material, _, err := ReadMaterial(root, id, conf.Link.Spoof.MaterialSHA256)
	if err != nil {
		return err
	}
	if err = ConfirmLocalIdentity(conf.Link, material); err != nil {
		return err
	}
	if material.Role() == "creator" && bindPeer == nil {
		return errors.New("Spoof creator helper lacks canonical Engine binding")
	}
	return newAgent(root, conf.Link, material, bindPeer).run(ctx)
}
