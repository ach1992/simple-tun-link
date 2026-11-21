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
	SourceCandidates       int           `json:"source_candidates"`
	Authenticated          bool          `json:"authenticated"`
	BilateralConfirmed     bool          `json:"bilateral_confirmed"`
	SentPrivatePackets     uint64        `json:"sent_private_packets"`
	ReceivedPrivatePackets uint64        `json:"received_private_packets"`
	LastError              string        `json:"last_error,omitempty"`
	UpdatedAt              time.Time     `json:"updated_at"`
	LastAuthenticatedAt    time.Time     `json:"last_authenticated_at,omitempty"`
}
type Agent struct {
	root              string
	link              domain.Link
	material          Material
	tun               *carrier.PrivateTUN
	receiver          *net.UDPConn
	sender            *carrier.RawSender
	inventory         carrier.Inventory
	cursor            carrier.DiscoveryCursor
	chosen            netip.Addr
	handshake         *carrier.Handshake
	session           *carrier.Session
	attempt           [16]byte
	pendingKind       carrier.FrameKind
	pendingPayload    []byte
	pendingAt         time.Time
	lastAuth          time.Time
	lastSentKeepalive time.Time
	lastSourceRefresh time.Time
	connected         bool
	bindPeer          func(*carrier.Session) error
	status            RuntimeStatus
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
func (a *Agent) handshakeConfig(attempt [16]byte) carrier.HandshakeConfig {
	creator := netip.AddrPortFrom(a.link.Underlay.Local, a.link.Spoof.ListenPort)
	recipient := a.peerEndpoint()
	aIP, bIP := a.link.Addresses.Local.Addr(), a.link.Addresses.Peer.Addr()
	if a.material.Role() == "recipient" {
		creator, recipient = recipient, creator
		aIP, bIP = bIP, aIP
	}
	c := carrier.HandshakeConfig{
		Role: carrier.Role(a.material.Role()), LinkID: a.link.ID, Attempt: attempt,
		CreatorEndpoint: creator, RecipientEndpoint: recipient,
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
	if a.connected {
		a.status.State = "CONNECTED"
	} else if a.session != nil {
		a.status.State = "AUTHENTICATING"
	} else if a.handshake != nil {
		a.status.State = "DISCOVERING"
	} else if len(a.inventory.Addresses) == 0 {
		a.status.State = "NO_WORKING_PATH"
	} else {
		a.status.State = "WAITING_FOR_PEER"
	}
	a.status.SelectedSource = ""
	if a.chosen.IsValid() {
		a.status.SelectedSource = a.chosen.String()
	}
	a.status.SourceCandidates = len(a.inventory.Addresses)
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
		a.chosen = netip.Addr{}
		if a.connected {
			a.connected = false
			a.session = nil
			a.handshake = nil
		}
		a.record(err)
		return
	}
	if slices.Equal(inv.Addresses, a.inventory.Addresses) {
		a.inventory = inv
		return
	}
	replacement, err := carrier.OpenRawSender(a.peerEndpoint(), a.link.Spoof.ListenPort, inv, a.link.Spoof.Interface)
	if err != nil {
		a.record(err)
		if a.sender != nil {
			_ = a.sender.Close()
			a.sender = nil
		}
		a.inventory = carrier.Inventory{}
		return
	}
	old := a.sender
	a.sender = replacement
	a.inventory = inv
	if old != nil {
		_ = old.Close()
	}
	if a.chosen.IsValid() && !slices.Contains(inv.Addresses, a.chosen) {
		a.chosen = netip.Addr{}
		a.connected = false
		a.session = nil
		a.handshake = nil
		a.record(errors.New("previous selected Source disappeared; rediscovery in same Link"))
	}
}
func (a *Agent) sendSelected(encoded []byte) error {
	if a.sender == nil {
		return errors.New("local Source file unavailable")
	}
	if a.chosen.IsValid() {
		return a.sender.Send(a.chosen, encoded)
	}
	return a.sendCandidates(encoded)
}
func (a *Agent) sendCandidates(encoded []byte) error {
	if a.sender == nil {
		return errors.New("raw source sender unavailable")
	}
	sources, err := a.cursor.NextBatch(a.inventory, 4)
	if err != nil {
		return err
	}
	var first error
	for _, candidate := range sources {
		if e := a.sender.Send(candidate, encoded); e != nil && first == nil {
			first = e
		}
	}
	return first
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
	a.pendingKind = carrier.KindHandshake1
	a.pendingPayload = first
	a.chosen = netip.Addr{}
	return a.sendPending()
}
func (a *Agent) forgetHandshake() {
	a.session = nil
	a.handshake = nil
	a.connected = false
	a.pendingPayload = nil
	a.chosen = netip.Addr{}
}
func (a *Agent) received(frame carrier.Frame, outer netip.AddrPort) error {
	if frame.LinkID != a.link.ID {
		return nil
	}
	if a.material.Role() == "creator" && frame.Kind == carrier.KindHandshake1 {
		if a.connected && time.Since(a.lastAuth) < 8*time.Second {
			return nil
		}
		// A retry with the same Attempt must not rewrite the transcript.
		if a.handshake != nil && frame.Attempt == a.attempt {
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
		a.handshake = h
		a.attempt = frame.Attempt
		a.pendingKind = carrier.KindHandshake2
		a.pendingPayload = reply
		a.pendingAt = time.Now()
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
			// The observed responder outer source is a directional hint only, not identity.
			if slices.Contains(a.inventory.Addresses, outer.Addr()) {
				a.cursor.PreferredSucceeded(outer.Addr())
			}
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
			return a.sendControl(carrier.KindKeepalive, outer.Addr())
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
		if len(plain) == 4 {
			var address [4]byte
			copy(address[:], plain)
			candidate := netip.AddrFrom4(address)
			if slices.Contains(a.inventory.Addresses, candidate) {
				a.chosen = candidate
				a.cursor.PreferredSucceeded(candidate)
			}
		}
		if err = a.sendControl(carrier.KindKeepaliveAck, outer.Addr()); err != nil {
			return err
		}
	case carrier.KindKeepaliveAck:
		if len(plain) == 4 {
			var address [4]byte
			copy(address[:], plain)
			candidate := netip.AddrFrom4(address)
			if slices.Contains(a.inventory.Addresses, candidate) {
				a.chosen = candidate
				a.cursor.PreferredSucceeded(candidate)
			}
		}
		if !a.connected {
			a.connected = true
			a.status.LastError = ""
			fmt.Fprintln(os.Stderr, "spoof link", a.link.ID, "authenticated bilateral path confirmed; private IPv4 ready")
			// Confirm the creator has proof that the recipient saw its response.
			if err = a.sendControl(carrier.KindKeepaliveAck, outer.Addr()); err != nil {
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
func (a *Agent) sendControl(kind carrier.FrameKind, observedPeerSource netip.Addr) error {
	if a.session == nil {
		return nil
	}
	// This address is an authenticated observation exchanged only over Noise.
	// It does not authorize use of any Source absent from the LOCAL file.
	payload := make([]byte, 4)
	if observedPeerSource.Is4() {
		copy(payload, observedPeerSource.AsSlice())
	}
	encrypted, err := a.session.Seal(kind, payload)
	if err != nil {
		return err
	}
	return a.sendSelected(encrypted)
}
func (a *Agent) tick() {
	if time.Since(a.lastSourceRefresh) >= 2*time.Second {
		a.refreshSources()
	}
	if len(a.inventory.Addresses) == 0 {
		return
	}
	if a.session != nil && a.connected {
		if time.Since(a.lastAuth) > 12*time.Second {
			a.record(errors.New("authenticated peer liveness expired; rediscovering without re-pair"))
			a.forgetHandshake()
		} else if time.Since(a.lastSentKeepalive) >= 3*time.Second {
			a.lastSentKeepalive = time.Now()
			if err := a.sendControl(carrier.KindKeepalive, netip.Addr{}); err != nil {
				a.record(err)
			}
			return
		} else {
			return
		}
	}
	if a.material.Role() == "recipient" && a.handshake == nil {
		if err := a.startRecipient(); err != nil {
			a.record(err)
		}
		return
	}
	if a.handshake != nil && time.Since(a.pendingAt) > 13*time.Second {
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
	if a.session != nil && time.Since(a.lastSentKeepalive) > 800*time.Millisecond {
		a.lastSentKeepalive = time.Now()
		if err := a.sendControl(carrier.KindKeepalive, netip.Addr{}); err != nil {
			a.record(err)
		}
	}
}

type receivedFrame struct {
	frame carrier.Frame
	outer netip.AddrPort
}

func (a *Agent) run(ctx context.Context) error {
	tun, err := carrier.OpenPrivateTUN(ctx, a.link.ID, 1280, a.link.Addresses.Local.Addr(), a.link.Addresses.Peer.Addr())
	if err != nil {
		return err
	}
	a.tun = tun
	defer tun.Close()
	receiver, err := carrier.OpenReceiver(a.localEndpoint())
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
		buffer := make([]byte, 4096)
		for ctx.Err() == nil {
			_ = receiver.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			n, outer, err := receiver.ReadFromUDPAddrPort(buffer)
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
			case frames <- receivedFrame{frame, outer}:
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
			if err = a.received(incoming.frame, incoming.outer); err != nil {
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
