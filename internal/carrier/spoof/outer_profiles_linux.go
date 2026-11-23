//go:build linux

package spoof

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ProfileFrameReceiver adds the observed outer transport, which is an
// unauthenticated hint until the enclosed Noise transcript authenticates.
type ProfileFrameReceiver interface {
	FrameReceiver
	ReadProfileFrame([]byte) (int, netip.AddrPort, string, error)
}

type RawProfileReceiver struct {
	fd       int
	local    netip.AddrPort
	profile  string
	deadline time.Time
}

func OpenRawProfileReceiver(local netip.AddrPort, profile, device string) (*RawProfileReceiver, error) {
	if !local.IsValid() || !local.Addr().Is4() || local.Addr().IsUnspecified() ||
		local.Addr().IsMulticast() || local.Port() == 0 || profile == ProfileAuto || profile == ProfileUDP ||
		profile == ProfileICMP {
		return nil, fmt.Errorf("unsupported STL raw profile receiver %q for %v", profile, local)
	}
	number, err := ProfileNumber(profile)
	if err != nil {
		return nil, err
	}
	if device != "" {
		iface, e := net.InterfaceByName(device)
		if e != nil || iface.Flags&net.FlagUp == 0 {
			return nil, errors.New("STL raw receive interface must exist and be UP")
		}
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(number))
	if err != nil {
		return nil, fmt.Errorf("open STL raw %s receive socket (CAP_NET_RAW needed): %w", profile, err)
	}
	if device != "" {
		if err = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("bind raw receive device %q: %w", device, err)
		}
	}
	return &RawProfileReceiver{fd: fd, local: local, profile: profile}, nil
}
func (r *RawProfileReceiver) SetReadDeadline(d time.Time) error {
	if r == nil || r.fd < 0 {
		return os.ErrClosed
	}
	r.deadline = d
	return nil
}
func (r *RawProfileReceiver) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	fd := r.fd
	r.fd = -1
	return unix.Close(fd)
}
func (r *RawProfileReceiver) ReadFrame(p []byte) (int, netip.AddrPort, error) {
	n, src, _, err := r.ReadProfileFrame(p)
	return n, src, err
}
func (r *RawProfileReceiver) ReadProfileFrame(p []byte) (int, netip.AddrPort, string, error) {
	if r == nil || r.fd < 0 {
		return 0, netip.AddrPort{}, "", os.ErrClosed
	}
	raw := make([]byte, len(p)+90)
	for {
		remain := time.Until(r.deadline)
		if r.deadline.IsZero() || remain <= 0 {
			return 0, netip.AddrPort{}, "", os.ErrDeadlineExceeded
		}
		ms := max(1, int(remain/time.Millisecond))
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, netip.AddrPort{}, "", fmt.Errorf("poll %s raw: %w", r.profile, err)
		}
		if ready == 0 {
			continue
		}
		n, _, err := unix.Recvfrom(r.fd, raw, 0)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, netip.AddrPort{}, "", fmt.Errorf("recv %s raw: %w", r.profile, err)
		}
		allowed := r.profile
		if allowed == ProfileProto58 {
			allowed = ProfileAuto
		} // shared protocol number; recognize both forms
		frame, source, profile, e := DecodeOuterPacket(raw[:n], r.local, allowed)
		if e != nil || len(frame) > len(p) {
			continue
		}
		copy(p, frame)
		return len(frame), source, profile, nil
	}
}

type receivedProfileFrame struct {
	raw     []byte
	source  netip.AddrPort
	profile string
	err     error
}
type MultiProfileReceiver struct {
	parts    []ProfileFrameReceiver
	opened   []string
	failed   []string
	deadline time.Time
	packets  chan receivedProfileFrame
	stop     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
}

func OpenMultiProfileReceiver(local netip.AddrPort, device string) (*MultiProfileReceiver, error) {
	r := &MultiProfileReceiver{packets: make(chan receivedProfileFrame, 128), stop: make(chan struct{})}
	try := func(profile string) {
		var part ProfileFrameReceiver
		var err error
		switch profile {
		case ProfileUDP:
			part, err = openUDPFrameReceiver(local, device)
		case ProfileICMP:
			var c *ICMPReceiver
			c, err = OpenICMPReceiver(local, device)
			if err == nil {
				part = c
			}
		default:
			part, err = OpenRawProfileReceiver(local, profile, device)
		}
		if err != nil {
			r.failed = append(r.failed, profile+": "+err.Error())
			return
		}
		r.opened = append(r.opened, profile)
		r.parts = append(r.parts, part)
	}
	// Both 58 shapes share one AF_INET/IPPROTO_58 socket. Decode disambiguates
	// the two shape markers rather than opening duplicate OS listeners.
	for _, profile := range AllProfiles() {
		if profile != ProfileProto58Echo {
			try(profile)
		}
	}
	if len(r.parts) == 0 {
		return nil, fmt.Errorf("no STL Spoof receive profiles available: %v", r.failed)
	}
	for _, part := range r.parts {
		r.wg.Add(1)
		go func(part ProfileFrameReceiver) {
			defer r.wg.Done()
			buf := make([]byte, 65535)
			for {
				select {
				case <-r.stop:
					return
				default:
				}
				_ = part.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
				n, source, profile, err := part.ReadProfileFrame(buf)
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						continue
					}
					if errors.Is(err, os.ErrDeadlineExceeded) {
						continue
					}
					select {
					case r.packets <- receivedProfileFrame{err: err}:
					case <-r.stop:
					}
					return
				}
				ready := receivedProfileFrame{raw: append([]byte(nil), buf[:n]...), source: source, profile: profile}
				select {
				case r.packets <- ready:
				case <-r.stop:
					return
				}
			}
		}(part)
	}
	return r, nil
}
func (r *MultiProfileReceiver) AvailableProfiles() []string {
	names := append([]string(nil), r.opened...)
	for _, v := range r.opened {
		if v == ProfileProto58 {
			names = append(names, ProfileProto58Echo)
			break
		}
	}
	return names
}
func (r *MultiProfileReceiver) FailedProfiles() []string          { return append([]string(nil), r.failed...) }
func (r *MultiProfileReceiver) SetReadDeadline(t time.Time) error { r.deadline = t; return nil }
func (r *MultiProfileReceiver) ReadFrame(p []byte) (int, netip.AddrPort, error) {
	n, a, _, e := r.ReadProfileFrame(p)
	return n, a, e
}
func (r *MultiProfileReceiver) ReadProfileFrame(p []byte) (int, netip.AddrPort, string, error) {
	for {
		wait := time.Until(r.deadline)
		if r.deadline.IsZero() || wait <= 0 {
			return 0, netip.AddrPort{}, "", os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(wait)
		select {
		case <-r.stop:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return 0, netip.AddrPort{}, "", os.ErrClosed
		case packet := <-r.packets:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if packet.err != nil {
				return 0, netip.AddrPort{}, "", packet.err
			}
			if len(packet.raw) > len(p) {
				continue
			}
			copy(p, packet.raw)
			return len(packet.raw), packet.source, packet.profile, nil
		case <-timer.C:
			return 0, netip.AddrPort{}, "", os.ErrDeadlineExceeded
		}
	}
}
func (r *MultiProfileReceiver) Close() error {
	r.once.Do(func() { close(r.stop); r.wg.Wait() })
	var first error
	for _, p := range r.parts {
		if err := p.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (r *udpFrameReceiver) ReadProfileFrame(p []byte) (int, netip.AddrPort, string, error) {
	n, s, err := r.ReadFrame(p)
	return n, s, ProfileUDP, err
}
func (r *ICMPReceiver) ReadProfileFrame(p []byte) (int, netip.AddrPort, string, error) {
	n, s, err := r.ReadFrame(p)
	return n, s, ProfileICMP, err
}
