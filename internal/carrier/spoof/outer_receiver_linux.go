//go:build linux

package spoof

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// FrameReceiver receives ONLY a datagram addressed to this Link's already
// configured real endpoint. Its outer sender Source is untrusted until the
// enclosed Noise transcript / AEAD authenticates a remote session.
type FrameReceiver interface {
	ReadFrame([]byte) (int, netip.AddrPort, error)
	SetReadDeadline(time.Time) error
	Close() error
}

type udpFrameReceiver struct{ *net.UDPConn }

func (r *udpFrameReceiver) ReadFrame(payload []byte) (int, netip.AddrPort, error) {
	return r.ReadFromUDPAddrPort(payload)
}

// OpenFrameReceiver chooses a single immutable per-Link packet profile. UDP
// remains the default; ICMP requires the separately validated raw path.
func OpenFrameReceiver(local netip.AddrPort, profile, device string) (FrameReceiver, error) {
	switch profile {
	case ProfileAuto:
		return OpenMultiProfileReceiver(local, device)
	case ProfileICMP:
		return OpenICMPReceiver(local, device)
	case "", ProfileUDP: // preserve published draft explicit UDP default
	default:
		if !ValidProfile(profile) {
			return nil, fmt.Errorf("unsupported Spoof outer receiver profile %q", profile)
		}
		return OpenRawProfileReceiver(local, profile, device)
	}
	return openUDPFrameReceiver(local, device)
}

// Auto and fixed UDP use the same ingress binding; outgoing device selection
// never substitutes for the operator's independent receiving interface.
func openUDPFrameReceiver(local netip.AddrPort, device string) (*udpFrameReceiver, error) {
	if device == "" {
		conn, err := OpenReceiver(local)
		if err != nil {
			return nil, err
		}
		return &udpFrameReceiver{conn}, nil
	}
	// UDP needs the same explicit ingress-device separation as the raw
	// profile receivers. Outgoing --device never constrains this socket.
	iface, err := net.InterfaceByName(device)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("Spoof UDP ingress interface %q missing or DOWN", device)
	}
	config := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		var optionErr error
		if e := raw.Control(func(fd uintptr) {
			optionErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
		}); e != nil {
			return e
		}
		return optionErr
	}}
	conn, err := config.ListenPacket(context.Background(), "udp4", local.String())
	if err != nil {
		return nil, fmt.Errorf("Spoof UDP listener bind %s on ingress %s: %w", local, device, err)
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("Spoof UDP listener did not return UDPConn")
	}
	return &udpFrameReceiver{udp}, nil
}

type ICMPReceiver struct {
	fd       int
	local    netip.AddrPort
	deadline time.Time
}

// OpenICMPReceiver binds raw IPv4 Echo Reply datagrams by exact destination
// address, ICMP identifier and device, without listening on a UDP port.
func OpenICMPReceiver(local netip.AddrPort, device string) (*ICMPReceiver, error) {
	if !local.IsValid() || !local.Addr().Is4() || local.Addr().IsUnspecified() ||
		local.Addr().IsMulticast() || local.Port() == 0 {
		return nil, errors.New("ICMP receiver needs real IPv4 endpoint and explicit receive identifier")
	}
	if device != "" {
		iface, err := net.InterfaceByName(device)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return nil, errors.New("Spoof ICMP receiving interface must be UP")
		}
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("ICMP raw receive socket requires CAP_NET_RAW: %w", err)
	}
	fail := func(e error) (*ICMPReceiver, error) { unix.Close(fd); return nil, e }
	if device != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device); err != nil {
			return fail(fmt.Errorf("bind ICMP receiving device: %w", err))
		}
	}
	return &ICMPReceiver{fd: fd, local: local}, nil
}
func (r *ICMPReceiver) SetReadDeadline(deadline time.Time) error {
	if r == nil || r.fd < 0 {
		return os.ErrClosed
	}
	r.deadline = deadline
	return nil
}
func (r *ICMPReceiver) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	fd := r.fd
	r.fd = -1
	return unix.Close(fd)
}
func (r *ICMPReceiver) ReadFrame(payload []byte) (int, netip.AddrPort, error) {
	if r == nil || r.fd < 0 {
		return 0, netip.AddrPort{}, os.ErrClosed
	}
	raw := make([]byte, len(payload)+60)
	for {
		// Every read is bounded: cancelled helpers set a 400ms read deadline.
		remain := time.Until(r.deadline)
		if r.deadline.IsZero() || remain <= 0 {
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		}
		ms := int(remain / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("poll raw ICMP: %w", err)
		}
		if ready == 0 {
			continue
		}
		n, _, err := unix.Recvfrom(r.fd, raw, 0)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("receive raw ICMP: %w", err)
		}
		b := raw[:n]
		if len(b) < ipv4MinHeader+8+frameHeader || b[0]>>4 != 4 || b[9] != 1 {
			continue
		}
		ipHeaderLen := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ipHeaderLen < 20 || total > len(b) || total < ipHeaderLen+8+frameHeader {
			continue
		}
		if !bytes.Equal(b[16:20], r.local.Addr().AsSlice()) {
			continue
		}
		inner := b[ipHeaderLen:total]
		if inner[0] != 0 || inner[1] != 0 || binary.BigEndian.Uint16(inner[4:6]) != r.local.Port() {
			continue
		}
		if checksum16(inner) != 0 {
			continue
		}
		frame := inner[8:]
		if len(frame) > len(payload) || !bytes.Equal(frame[:4], frameMagic[:]) {
			continue
		}
		source, _ := netip.AddrFromSlice(b[12:16])
		if !source.Is4() {
			continue
		}
		copy(payload, frame)
		return len(frame), netip.AddrPortFrom(source, r.local.Port()), nil
	}
}

var _ FrameReceiver = (*ICMPReceiver)(nil)
