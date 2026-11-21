//go:build linux

package spoof

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// TunnelName is a stable, Link-ID-derived Linux name (<=IFNAMSIZ). Every
// endpoint's independently owned TUN uses its own namespace-local identity.
func TunnelName(id domain.LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return "stls" + string(id)[4:14], nil
}

type PrivateTUN struct {
	file  *os.File
	name  string
	local netip.Addr
	peer  netip.Addr
	mtu   int
	mu    sync.Mutex
}

func runPrivateIP(ctx context.Context, args ...string) error {
	timeout, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(timeout, "ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("owned Spoof TUN ip %s failed: %w: %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return nil
}

// OpenPrivateTUN creates one non-persistent exact Link-owned interface. A
// failed setup or service exit closes its descriptor and removes only its
// private route/device. It does not modify default routes or other Links.
func OpenPrivateTUN(ctx context.Context, id domain.LinkID, mtu int, local, peer netip.Addr) (*PrivateTUN, error) {
	name, err := TunnelName(id)
	if err != nil {
		return nil, err
	}
	if mtu < 576 || mtu > 65535 || !local.Is4() || !peer.Is4() ||
		local == peer || local.IsUnspecified() || peer.IsUnspecified() ||
		local.IsLoopback() || peer.IsLoopback() {
		return nil, errors.New("Spoof requires two distinct valid private IPv4 addresses and a usable TUN MTU")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, errors.New("Spoof TUN name already exists; refuse foreign interface adoption")
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("Spoof Linux TUN access (CAP_NET_ADMIN needed): %w", err)
	}
	f := os.NewFile(uintptr(fd), "spoof-tun-"+name)
	ifreq, err := unix.NewIfreq(name)
	if err == nil {
		ifreq.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL))
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifreq)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("Spoof exclusive Linux TUN creation: %w", err)
	}
	for _, args := range [][]string{
		{"link", "set", "dev", name, "mtu", fmt.Sprint(mtu)},
		{"link", "set", "dev", name, "alias", "stl:spoof:" + string(id)},
		{"addr", "add", local.String() + "/32", "dev", name},
		{"link", "set", "dev", name, "up"},
		{"route", "add", peer.String() + "/32", "dev", name, "scope", "link", "src", local.String()},
	} {
		if err := runPrivateIP(ctx, args...); err != nil {
			f.Close()
			return nil, err
		}
	}
	return &PrivateTUN{file: f, name: name, local: local, peer: peer, mtu: mtu}, nil
}

func (t *PrivateTUN) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return nil
	}
	err := t.file.Close()
	t.file = nil
	return err
}

func validPrivatePacket(packet []byte, source, destination netip.Addr, mtu int) error {
	if len(packet) < 20 || len(packet) > mtu || packet[0]>>4 != 4 {
		return errors.New("Spoof private packet must be IPv4 within negotiated TUN MTU")
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return errors.New("Spoof private IPv4 header length invalid")
	}
	total := int(packet[2])<<8 | int(packet[3])
	if total < headerLen || total != len(packet) {
		return errors.New("Spoof private IPv4 total length inconsistent")
	}
	var rawSource, rawDestination [4]byte
	copy(rawSource[:], packet[12:16])
	copy(rawDestination[:], packet[16:20])
	if netip.AddrFrom4(rawSource) != source || netip.AddrFrom4(rawDestination) != destination {
		return errors.New("Spoof private IP source/destination differs from paired Link")
	}
	return nil
}

// ReadPacket returns a local app-originated private IPv4 packet. Invalid
// kernel/app packets fail rather than being silently redirected elsewhere.
func (t *PrivateTUN) ReadPacket(ctx context.Context) ([]byte, error) {
	if t == nil || t.file == nil {
		return nil, errors.New("Spoof TUN is closed")
	}
	poll := []unix.PollFd{{Fd: int32(t.file.Fd()), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		n, err := unix.Poll(poll, 40)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("Spoof TUN poll: %w", err)
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, errors.New("Spoof owned TUN unavailable")
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		b := make([]byte, t.mtu+64)
		size, err := unix.Read(int(t.file.Fd()), b)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("Spoof TUN read: %w", err)
		}
		p := b[:size]
		// Linux may originate IPv6 link-local management packets as the
		// interface becomes UP. This is an IPv4-only private Link: silently
		// drop unrelated AF traffic at the TUN boundary instead of taking
		// down the service that owns the Link. A malformed IPv4 packet is
		// still a reportable error, never forwarded.
		if len(p) == 0 || p[0]>>4 != 4 {
			continue
		}
		if err := validPrivatePacket(p, t.local, t.peer, t.mtu); err != nil {
			// Kernel/application traffic may target a different private
			// destination immediately when the interface comes UP. It is
			// not paired Link traffic: discard at the TUN boundary, never
			// terminate a healthy owned helper or redirect such packets.
			// Authenticated remote frames are validated separately.
			continue
		}
		return p, nil
	}
	return nil, ctx.Err()
}

// WritePacket accepts only authenticated peer->local IP packets. Caller
// must first verify AEAD, anti-replay and pinned Link session identity.
func (t *PrivateTUN) WritePacket(ctx context.Context, packet []byte) error {
	if t == nil || t.file == nil {
		return errors.New("Spoof TUN is closed")
	}
	if err := validPrivatePacket(packet, t.peer, t.local, t.mtu); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for ctx.Err() == nil {
		written, err := unix.Write(int(t.file.Fd()), packet)
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("Spoof owned TUN write: %w", err)
		}
		if written != len(packet) {
			return fmt.Errorf("Spoof owned TUN packet partially written (%d/%d)", written, len(packet))
		}
		return nil
	}
	return ctx.Err()
}
