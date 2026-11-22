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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	file      *os.File
	name      string
	ifIndex   int
	ownerLink domain.LinkID
	local     netip.Addr
	peer      netip.Addr
	mtu       atomic.Int32
	mu        sync.Mutex
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
	// Pin the exact kernel interface index before any post-create mutation.
	// Both the live TUN file and the Link-scoped alias must identify it.
	current, err := net.InterfaceByName(name)
	if err != nil || current.Index <= 0 {
		f.Close()
		return nil, fmt.Errorf("owned Spoof TUN identity unavailable after creation: %w", err)
	}
	alias, err := os.ReadFile(filepath.Join("/sys/class/net", name, "ifalias"))
	if err != nil || strings.TrimSpace(string(alias)) != "stl:spoof:"+string(id) {
		f.Close()
		return nil, errors.New("owned Spoof TUN alias unverified after creation")
	}
	owned := &PrivateTUN{file: f, name: name, ifIndex: current.Index, ownerLink: id, local: local, peer: peer}
	owned.mtu.Store(int32(mtu))
	return owned, nil
}

func (t *PrivateTUN) MTU() int {
	if t == nil {
		return 0
	}
	return int(t.mtu.Load())
}

// SetMTU changes only the exact TUN created by this helper. The original
// descriptor stays open and the observed kernel MTU is verified before
// accepting the change. No global route, sysctl or unrelated interface is
// affected.
// The caller supplies the owning host adapter's ifindex-based Netlink write.
// This avoids a carrier -> host import cycle and an unsafe name-based write.
func (t *PrivateTUN) SetMTU(ctx context.Context, mtu int,
	setByIndex func(context.Context, int, int) error) error {
	if t == nil || mtu < 576 || mtu > 65431 || setByIndex == nil {
		return errors.New("owned Spoof TUN MTU outside IPv4 carrier bounds")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return errors.New("owned Spoof TUN is closed")
	}
	iface, err := net.InterfaceByName(t.name)
	if err != nil || iface == nil || iface.Flags&net.FlagUp == 0 {
		return errors.New("Spoof TUN identity lost during MTU change")
	}
	if iface.Index != t.ifIndex || t.ifIndex <= 0 || t.ownerLink.Validate() != nil {
		return errors.New("Spoof TUN index or Link ownership changed before MTU apply")
	}
	alias, err := os.ReadFile(filepath.Join("/sys/class/net", t.name, "ifalias"))
	if err != nil || strings.TrimSpace(string(alias)) != "stl:spoof:"+string(t.ownerLink) {
		return errors.New("Spoof TUN alias changed; refuse foreign MTU mutation")
	}
	// Netlink writes to the pinned ifindex instead of resolving a mutable
	// interface name a second time. Keep the existing private TUN fd open.
	if err := setByIndex(ctx, t.ifIndex, mtu); err != nil {
		return fmt.Errorf("apply exact owned Spoof TUN MTU: %w", err)
	}
	observed, err := net.InterfaceByIndex(t.ifIndex)
	if err != nil || observed.Index != t.ifIndex || observed.Name != t.name || observed.MTU != mtu {
		return fmt.Errorf("Spoof TUN MTU/identity readback differs from requested %d: %v", mtu, err)
	}
	t.mtu.Store(int32(mtu))
	return nil
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

// The local TUN MTU constrains this host's outgoing private packets ONLY.
// An authenticated remote peer may have a different outgoing MTU. Its
// incoming private IPv4 packet must be accepted up to the real IPv4 length
// limit, rather than silently discarded against this host's outbound MTU.
const maxAuthenticatedIncomingIPv4Bytes = 65535

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
		b := make([]byte, t.MTU()+64)
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
		if err := validPrivatePacket(p, t.local, t.peer, t.MTU()); err != nil {
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
// The remote sender may have a larger outgoing path MTU than the local
// endpoint; local TUN MTU never limits authenticated inbound IPv4 payload.
func (t *PrivateTUN) WritePacket(ctx context.Context, packet []byte) error {
	if t == nil || t.file == nil {
		return errors.New("Spoof TUN is closed")
	}
	if err := validPrivatePacket(packet, t.peer, t.local, maxAuthenticatedIncomingIPv4Bytes); err != nil {
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
