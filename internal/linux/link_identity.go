package linux

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const netlinkPollMillis = 100

// SetLinkAliasByIndex marks the exact observed kernel link identity rather than
// looking it up again by a potentially reused interface name.
func SetLinkAliasByIndex(ctx context.Context, index int, alias string) error {
	if index <= 0 {
		return fmt.Errorf("valid link index is required")
	}
	if alias == "" || len(alias) > 255 {
		return fmt.Errorf("valid link alias is required")
	}
	for _, r := range alias {
		if r == 0 || r == '\r' || r == '\n' {
			return fmt.Errorf("link alias contains invalid control characters")
		}
	}
	value := append([]byte(alias), 0)
	return routeLinkRequest(ctx, unix.RTM_SETLINK, index, 0, 0, unix.IFLA_IFALIAS, value)
}

// SetLinkUpByIndex activates the exact observed kernel link identity without a
// second name lookup that could target a replacement interface.
func SetLinkUpByIndex(ctx context.Context, index int) error {
	if index <= 0 {
		return fmt.Errorf("valid link index is required")
	}
	return routeLinkRequest(ctx, unix.RTM_NEWLINK, index, unix.IFF_UP, unix.IFF_UP, 0, nil)
}

// AddIPv4AddressByIndex assigns one IPv4 prefix to the exact observed kernel
// link identity. The request is exclusive so a pre-existing address is not
// silently adopted as state created by the current operation.
func AddIPv4AddressByIndex(ctx context.Context, index int, prefix netip.Prefix) error {
	if index <= 0 {
		return fmt.Errorf("valid link index is required")
	}
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 0 || prefix.Bits() > 32 {
		return fmt.Errorf("valid IPv4 prefix is required")
	}
	addr := prefix.Addr().As4()
	attrs := appendNetlinkAttr(nil, unix.IFA_LOCAL, addr[:])
	attrs = appendNetlinkAttr(attrs, unix.IFA_ADDRESS, addr[:])

	const seq uint32 = 1
	message := make([]byte, unix.SizeofNlMsghdr+unix.SizeofIfAddrmsg+len(attrs))
	order := binary.NativeEndian
	order.PutUint32(message[0:4], uint32(len(message)))
	order.PutUint16(message[4:6], unix.RTM_NEWADDR)
	order.PutUint16(message[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	order.PutUint32(message[8:12], seq)
	base := unix.SizeofNlMsghdr
	message[base] = unix.AF_INET
	message[base+1] = byte(prefix.Bits())
	message[base+2] = 0
	message[base+3] = unix.RT_SCOPE_UNIVERSE
	order.PutUint32(message[base+4:base+8], uint32(index))
	copy(message[base+unix.SizeofIfAddrmsg:], attrs)
	return sendRouteNetlinkRequest(ctx, message, seq)
}

// DeleteLinkByIndex deletes the exact observed kernel link identity. Callers
// must still revalidate that the index remains attributable to their resource
// immediately before invoking this destructive primitive.
func DeleteLinkByIndex(ctx context.Context, index int) error {
	if index <= 0 {
		return fmt.Errorf("valid link index is required")
	}
	return routeLinkRequest(ctx, unix.RTM_DELLINK, index, 0, 0, 0, nil)
}

func routeLinkRequest(ctx context.Context, messageType uint16, index int, flags, change uint32, attrType uint16, attrValue []byte) error {
	const seq uint32 = 1
	attrLen := 0
	if attrType != 0 {
		attrLen = alignNetlink(unix.SizeofRtAttr + len(attrValue))
	}
	message := make([]byte, unix.SizeofNlMsghdr+unix.SizeofIfInfomsg+attrLen)
	order := binary.NativeEndian
	order.PutUint32(message[0:4], uint32(len(message)))
	order.PutUint16(message[4:6], messageType)
	order.PutUint16(message[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	order.PutUint32(message[8:12], seq)
	base := unix.SizeofNlMsghdr
	message[base] = unix.AF_UNSPEC
	order.PutUint32(message[base+4:base+8], uint32(int32(index)))
	order.PutUint32(message[base+8:base+12], flags)
	order.PutUint32(message[base+12:base+16], change)
	if attrType != 0 {
		off := base + unix.SizeofIfInfomsg
		order.PutUint16(message[off:off+2], uint16(unix.SizeofRtAttr+len(attrValue)))
		order.PutUint16(message[off+2:off+4], attrType)
		copy(message[off+unix.SizeofRtAttr:], attrValue)
	}
	return sendRouteNetlinkRequest(ctx, message, seq)
}

func appendNetlinkAttr(dst []byte, attrType uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	aligned := alignNetlink(length)
	start := len(dst)
	dst = append(dst, make([]byte, aligned)...)
	order := binary.NativeEndian
	order.PutUint16(dst[start:start+2], uint16(length))
	order.PutUint16(dst[start+2:start+4], attrType)
	copy(dst[start+unix.SizeofRtAttr:start+length], value)
	return dst
}

func sendRouteNetlinkRequest(ctx context.Context, message []byte, seq uint32) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open route netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind route netlink socket: %w", err)
	}

	for {
		err = unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if err == nil {
			break
		}
		if err != unix.EAGAIN && err != unix.EWOULDBLOCK {
			return fmt.Errorf("send route netlink request: %w", err)
		}
		if err := waitNetlink(ctx, fd, unix.POLLOUT); err != nil {
			return err
		}
	}

	buffer := make([]byte, 8192)
	order := binary.NativeEndian
	for {
		n, _, recvErr := unix.Recvfrom(fd, buffer, 0)
		if recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK {
			if err := waitNetlink(ctx, fd, unix.POLLIN); err != nil {
				return err
			}
			continue
		}
		if recvErr != nil {
			return fmt.Errorf("receive route netlink response: %w", recvErr)
		}
		messages, parseErr := syscall.ParseNetlinkMessage(buffer[:n])
		if parseErr != nil {
			return fmt.Errorf("parse route netlink response: %w", parseErr)
		}
		for _, reply := range messages {
			if reply.Header.Seq != seq {
				continue
			}
			if reply.Header.Type != unix.NLMSG_ERROR || len(reply.Data) < 4 {
				continue
			}
			code := int32(order.Uint32(reply.Data[:4]))
			if code == 0 {
				return nil
			}
			return fmt.Errorf("route netlink request failed: %w", unix.Errno(-code))
		}
	}
}

func waitNetlink(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		timeout := netlinkPollMillis
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			if remaining < time.Duration(timeout)*time.Millisecond {
				timeout = max(1, int(remaining/time.Millisecond))
			}
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(fds, timeout)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll route netlink socket: %w", err)
		}
		if n > 0 {
			return nil
		}
	}
}

func alignNetlink(length int) int { return (length + 3) &^ 3 }
