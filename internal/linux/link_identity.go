package linux

import (
	"context"
	"encoding/binary"
	"fmt"
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
	return routeLinkRequest(ctx, unix.RTM_SETLINK, index, unix.IFLA_IFALIAS, value)
}

// DeleteLinkByIndex deletes the exact observed kernel link identity. This
// avoids deleting a replacement link that later reused the same interface name.
func DeleteLinkByIndex(ctx context.Context, index int) error {
	if index <= 0 {
		return fmt.Errorf("valid link index is required")
	}
	return routeLinkRequest(ctx, unix.RTM_DELLINK, index, 0, nil)
}

func routeLinkRequest(ctx context.Context, messageType uint16, index int, attrType uint16, attrValue []byte) error {
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

	const seq uint32 = 1
	payloadLen := unix.SizeofIfInfomsg
	attrLen := 0
	if attrType != 0 {
		attrLen = alignNetlink(unix.SizeofRtAttr + len(attrValue))
	}
	message := make([]byte, unix.SizeofNlMsghdr+payloadLen+attrLen)
	order := binary.NativeEndian
	order.PutUint32(message[0:4], uint32(len(message)))
	order.PutUint16(message[4:6], messageType)
	order.PutUint16(message[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	order.PutUint32(message[8:12], seq)
	base := unix.SizeofNlMsghdr
	message[base] = unix.AF_UNSPEC
	order.PutUint32(message[base+4:base+8], uint32(int32(index)))
	if attrType != 0 {
		off := base + payloadLen
		order.PutUint16(message[off:off+2], uint16(unix.SizeofRtAttr+len(attrValue)))
		order.PutUint16(message[off+2:off+4], attrType)
		copy(message[off+unix.SizeofRtAttr:], attrValue)
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
