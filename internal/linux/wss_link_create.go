package linux

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// WSSOwnerTag includes the 128-bit original durable pre-host-effect nonce,
// not merely the externally chosen public Link ID.
func WSSOwnerTag(id domain.LinkID, nonce string) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(nonce)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != nonce {
		return "", fmt.Errorf("invalid original WSS object nonce")
	}
	return "stl:" + string(id) + ":tx:" + nonce, nil
}
func ParseWSSOwnerTag(tag string) (domain.LinkID, string, bool) {
	if !strings.HasPrefix(tag, "stl:") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(tag, "stl:"), ":tx:")
	if len(parts) != 2 {
		return "", "", false
	}
	id := domain.LinkID(parts[0])
	expected, err := WSSOwnerTag(id, parts[1])
	if err != nil || expected != tag {
		return "", "", false
	}
	return id, parts[1], true
}

// WSSStagingName is generated from the already-durable 128-bit transaction
// nonce BEFORE creation. Its 70-bit nonce-derived, non-public kernel name
// exists atomically on the first RTM_NEWLINK. This closes the Linux
// create-then-set-alias interruption window: if the process dies before alias
// is set, the interface retains this original unpredictable creation name.
// Staging names are not sufficient deletion authority by themselves.
func WSSStagingName(id domain.LinkID, nonce string) (string, error) {
	if _, err := WSSOwnerTag(id, nonce); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(string(id) + ":wss:" + nonce))
	part := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
	return "w" + part[:14], nil
}

// CreateWSSWireGuardStaged performs an exclusive atomic RTM_NEWLINK with an
// original nonce-derived kernel name and WG kind. IFLA_IFALIAS is NOT
// applied at link creation on supported Linux and MUST NOT be represented
// as atomic: an alias is separately set by *ifindex* before renaming the
// interface to its stable public Link name.
func CreateWSSWireGuardStaged(ctx context.Context, name string) error {
	if !validWireGuardStagingName(name, 'w') {
		return fmt.Errorf("invalid exact WSS temporary kernel identity")
	}
	return createWireGuardStaged(ctx, name)
}

// The kernel create primitive is shared between WSS and QUIC; the separate
// exported callers enforce distinct, nonce-generated name namespaces.
func validWireGuardStagingName(name string, prefix byte) bool {
	if len(name) != 15 || name[0] != prefix {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= '2' && name[i] <= '7')) {
			return false
		}
	}
	return true
}

func createWireGuardStaged(ctx context.Context, name string) error {
	linkInfo := appendNetlinkAttr(nil, unix.IFLA_INFO_KIND, []byte("wireguard\x00"))
	attrs := appendNetlinkAttr(nil, unix.IFLA_IFNAME, append([]byte(name), 0))
	attrs = appendNetlinkAttr(attrs, unix.IFLA_LINKINFO|unix.NLA_F_NESTED, linkInfo)
	const seq uint32 = 1
	msg := make([]byte, unix.SizeofNlMsghdr+unix.SizeofIfInfomsg+len(attrs))
	order := binary.NativeEndian
	order.PutUint32(msg[0:4], uint32(len(msg)))
	order.PutUint16(msg[4:6], unix.RTM_NEWLINK)
	order.PutUint16(msg[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	order.PutUint32(msg[8:12], seq)
	msg[unix.SizeofNlMsghdr] = unix.AF_UNSPEC
	copy(msg[unix.SizeofNlMsghdr+unix.SizeofIfInfomsg:], attrs)
	return sendRouteNetlinkRequest(ctx, msg, seq)
}

// RenameLinkByIndex must be used ONLY after a confirmed original nonce
// marker has been set on the same ifindex. It does not use a mutable name.
func RenameLinkByIndex(ctx context.Context, index int, newName string) error {
	if index <= 0 || len(newName) == 0 || len(newName) > 15 || strings.ContainsAny(newName, "/:\x00\r\n \t") {
		return fmt.Errorf("invalid Link rename identity")
	}
	return routeLinkRequest(ctx, unix.RTM_SETLINK, index, 0, 0, unix.IFLA_IFNAME, append([]byte(newName), 0))
}
