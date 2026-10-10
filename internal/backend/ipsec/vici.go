package ipsec

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/strongswan/govici/vici"
)

// Session is a testable, scoped subset of govici. The preliminary adapter is
// READ-ONLY: callers cannot reach global load-conns, load-creds, clear-creds or
// delete-all operations. Daemon mutations belong to the future Engine-locked
// owner-checked backend, not an unguarded shell command or an opt-in flag.
type Session interface {
	Call(context.Context, string, *vici.Message) (*vici.Message, error)
	Close() error
}

type SessionDialer func(context.Context) (Session, error)

type Reader struct{ Dial SessionDialer }

// NewReader opens the VICI control socket only for explicit per-Link public
// state inspection. An unavailable/non-socket endpoint fails closed. The
// caller's context bounds the VICI command; never fall back to swanctl
// --load-conns, which can unload foreign configurations.
func NewReader(socketPath string) (Reader, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		socketPath == "/" {
		return Reader{}, fmt.Errorf("invalid VICI socket location")
	}
	return Reader{Dial: func(ctx context.Context) (Session, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Lstat(socketPath)
		if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("VICI control socket unavailable or not a socket")
		}
		// Verify the endpoint is connected only to a Unix socket. Do not
		// silently switch to TCP or a network-reachable management service.
		return vici.NewSession(vici.WithAddr("unix", socketPath),
			vici.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network != "unix" || addr != socketPath {
					return nil, fmt.Errorf("unexpected VICI endpoint")
				}
				d := net.Dialer{}
				return d.DialContext(ctx, network, addr)
			}))
	}}, nil
}

// Snapshot only reports whether names are present, not whether STL owns them.
// A matching name by itself NEVER authorizes replacement, unload or cleanup.
// Invalid/missing daemon collection results fail closed rather than turning
// an unknown daemon into an empty, writable one.
type Snapshot struct {
	ConnectionNamePresent bool
	SecretNamePresent     bool
}

func (r Reader) Inspect(ctx context.Context, p Profile) (Snapshot, error) {
	if ctx == nil || r.Dial == nil {
		return Snapshot{}, fmt.Errorf("VICI reader requires context and dialer")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := p.validateIdentity(); err != nil {
		return Snapshot{}, err
	}
	session, err := r.Dial(ctx)
	if err != nil {
		// A library/network error might contain daemon-controlled text;
		// never format it in a secret-related operator response.
		return Snapshot{}, fmt.Errorf("VICI daemon inspection unavailable")
	}
	if session == nil {
		return Snapshot{}, fmt.Errorf("VICI session unavailable")
	}
	defer session.Close()
	conn, err := session.Call(ctx, "get-conns", vici.NewMessage())
	if err != nil {
		return Snapshot{}, fmt.Errorf("VICI connection inventory unavailable")
	}
	seenConn, err := containsExactUnique(conn, "conns", p.ConnectionName)
	if err != nil {
		return Snapshot{}, err
	}
	keys, err := session.Call(ctx, "get-shared", vici.NewMessage())
	if err != nil {
		return Snapshot{}, fmt.Errorf("VICI credential inventory unavailable")
	}
	seenKey, err := containsExactUnique(keys, "keys", p.SecretName)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{ConnectionNamePresent: seenConn, SecretNamePresent: seenKey}, nil
}

func containsExactUnique(reply *vici.Message, key, target string) (bool, error) {
	if reply == nil {
		return false, fmt.Errorf("invalid VICI inventory response")
	}
	raw, ok := reply.Get(key).([]string)
	if !ok {
		return false, fmt.Errorf("incomplete VICI inventory response")
	}
	seen := make(map[string]struct{}, len(raw))
	found := false
	for _, name := range raw {
		if name == "" {
			return false, fmt.Errorf("invalid VICI inventory entry")
		}
		if _, duplicate := seen[name]; duplicate {
			return false, fmt.Errorf("ambiguous VICI inventory")
		}
		seen[name] = struct{}{}
		if name == target {
			found = true
		}
	}
	return found, nil
}

// ConnectionRequest is a PUBLIC per-Link VICI load-conn request to be consumed
// ONLY by the future owner-checked Engine backend. It does not call the daemon,
// load a shared secret, or establish an IKE SA. Direct use of this message
// without canonical Link locks and ownership proof is NOT supported.
func (p Profile) ConnectionRequest() (*vici.Message, error) {
	if err := p.validateIdentity(); err != nil {
		return nil, err
	}
	l, r := p.LinkHostSelectors()
	if p.ConnectionName == "" || p.ChildName == "" || p.InterfaceID == 0 ||
		p.LocalIKEID == "" || p.PeerIKEID == "" {
		return nil, fmt.Errorf("invalid IPsec connection profile")
	}
	// NAT-T is an explicit per-Link policy. Native ESP permits charon to
	// detect actual NAT, but does not force encapsulation without one.
	forceUDP := p.Link.Encapsulation == domain.EncapNATT
	req := map[string]any{
		p.ConnectionName: map[string]any{
			"version":      "2",
			"mobike":       "no",
			"encap":        forceUDP,
			"local_addrs":  []string{p.Link.Underlay.Local.String()},
			"remote_addrs": []string{p.Link.Underlay.Peer.String()},
			"local":        map[string]any{"auth": "psk", "id": p.LocalIKEID},
			"remote":       map[string]any{"auth": "psk", "id": p.PeerIKEID},
			"children": map[string]any{
				p.ChildName: map[string]any{
					"local_ts":     []string{l.String()},
					"remote_ts":    []string{r.String()},
					"mode":         "tunnel",
					"start_action": "none",
					"if_id_in":     strconv.FormatUint(uint64(p.InterfaceID), 10),
					"if_id_out":    strconv.FormatUint(uint64(p.InterfaceID), 10),
				},
			},
		},
	}
	msg, err := vici.MarshalMessage(req)
	if err != nil {
		return nil, fmt.Errorf("cannot form public IPsec connection intent")
	}
	return msg, nil
}
