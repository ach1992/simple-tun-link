package ipsec

import (
	"context"
	"fmt"
	"iter"
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
	CallStreaming(context.Context, string, string, *vici.Message) iter.Seq2[*vici.Message, error]
	Close() error
}

// The dialer is deliberately NOT part of Reader's public configuration.
// Only NewReader can construct a production reader. Test-time injection is
// confined to same-package test code, not arbitrary CLI/backend consumers.
type sessionDialer func(context.Context) (Session, error)

type Reader struct{ dial sessionDialer }

// NewReader opens the VICI control socket only for explicit per-Link public
// state inspection. An unavailable/non-socket endpoint fails closed. The
// caller's context bounds the VICI command; never fall back to swanctl
// --load-conns, which can unload foreign configurations.
func NewReader(socketPath string) (Reader, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		socketPath == "/" {
		return Reader{}, fmt.Errorf("invalid VICI socket location")
	}
	return Reader{dial: func(ctx context.Context) (Session, error) {
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
// Both VICI-only get-conns and all-provider list-conns must be checked: the
// former alone cannot rule out collisions with other connection providers.
type Snapshot struct {
	ConnectionNamePresent bool
	SecretNamePresent     bool
}

func (r Reader) Inspect(ctx context.Context, p Profile) (Snapshot, error) {
	if ctx == nil || r.dial == nil {
		return Snapshot{}, fmt.Errorf("VICI reader requires context and dialer")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := p.validateIdentity(); err != nil {
		return Snapshot{}, err
	}
	session, err := r.dial(ctx)
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
	seenVICIConn, err := containsExactUnique(conn, "conns", p.ConnectionName)
	if err != nil {
		return Snapshot{}, err
	}
	// get-conns ONLY enumerates VICI-loaded connections. strongSwan may
	// load a foreign matching name from another backend; load-conn would
	// replace that object. Inspect the daemon-wide view as well.
	seenAnyConn, err := daemonConnectionPresent(ctx, session, p.ConnectionName)
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
	return Snapshot{ConnectionNamePresent: seenVICIConn || seenAnyConn, SecretNamePresent: seenKey}, nil
}

// daemonConnectionPresent checks all loaded strongSwan configurations, not
// just VICI-owned ones. The single-name filter is a request optimization,
// NEVER ownership proof. Any unexpected event, duplicate, or stream error
// prevents a vacancy verdict. The stream completes before returning: early
// cancellation could otherwise turn an incomplete inventory into absence.
func daemonConnectionPresent(ctx context.Context, session Session, name string) (bool, error) {
	query := vici.NewMessage()
	if err := query.Set("ike", name); err != nil {
		return false, fmt.Errorf("invalid daemon inventory filter")
	}
	count := 0
	for event, err := range session.CallStreaming(ctx, "list-conns", "list-conn", query) {
		if err != nil || event == nil {
			return false, fmt.Errorf("strongSwan complete connection inventory unavailable")
		}
		fields := event.Keys()
		if len(fields) != 1 || fields[0] != name {
			return false, fmt.Errorf("unexpected strongSwan connection inventory identity")
		}
		if section, ok := event.Get(name).(*vici.Message); !ok || section == nil {
			return false, fmt.Errorf("invalid strongSwan connection inventory entry")
		}
		count++
		if count > 1 {
			return false, fmt.Errorf("ambiguous strongSwan connection inventory")
		}
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("strongSwan complete connection inventory interrupted")
	}
	return count == 1, nil
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
