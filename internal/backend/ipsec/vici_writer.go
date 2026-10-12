package ipsec

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/strongswan/govici/vici"
)

// ScopedWriter is restricted to an externally admitted, lifetime-exclusive
// private strongSwan daemon. No method performs a bulk/reload/flush operation.
// An IPsec operation MUST already hold Engine Link/resource locks, have a
// durable transaction intent and pass runtime ownership admission.
type ScopedWriter struct{ socket string }

func NewScopedWriter(socket string) (ScopedWriter, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || socket == "/" {
		return ScopedWriter{}, fmt.Errorf("invalid private VICI endpoint")
	}
	return ScopedWriter{socket: socket}, nil
}

func (w ScopedWriter) session(ctx context.Context) (*vici.Session, error) {
	if ctx == nil {
		return nil, fmt.Errorf("VICI request requires context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("VICI request interrupted")
	}
	info, err := os.Lstat(w.socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("private VICI socket is missing or unsafe")
	}
	s, err := vici.NewSession(
		vici.WithAddr("unix", w.socket),
		vici.WithDialContext(func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "unix" || address != w.socket {
				return nil, fmt.Errorf("refusing alternate VICI endpoint")
			}
			return (&net.Dialer{}).DialContext(ctx, "unix", w.socket)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("private VICI connection unavailable")
	}
	return s, nil
}

func (w ScopedWriter) call(ctx context.Context, op string, msg *vici.Message) error {
	s, err := w.session(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	response, err := s.Call(ctx, op, msg)
	if err != nil || response == nil {
		// Never echo daemon text: it may contain raw PSK or VICI frames.
		return fmt.Errorf("scoped VICI %s outcome unknown; manual reconciliation required", op)
	}
	if result, ok := response.Get("success").(string); !ok || result != "yes" {
		return fmt.Errorf("scoped VICI %s rejected; inspect owned state before retry", op)
	}
	return nil
}

// LoadShared loads exactly one named 256-bit key with both Link IKE IDs.
// The caller's exclusive runtime writer boundary MUST rule out races with
// other VICI clients. VICI's load-shared has replace-by-name semantics.
func (w ScopedWriter) LoadShared(ctx context.Context, p Profile, secret *PSK) error {
	if p.validateIdentity() != nil || secret == nil {
		return fmt.Errorf("invalid scoped shared-key intent")
	}
	raw := secret.SecretBytes()
	defer clear(raw)
	msg, err := vici.MarshalMessage(map[string]any{
		"id": p.SecretName, "type": "IKE",
		"data":   string(raw),
		"owners": []string{p.LocalIKEID, p.PeerIKEID},
	})
	if err != nil {
		return fmt.Errorf("invalid scoped shared-key request")
	}
	// The govici wire API accepts strings, not []byte; the transient string
	// cannot be scrubbed by Go. Do not log, serialize or retain this message.
	return w.call(ctx, "load-shared", msg)
}

func (w ScopedWriter) LoadConnection(ctx context.Context, p Profile) error {
	m, err := p.ConnectionRequest()
	if err != nil {
		return err
	}
	return w.call(ctx, "load-conn", m)
}

func (w ScopedWriter) Initiate(ctx context.Context, p Profile) error {
	if p.validateIdentity() != nil {
		return fmt.Errorf("invalid scoped IKE initiation identity")
	}
	m, err := vici.MarshalMessage(map[string]any{
		"ike": p.ConnectionName, "child": p.ChildName,
		"timeout": "20000", "loglevel": "0",
	})
	if err != nil {
		return fmt.Errorf("invalid IKE initiation request")
	}
	return w.call(ctx, "initiate", m)
}

func (w ScopedWriter) Terminate(ctx context.Context, p Profile) error {
	if p.validateIdentity() != nil {
		return fmt.Errorf("invalid scoped IKE termination identity")
	}
	m, err := vici.MarshalMessage(map[string]any{
		"ike": p.ConnectionName, "timeout": "20000", "loglevel": "0",
	})
	if err != nil {
		return fmt.Errorf("invalid scoped IKE termination request")
	}
	return w.call(ctx, "terminate", m)
}

func (w ScopedWriter) UnloadConnection(ctx context.Context, p Profile) error {
	if p.validateIdentity() != nil {
		return fmt.Errorf("invalid scoped unload identity")
	}
	m, _ := vici.MarshalMessage(map[string]any{"name": p.ConnectionName})
	return w.call(ctx, "unload-conn", m)
}

func (w ScopedWriter) UnloadShared(ctx context.Context, p Profile) error {
	if p.validateIdentity() != nil {
		return fmt.Errorf("invalid scoped credential unload identity")
	}
	m, _ := vici.MarshalMessage(map[string]any{"id": p.SecretName})
	return w.call(ctx, "unload-shared", m)
}

func (w ScopedWriter) Inspect(ctx context.Context, p Profile) (Snapshot, error) {
	r, err := NewReader(w.socket)
	if err != nil {
		return Snapshot{}, err
	}
	return r.Inspect(ctx, p)
}

// A non-empty socket path is never sufficient runtime admission.
func (w ScopedWriter) validate() error {
	if strings.TrimSpace(w.socket) == "" || !filepath.IsAbs(w.socket) {
		return fmt.Errorf("private VICI endpoint required")
	}
	return nil
}
