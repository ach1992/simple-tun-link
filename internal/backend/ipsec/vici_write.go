package ipsec

import (
	"context"
	"fmt"

	"github.com/strongswan/govici/vici"
)

// ScopedWriter is a narrowly bounded, per-object VICI client. Constructing
// one does NOT authorize direct daemon writes. The Engine must first create
// and durably advance its owner-checked per-Link operation journal under
// canonical locks. This source-only checkpoint intentionally has no CLI
// registration, unload operation, daemon-global reload, or SA initiation.
type ScopedWriter struct{ dial sessionDialer }

// NewScopedWriter uses the same validated Unix-socket-only transport as the
// read-only reader; untrusted environment paths never select remote TCP.
func NewScopedWriter(socketPath string) (ScopedWriter, error) {
	reader, err := NewReader(socketPath)
	if err != nil {
		return ScopedWriter{}, err
	}
	return ScopedWriter{dial: reader.dial}, nil
}

func (w ScopedWriter) withSession(ctx context.Context, call func(Session) error) error {
	if ctx == nil || w.dial == nil {
		return fmt.Errorf("scoped VICI transport unavailable")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("scoped VICI call interrupted")
	}
	s, err := w.dial(ctx)
	if err != nil || s == nil {
		return fmt.Errorf("scoped VICI connection unavailable")
	}
	// A successful daemon reply followed by a failed close is uncertain
	// from the caller's perspective, not permission to retry an effect.
	callErr := call(s)
	closeErr := s.Close()
	if callErr != nil {
		return callErr
	}
	if closeErr != nil || ctx.Err() != nil {
		return fmt.Errorf("scoped VICI command outcome uncertain")
	}
	return nil
}

// LoadShared adds ONLY the exact Link-owned named IKE PSK, scoped to the two
// canonical IKE endpoint identities. Both name and owner identities are
// derived from the full Link ID. Response details are untrusted/secret-bearing;
// never include library error, daemon stderr or message contents in errors.
func (w ScopedWriter) LoadShared(ctx context.Context, p Profile, key *PSK) error {
	if err := p.validateIdentity(); err != nil || key == nil {
		return fmt.Errorf("invalid scoped VICI shared-key identity")
	}
	material := key.SecretBytes()
	defer clear(material)
	checked, err := ParsePSK(material)
	if err != nil {
		return fmt.Errorf("invalid protected per-Link PSK")
	}
	checked.Zeroize()
	req := vici.NewMessage()
	if err := req.Set("id", p.SecretName); err != nil {
		return fmt.Errorf("cannot form scoped VICI shared-key request")
	}
	if err := req.Set("type", "IKE"); err != nil {
		return fmt.Errorf("cannot form scoped VICI shared-key request")
	}
	if err := req.Set("owners", []string{p.LocalIKEID, p.PeerIKEID}); err != nil {
		return fmt.Errorf("cannot form scoped VICI shared-key request")
	}
	// VICI represents binary values as length-prefixed strings, not argv
	// text or hex-encoded configuration. This field is never logged. govici
	// marshaling necessarily allocates transient transport copies; no data
	// can be included in an error even when that encoding fails.
	if err := req.Set("data", string(material)); err != nil {
		return fmt.Errorf("cannot form scoped VICI shared-key request")
	}
	defer req.Unset("data")
	return w.withSession(ctx, func(s Session) error {
		reply, err := s.Call(ctx, "load-shared", req)
		if err != nil || reply == nil || reply.Get("success") != "yes" {
			return fmt.Errorf("scoped VICI shared-key outcome uncertain")
		}
		return nil
	})
}

// LoadConnection loads ONLY the one canonical connection. It has
// start_action=none, cannot initiate IKE or install policies, and must not
// run before Engine recorded a durable issuing-connection marker and
// rechecked daemon-wide name vacancy.
func (w ScopedWriter) LoadConnection(ctx context.Context, p Profile) error {
	req, err := p.ConnectionRequest()
	if err != nil {
		return fmt.Errorf("invalid scoped VICI connection intent")
	}
	return w.withSession(ctx, func(s Session) error {
		reply, err := s.Call(ctx, "load-conn", req)
		if err != nil || reply == nil || reply.Get("success") != "yes" {
			return fmt.Errorf("scoped VICI connection outcome uncertain")
		}
		return nil
	})
}
