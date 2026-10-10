package ipsec

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/strongswan/govici/vici"
)

type scopedWriteSession struct {
	t          *testing.T
	calls      []string
	secret     []byte
	secretName string
	owners     []string
	conn       string
	forcedErr  error
	noSuccess  bool
	closed     bool
	closeErr   error
}

func (s *scopedWriteSession) Call(_ context.Context, command string, req *vici.Message) (*vici.Message, error) {
	s.t.Helper()
	if req == nil {
		s.t.Fatal("nil scoped VICI request")
	}
	s.calls = append(s.calls, command)
	switch command {
	case "load-shared":
		if !reflect.DeepEqual(req.Keys(), []string{"id", "type", "owners", "data"}) ||
			req.Get("type") != "IKE" {
			s.t.Fatal("not a bounded IKE PSK load")
		}
		s.secretName, _ = req.Get("id").(string)
		s.owners, _ = req.Get("owners").([]string)
		payload, ok := req.Get("data").(string)
		if !ok {
			s.t.Fatal("raw IKE PSK not passed through length-prefixed VICI field")
		}
		s.secret = []byte(payload)
	case "load-conn":
		if len(req.Keys()) != 1 {
			s.t.Fatal("VICI writer tried multi-object load")
		}
		s.conn = req.Keys()[0]
		cfg, ok := req.Get(s.conn).(*vici.Message)
		if !ok || cfg.Get("version") != "2" || cfg.Get("mobike") != "no" {
			s.t.Fatal("writer lost canonical IKEv2 scope")
		}
	default:
		s.t.Fatalf("unauthorized VICI write command: %s", command)
	}
	if s.forcedErr != nil {
		return nil, s.forcedErr
	}
	reply := vici.NewMessage()
	if !s.noSuccess {
		if err := reply.Set("success", "yes"); err != nil {
			s.t.Fatal(err)
		}
	} else {
		if err := reply.Set("success", "no"); err != nil {
			s.t.Fatal(err)
		}
		if err := reply.Set("errmsg", "SENSITIVE daemon stderr and key"); err != nil {
			s.t.Fatal(err)
		}
	}
	return reply, nil
}
func (s *scopedWriteSession) CallStreaming(context.Context, string, string, *vici.Message) iter.Seq2[*vici.Message, error] {
	return func(func(*vici.Message, error) bool) { s.t.Fatal("scoped VICI writer attempted an unrelated stream") }
}
func (s *scopedWriteSession) Close() error { s.closed = true; return s.closeErr }

func TestScopedVICIWriterUsesOnlyExactPerLinkCommands(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapNATT))
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x73}, 32)
	secret[7] = 0 // binary PSK with an embedded NUL; VICI values are length-prefixed
	key, err := ParsePSK(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zeroize()
	s := &scopedWriteSession{t: t}
	writer := ScopedWriter{dial: func(context.Context) (Session, error) { return s, nil }}
	if err := writer.LoadShared(context.Background(), p, &key); err != nil {
		t.Fatal(err)
	}
	if !s.closed || !reflect.DeepEqual(s.calls, []string{"load-shared"}) ||
		s.secretName != p.SecretName ||
		!reflect.DeepEqual(s.owners, []string{p.LocalIKEID, p.PeerIKEID}) ||
		!bytes.Equal(s.secret, secret) {
		t.Fatal("key load not strictly bound to one profile and two IKE identities")
	}
	clear(s.secret)
	s.closed = false
	if err := writer.LoadConnection(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if !s.closed || !reflect.DeepEqual(s.calls, []string{"load-shared", "load-conn"}) ||
		s.conn != p.ConnectionName {
		t.Fatal("wrong connection load scope")
	}
}

func TestScopedVICIWriterRejectsUntrustedRepliesAndMalformedInputs(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePSK(bytes.Repeat([]byte{0x81}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zeroize()
	for _, tc := range []struct {
		name      string
		err       error
		noSuccess bool
		closeErr  error
	}{
		{"transport-reply-error", errors.New("SENSITIVE raw daemon socket error"), false, nil},
		{"daemon-rejection", nil, true, nil},
		{"close-failure", nil, false, errors.New("SENSITIVE ambiguous closure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scopedWriteSession{t: t, forcedErr: tc.err, noSuccess: tc.noSuccess, closeErr: tc.closeErr}
			writer := ScopedWriter{dial: func(context.Context) (Session, error) { return s, nil }}
			e := writer.LoadShared(context.Background(), p, &key)
			if e == nil || strings.Contains(e.Error(), "SENSITIVE") || !s.closed {
				t.Fatalf("untrusted VICI failure accepted or leaked: %v", e)
			}
			clear(s.secret)
			s = &scopedWriteSession{t: t, forcedErr: tc.err, noSuccess: tc.noSuccess, closeErr: tc.closeErr}
			writer = ScopedWriter{dial: func(context.Context) (Session, error) { return s, nil }}
			e = writer.LoadConnection(context.Background(), p)
			if e == nil || strings.Contains(e.Error(), "SENSITIVE") || !s.closed {
				t.Fatalf("untrusted VICI connection failure accepted or leaked: %v", e)
			}
		})
	}
	count := 0
	writer := ScopedWriter{dial: func(context.Context) (Session, error) { count++; return &scopedWriteSession{t: t}, nil }}
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writer.LoadShared(cancelCtx, p, &key); err == nil || count != 0 {
		t.Fatal("cancelled writer sent request")
	}
	if err := writer.LoadConnection(cancelCtx, p); err == nil || count != 0 {
		t.Fatal("cancelled writer loaded config")
	}
	bad := p
	bad.ConnectionName = "foreign"
	if err := writer.LoadConnection(context.Background(), bad); err == nil || count != 0 {
		t.Fatal("uncanonical profile used for VICI mutation")
	}
	if err := writer.LoadShared(context.Background(), p, nil); err == nil || count != 0 {
		t.Fatal("missing PSK triggered VICI mutation")
	}
	zero := PSK{}
	if err := writer.LoadShared(context.Background(), p, &zero); err == nil || count != 0 {
		t.Fatal("zeroed PSK loaded into strongSwan")
	}
	if _, err := NewScopedWriter("./not-a-socket"); err == nil {
		t.Fatal("relative VICI endpoint accepted")
	}
}
