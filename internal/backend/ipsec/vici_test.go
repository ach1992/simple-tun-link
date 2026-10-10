package ipsec

import (
	"context"
	"errors"
	"iter"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/strongswan/govici/vici"
)

// Same-package test seam only: production packages can obtain a Reader via
// NewReader but cannot inject a transport or bypass its Unix socket policy.
func readerWithTestSession(dial sessionDialer) Reader {
	return Reader{dial: dial}
}

func TestReaderTransportIsNotExternallyInjectable(t *testing.T) {
	typeOfReader := reflect.TypeOf(Reader{})
	for i := 0; i < typeOfReader.NumField(); i++ {
		if field := typeOfReader.Field(i); field.IsExported() {
			t.Fatalf("Reader unexpectedly exposes transport-setting field %q", field.Name)
		}
	}
}

type fakeSession struct {
	got       []string
	replies   map[string]*vici.Message
	events    []*vici.Message
	streamErr error
	filter    string
	failAt    string
	errorMsg  string
	closed    bool
}

func (f *fakeSession) Call(_ context.Context, cmd string, in *vici.Message) (*vici.Message, error) {
	if in == nil {
		return nil, errors.New("nil inventory request")
	}
	f.got = append(f.got, cmd)
	if f.failAt == cmd {
		return nil, errors.New(f.errorMsg)
	}
	return f.replies[cmd], nil
}

func (f *fakeSession) CallStreaming(_ context.Context, cmd, event string, in *vici.Message) iter.Seq2[*vici.Message, error] {
	return func(yield func(*vici.Message, error) bool) {
		f.got = append(f.got, cmd)
		if cmd != "list-conns" || event != "list-conn" || in == nil {
			yield(nil, errors.New("unexpected daemon-wide inventory request"))
			return
		}
		f.filter, _ = in.Get("ike").(string)
		for _, item := range f.events {
			if !yield(item, nil) {
				return
			}
		}
		if f.streamErr != nil {
			yield(nil, f.streamErr)
		}
	}
}

func connEvent(t *testing.T, name string) *vici.Message {
	t.Helper()
	section := vici.NewMessage()
	if err := section.Set("version", "IKEv2"); err != nil {
		t.Fatal(err)
	}
	envelope := vici.NewMessage()
	if err := envelope.Set(name, section); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func (f *fakeSession) Close() error {
	f.closed = true
	return nil
}

func messageList(t *testing.T, field string, names []string) *vici.Message {
	t.Helper()
	m := vici.NewMessage()
	if err := m.Set(field, names); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReaderInspectsOnlyExactNamesAndNeverMutatesDaemon(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSession{replies: map[string]*vici.Message{
		"get-conns":  messageList(t, "conns", []string{"foreign-owner-conn", p.ConnectionName}),
		"get-shared": messageList(t, "keys", []string{"foreign-owner-secret", p.SecretName}),
	}}
	r := readerWithTestSession(func(context.Context) (Session, error) { return s, nil })
	got, err := r.Inspect(context.Background(), p)
	if err != nil || !got.ConnectionNamePresent || !got.SecretNamePresent {
		t.Fatalf("lost exact VICI names: %+v %v", got, err)
	}
	if !s.closed || !reflect.DeepEqual(s.got, []string{"get-conns", "list-conns", "get-shared"}) || s.filter != p.ConnectionName {
		t.Fatal("reader must not call any VICI load/unload/clear command")
	}
	s.got, s.closed = nil, false
	s.replies["get-conns"] = messageList(t, "conns", []string{"foreign-owner-conn"})
	s.replies["get-shared"] = messageList(t, "keys", []string{"foreign-owner-secret"})
	got, err = r.Inspect(context.Background(), p)
	if err != nil || got.ConnectionNamePresent || got.SecretNamePresent || !s.closed {
		t.Fatal("foreign identities were claimed as owned")
	}
}

func TestReaderFailsClosedOnUnknownMalformedOrDuplicateInventory(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		conn    *vici.Message
		shared  *vici.Message
		failCmd string
	}{
		{"missing response", nil, messageList(t, "keys", nil), ""},
		{"missing list", vici.NewMessage(), messageList(t, "keys", nil), ""},
		{"duplicate target", messageList(t, "conns", []string{p.ConnectionName, p.ConnectionName}), messageList(t, "keys", nil), ""},
		{"empty identity", messageList(t, "conns", []string{""}), messageList(t, "keys", nil), ""},
		{"missing shared response", messageList(t, "conns", []string{}), nil, ""},
		{"duplicate foreign shared", messageList(t, "conns", []string{}), messageList(t, "keys", []string{"foreign", "foreign"}), ""},
		{"daemon connection failure", nil, nil, "get-conns"},
		{"daemon credential failure", messageList(t, "conns", []string{}), nil, "get-shared"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeSession{replies: map[string]*vici.Message{
				"get-conns": tc.conn, "get-shared": tc.shared,
			}, failAt: tc.failCmd, errorMsg: "secret-redaction-fixture-should-not-appear"}
			r := readerWithTestSession(func(context.Context) (Session, error) { return s, nil })
			_, err := r.Inspect(context.Background(), p)
			if err == nil || strings.Contains(err.Error(), "secret-redaction-fixture") {
				t.Fatal("unsafe VICI inventory was trusted or leaked daemon text")
			}
			if !s.closed {
				t.Fatal("failed VICI inventory leaked open daemon session")
			}
			for _, c := range s.got {
				if !slices.Contains([]string{"get-conns", "list-conns", "get-shared"}, c) {
					t.Fatal("inspector invoked a daemon mutation")
				}
			}
		})
	}
}

// VICI get-conns excludes configs loaded by other strongSwan config
// backends. Operational load-conn REPLACES a same-name daemon object, so
// vacancy must use the complete streamed list-conns view as well.
func TestReaderRejectsForeignBackendConnectionNameCollision(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSession{
		replies: map[string]*vici.Message{
			"get-conns":  messageList(t, "conns", []string{}),
			"get-shared": messageList(t, "keys", []string{}),
		},
		events: []*vici.Message{connEvent(t, p.ConnectionName)},
	}
	r := readerWithTestSession(func(context.Context) (Session, error) { return s, nil })
	got, err := r.Inspect(context.Background(), p)
	if err != nil || !got.ConnectionNamePresent || got.SecretNamePresent || !s.closed {
		t.Fatalf("foreign backend collision lost: %+v %v", got, err)
	}
	if s.filter != p.ConnectionName || !reflect.DeepEqual(s.got, []string{"get-conns", "list-conns", "get-shared"}) {
		t.Fatalf("daemon-wide name probe not performed: %+v", s)
	}
}

// A partially delivered or malformed daemon-wide stream must never be
// mistaken for vacancy, even if the VICI-only view reports zero objects.
func TestReaderFailsClosedOnIncompleteOrAmbiguousAllBackendStream(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	badSection := vici.NewMessage()
	if err := badSection.Set(p.ConnectionName, "not-a-section"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		events []*vici.Message
		err    error
	}{
		{"stream interrupted", nil, errors.New("SENSITIVE daemon stderr")},
		{"stream failed after event", []*vici.Message{connEvent(t, p.ConnectionName)}, errors.New("SENSITIVE daemon stderr")},
		{"nil event", []*vici.Message{nil}, nil},
		{"malformed section", []*vici.Message{badSection}, nil},
		{"unexpected foreign name", []*vici.Message{connEvent(t, "foreign")}, nil},
		{"duplicate target", []*vici.Message{connEvent(t, p.ConnectionName), connEvent(t, p.ConnectionName)}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeSession{
				replies: map[string]*vici.Message{
					"get-conns":  messageList(t, "conns", []string{}),
					"get-shared": messageList(t, "keys", []string{}),
				},
				events: tc.events, streamErr: tc.err,
			}
			r := readerWithTestSession(func(context.Context) (Session, error) { return s, nil })
			got, err := r.Inspect(context.Background(), p)
			if err == nil || strings.Contains(err.Error(), "SENSITIVE") || !s.closed {
				t.Fatalf("unsafe daemon inventory accepted or leaked: %+v %v", got, err)
			}
			if slices.Contains(s.got, "get-shared") {
				t.Fatal("continued credential inventory after untrusted daemon connection view")
			}
		})
	}
}

func TestReaderRefusesUnsafeSocketAndNilDialer(t *testing.T) {
	for _, candidate := range []string{"", ".", "/", "/tmp/../unsafe", "relative/path"} {
		if _, err := NewReader(candidate); err == nil {
			t.Fatalf("accepted unsafe VICI socket path %q", candidate)
		}
	}
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	none := Reader{}
	if _, err = none.Inspect(context.Background(), p); err == nil {
		t.Fatal("nil VICI dialer accepted")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReader(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Inspect(context.Background(), p); err == nil {
		t.Fatal("non-socket VICI endpoint accepted")
	}
	sym := filepath.Join(dir, "vici-link")
	if err := os.Symlink(target, sym); err != nil {
		t.Fatal(err)
	}
	reader, err = NewReader(sym)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Inspect(context.Background(), p); err == nil {
		t.Fatal("symlink VICI endpoint accepted")
	}
}

func TestVICIConnectionPayloadIsPerLinkAndPublicOnly(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		t.Run(string(encap), func(t *testing.T) {
			p, err := NewProfile(testIPsecLink(t, encap))
			if err != nil {
				t.Fatal(err)
			}
			m, err := p.ConnectionRequest()
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Keys()) != 1 || m.Keys()[0] != p.ConnectionName {
				t.Fatal("must load one and only one named VICI connection")
			}
			conn, ok := m.Get(p.ConnectionName).(*vici.Message)
			if !ok {
				t.Fatal("missing IKE connection config")
			}
			if conn.Get("version") != "2" || conn.Get("mobike") != "no" ||
				conn.Get("encap") != map[domain.Encapsulation]string{domain.EncapESP: "no", domain.EncapNATT: "yes"}[encap] {
				t.Fatal("incorrect IKEv2 ESP/NAT-T public intent")
			}
			if got := conn.Get("local_addrs"); !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
				t.Fatal("incorrect bound local underlay", got)
			}
			if got := conn.Get("remote_addrs"); !reflect.DeepEqual(got, []string{"192.0.2.11"}) {
				t.Fatal("incorrect bound peer underlay", got)
			}
			local := conn.Get("local").(*vici.Message)
			remote := conn.Get("remote").(*vici.Message)
			if local.Get("auth") != "psk" || remote.Get("auth") != "psk" ||
				local.Get("id") != p.LocalIKEID || remote.Get("id") != p.PeerIKEID {
				t.Fatal("IKE PSK identities not bound to exact peer profile")
			}
			children := conn.Get("children").(*vici.Message)
			if len(children.Keys()) != 1 || children.Keys()[0] != p.ChildName {
				t.Fatal("invalid exact owned CHILD_SA structure")
			}
			child := children.Get(p.ChildName).(*vici.Message)
			if got := child.Get("local_ts"); !reflect.DeepEqual(got, []string{"10.99.0.0/32"}) {
				t.Fatal("child local selectors escape selected Link", got)
			}
			if got := child.Get("remote_ts"); !reflect.DeepEqual(got, []string{"10.99.0.1/32"}) {
				t.Fatal("child remote selectors escape selected Link", got)
			}
			if child.Get("if_id_in") != strconv.FormatUint(uint64(p.InterfaceID), 10) ||
				child.Get("if_id_out") != strconv.FormatUint(uint64(p.InterfaceID), 10) ||
				child.Get("mode") != "tunnel" || child.Get("start_action") != "none" {
				t.Fatal("unscoped XFRM interface or side-effectful start policy")
			}
			if strings.Contains(m.String(), "secret") || strings.Contains(m.String(), "0.0.0.0/0") ||
				strings.Contains(m.String(), "PRIVATE_KEY") {
				t.Fatal("VICI intent contains unexpected credential or broad traffic selectors")
			}
			other, err := NewProfile(invertTestLink(p.Link))
			if err != nil {
				t.Fatal(err)
			}
			o, err := other.ConnectionRequest()
			if err != nil {
				t.Fatal(err)
			}
			oc := o.Get(other.ConnectionName).(*vici.Message)
			ochild := oc.Get("children").(*vici.Message).Get(other.ChildName).(*vici.Message)
			if !reflect.DeepEqual(ochild.Get("local_ts"), child.Get("remote_ts")) ||
				!reflect.DeepEqual(ochild.Get("remote_ts"), child.Get("local_ts")) {
				t.Fatal("recipient traffic selectors were not inverted")
			}
		})
	}
}

func TestVICIProfileIsRevalidatedBeforeAnyIO(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Profile)
	}{
		{"foreign connection name", func(x *Profile) { x.ConnectionName = "foreign-conn" }},
		{"wrong XFRM id", func(x *Profile) { x.InterfaceID++ }},
		{"changed traffic selectors", func(x *Profile) {
			x.Link.Addresses.Local = x.Link.Addresses.Peer
		}},
		{"mutated IKE identity", func(x *Profile) { x.PeerIKEID = x.LocalIKEID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := p
			tc.mutate(&candidate)
			if _, err := candidate.ConnectionRequest(); err == nil {
				t.Fatal("noncanonical profile created unsafe VICI payload")
			}
			called := false
			r := readerWithTestSession(func(context.Context) (Session, error) {
				called = true
				return &fakeSession{}, nil
			})
			if _, err := r.Inspect(context.Background(), candidate); err == nil || called {
				t.Fatal("noncanonical profile reached daemon socket")
			}
		})
	}
}
