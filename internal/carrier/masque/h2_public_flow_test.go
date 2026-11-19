package masque

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Use independent read/write framers over a genuine TLS/ALPN=h2 socket.
// All assertions below see the actual peer-visible HTTP/2 frames and credit.
type publicH2WirePeer struct {
	conn                  *tls.Conn
	reader                *http2.Framer
	writer                *http2.Framer
	out                   *bufio.Writer
	port                  string
	advertisedConcurrency uint32
}

func publicH2WireFixture(t *testing.T) (string, *x509.CertPool, string, *channelPrivatePipe) {
	t.Helper()
	identity, roots := testTLS(t)
	addr := availableListener(t)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x67}, 32))
	pipe := &channelPrivatePipe{toClient: make(chan []byte, 8), toServer: make(chan []byte, 8)}
	srv, err := NewH2Server(H2ListenConfig{
		ListenAddress: addr, TLSServerName: "masque-test.invalid",
		ServerCert: identity, PublicTLS: true, BearerToken: []byte(token),
		LocalIPv4: netip.MustParseAddr("10.251.95.1"),
		PeerIPv4:  netip.MustParseAddr("10.251.95.2"),
	}, pipe)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("public H2 test listener shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("public H2 test listener did not stop")
		}
	})
	for i := 0; i < 100; i++ {
		raw, err := net.DialTimeout("tcp", addr, 80*time.Millisecond)
		if err == nil {
			raw.Close()
			return addr, roots, token, pipe
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("public H2 test listener failed to bind")
	return "", nil, "", nil
}

func newPublicH2WirePeer(t *testing.T, addr string, roots *x509.CertPool, initialWindow uint32) *publicH2WirePeer {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{
		RootCAs: roots, ServerName: "masque-test.invalid",
		NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("public TLS ALPN h2 not negotiated")
	}
	_, port, _ := net.SplitHostPort(addr)
	out := bufio.NewWriter(conn)
	p := &publicH2WirePeer{conn: conn, reader: http2.NewFramer(nil, conn),
		writer: http2.NewFramer(out, nil), out: out, port: port}
	p.reader.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if _, err := out.WriteString(http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	if err := p.writer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: initialWindow}); err != nil {
		t.Fatal(err)
	}
	p.flush(t)
	serverSettings, clientSettingsAck := false, false
	for !(serverSettings && clientSettingsAck) {
		f := p.next(t)
		if s, ok := f.(*http2.SettingsFrame); ok {
			if s.IsAck() {
				clientSettingsAck = true
			} else {
				serverSettings = true
				if err := s.ForeachSetting(func(setting http2.Setting) error {
					if setting.ID == http2.SettingMaxConcurrentStreams {
						p.advertisedConcurrency = setting.Val
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := p.writer.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
				p.flush(t)
			}
		}
	}
	return p
}

func (p *publicH2WirePeer) flush(t *testing.T) {
	t.Helper()
	if err := p.out.Flush(); err != nil {
		t.Fatal(err)
	}
}

func (p *publicH2WirePeer) next(t *testing.T) http2.Frame {
	t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	f, err := p.reader.ReadFrame()
	if err != nil {
		t.Fatal("expected HTTP/2 frame:", err)
	}
	return f
}

func (p *publicH2WirePeer) noFrame(t *testing.T) {
	t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(65 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	f, err := p.reader.ReadFrame()
	if err == nil {
		t.Fatalf("unexpected frame without HTTP/2 DATA credit: %+v", f.Header())
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a read timeout while DATA window is exhausted; got %v", err)
	}
}

func (p *publicH2WirePeer) get(t *testing.T, id uint32, method, path string) {
	t.Helper()
	p.request(t, id, method, path, true)
}

func (p *publicH2WirePeer) request(t *testing.T, id uint32, method, path string, endStream bool) {
	t.Helper()
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: method}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: net.JoinHostPort("masque-test.invalid", p.port)},
		{Name: ":path", Value: path},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.writer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, EndHeaders: true, EndStream: endStream, BlockFragment: block.Bytes(),
	}); err != nil {
		t.Fatal(err)
	}
	p.flush(t)
}

func (p *publicH2WirePeer) headers(t *testing.T, id uint32, code string, endStream bool) {
	t.Helper()
	for {
		f := p.next(t)
		if _, ok := f.(*http2.WindowUpdateFrame); ok {
			continue
		}
		h, ok := f.(*http2.MetaHeadersFrame)
		if !ok || h.StreamID != id || h.PseudoValue("status") != code || h.StreamEnded() != endStream {
			t.Fatalf("expected stream %d HTTP %s headers end=%v; got %+v", id, code, endStream, f)
		}
		return
	}
}

func (p *publicH2WirePeer) data(t *testing.T, id uint32, want []byte, endStream bool) {
	t.Helper()
	f := p.next(t)
	data, ok := f.(*http2.DataFrame)
	if !ok || data.StreamID != id || !bytes.Equal(data.Data(), want) || data.StreamEnded() != endStream {
		t.Fatalf("stream %d DATA end=%v expected %q; got %+v", id, endStream, want, f)
	}
}

func (p *publicH2WirePeer) credit(t *testing.T, id uint32, n uint32) {
	t.Helper()
	if err := p.writer.WriteWindowUpdate(id, n); err != nil {
		t.Fatal(err)
	}
	p.flush(t)
}

func (p *publicH2WirePeer) settings(t *testing.T, window uint32) {
	t.Helper()
	if err := p.writer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window}); err != nil {
		t.Fatal(err)
	}
	p.flush(t)
	for {
		f := p.next(t)
		if settings, ok := f.(*http2.SettingsFrame); ok && settings.IsAck() {
			return
		}
		t.Fatalf("expected SETTINGS ACK, got %+v", f)
	}
}

func TestMASQUEPublicH2ExactWireStreamWindowsAndCancellation(t *testing.T) {
	addr, roots, _, _ := publicH2WireFixture(t)
	p := newPublicH2WirePeer(t, addr, roots, 0)
	page := []byte("STL MASQUE HTTP/2 endpoint\n")
	missing := []byte("Not Found\n")

	p.get(t, 1, "GET", "/")
	p.headers(t, 1, "200", false)
	p.noFrame(t) // Zero stream credit: only HEADERS, never DATA.

	p.get(t, 3, "HEAD", "/")
	p.headers(t, 3, "200", true)
	p.noFrame(t) // HEAD terminates in HEADERS, not DATA.

	p.get(t, 5, "GET", "/not-found")
	p.headers(t, 5, "404", false)
	p.credit(t, 5, 3)
	p.data(t, 5, missing[:3], false)
	p.noFrame(t) // Stream 5's credit cannot be borrowed by stream 1.

	p.credit(t, 1, 5)
	p.data(t, 1, page[:5], false)
	p.noFrame(t)
	p.credit(t, 1, uint32(len(page)-5))
	p.data(t, 1, page[5:], true)
	p.credit(t, 5, uint32(len(missing)-3))
	p.data(t, 5, missing[3:], true)

	p.get(t, 7, "GET", "/")
	p.headers(t, 7, "200", false)
	p.credit(t, 7, uint32(len(page)))
	p.data(t, 7, page, true)

	// A previously closed stream's WINDOW_UPDATE must not credit new streams.
	p.credit(t, 1, 100)
	p.get(t, 9, "GET", "/")
	p.headers(t, 9, "200", false)
	p.noFrame(t)
	p.credit(t, 9, uint32(len(page)))
	p.data(t, 9, page, true)

	// Optional review concern: RST_STREAM on a pending ordinary public
	// response cancels only that stream, preserving the H2 connection.
	p.get(t, 11, "GET", "/")
	p.headers(t, 11, "200", false)
	if err := p.writer.WriteRSTStream(11, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	p.credit(t, 11, uint32(len(page)))
	p.get(t, 13, "GET", "/")
	p.headers(t, 13, "200", false)
	p.credit(t, 13, uint32(len(page)))
	p.data(t, 13, page, true)
	p.noFrame(t)
}

func TestMASQUEPublicH2ExactWireSettingsChangeWhileResponsePending(t *testing.T) {
	addr, roots, _, _ := publicH2WireFixture(t)
	p := newPublicH2WirePeer(t, addr, roots, 0)
	page := []byte("STL MASQUE HTTP/2 endpoint\n")
	p.get(t, 1, "GET", "/")
	p.headers(t, 1, "200", false)
	p.settings(t, 4) // SETTINGS adjusts the still-pending public stream.
	p.data(t, 1, page[:4], false)
	p.noFrame(t)
	p.settings(t, 0)
	p.noFrame(t)
	// Shrinking INITIAL_WINDOW_SIZE from 4 to 0 makes this active
	// stream's window -4 (it already sent 4 bytes). Replenish that
	// debt as well as the remaining payload credit.
	p.credit(t, 1, uint32(len(page)))
	p.data(t, 1, page[4:], true)
}

func TestMASQUEPublicH2ExactWireConnectionWindowExhaustion(t *testing.T) {
	addr, roots, _, _ := publicH2WireFixture(t)
	p := newPublicH2WirePeer(t, addr, roots, 65535)
	page := []byte("STL MASQUE HTTP/2 endpoint\n")
	full := 65535 / len(page)
	for i := 0; i < full; i++ {
		id := uint32(2*i + 1)
		p.get(t, id, "GET", "/")
		p.headers(t, id, "200", false)
		p.data(t, id, page, true)
	}
	remaining := 65535 - full*len(page)
	id := uint32(2*full + 1)
	p.get(t, id, "GET", "/")
	p.headers(t, id, "200", false)
	if remaining > 0 {
		p.data(t, id, page[:remaining], false)
	}
	second := id + 2
	p.get(t, second, "GET", "/")
	p.headers(t, second, "200", false)
	p.noFrame(t) // Both streams have credit; the connection has NONE.

	// Connection-level WINDOW_UPDATE replenishes the shared pool, without
	// manufacturing stream credit, and both pending responses can finish.
	p.credit(t, 0, uint32(2*len(page)))
	got := make(map[uint32][]byte)
	finished := map[uint32]bool{}
	for len(finished) < 2 {
		frame := p.next(t)
		data, ok := frame.(*http2.DataFrame)
		if !ok || (data.StreamID != id && data.StreamID != second) {
			t.Fatalf("unexpected H2 frame after connection refill: %+v", frame)
		}
		got[data.StreamID] = append(got[data.StreamID], data.Data()...)
		if data.StreamEnded() {
			finished[data.StreamID] = true
		}
	}
	if !bytes.Equal(got[id], page[remaining:]) || !bytes.Equal(got[second], page) {
		t.Fatalf("connection credit isolation mismatch: id=%q other=%q", got[id], got[second])
	}
	p.get(t, second+2, "HEAD", "/")
	p.headers(t, second+2, "200", true)
	p.noFrame(t)
	t.Logf("verified %d sequential GETs consumed exactly 65535 bytes of connection credit", full+2)
}

func TestMASQUECapsuleStructuredBooleanSyntax(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"?1", true},
		{" ?1 ", true},
		{"?1;feature", true},
		{"?1;feature=?0;other=?1", true},
		{"?1;version=42;quality=0.5", true},
		{"?1;token=foo/bar;message=\"a,b;c\"", true},
		{"?1;bytes=:dGVzdA==:;when=@1659578233", true},
		{"?1;display=%\"caf%c3%a9\"", true},
		{"?1;display=%\"\"", true},
		{"?1;display=%\"x\"", true},
		{"?1;bytes=:dGVzdA:", true},
		{"?1;bytes=:dGVzdA=:", true},
		{"?1;bytes=::", true},
		{"?1;display=%\"caf%c3%a9\"", true},
		{"?1;display=%\"literal\\backslash\"", true},
		{"?1;feature=foo; extra=?1", true},
		{"?1;feature=one;feature=two", true},
		{"?1;bytes=:dGVzdA!:", false},
		{"?1;bytes=:dGVzdA===:", false},
		{"?1;bytes=:dGV\\nzdA==:", false},
		{"?1;display=%\"%ff\"", false},
		{"?1;display=%\"%FF\"", false},
		{"?1;display=%\"caf%C3%A9\"", false},
		{"?1;display=%\"%c3%28\"", false},
		{"?1;display=%\"%c3\"", false},
		// A partial Display String must never reach make() with a negative
		// capacity, including when the request has no bearer authorization.
		{"?1;flag=%", false},
		{"?1;flag=%\"", false},
		{"?1;flag=%\"x", false},
		{"?1;flag=%\"%", false},
		{"?1;flag=%\"%f", false},
		{"?1;flag=%\"%ff", false},
		{"?1 ;feature", false},
		{"?1\t;feature", false},
		{"?1;\tfeature", false},
		{"?1;feature=one ;other", false},
		{"?0", false},
		{"?1, ?0", false},
		{"?1;feature=?2", false},
		{"?1;feature=", false},
		{"?1;feature=foo bar", false},
		{"?1;feature=:", false},
		{"?1;feature=\"bad\\z\"", false},
		{"?1;Feature=1", false},
		{"?1;feature=1.2345", false},
		{"?1;;feature", false},
	} {
		if got := capsuleProtocolTrue(tc.value); got != tc.valid {
			t.Errorf("capsule-protocol %q: got %v want %v", tc.value, got, tc.valid)
		}
	}
}

// Send real HPACK-encoded CONNECT-IP requests directly to the TLS listener,
// with correct bearer and topology. These negative cases bypass client-side
// validation and prove malformed Capsule-Protocol messages cannot be
// admitted even though authentication is otherwise correct.
func TestMASQUEPublicH2ExactWireCapsuleProtocolAdmission(t *testing.T) {
	single := func(value string) []hpack.HeaderField {
		return []hpack.HeaderField{{Name: "capsule-protocol", Value: value}}
	}
	for _, tc := range []struct {
		label    string
		capsule  []hpack.HeaderField
		extra    []hpack.HeaderField
		expected string
	}{
		{label: "missing capsule", expected: "403"},
		{label: "false capsule", capsule: single("?0"), expected: "403"},
		{label: "duplicate true then false", capsule: []hpack.HeaderField{
			{Name: "capsule-protocol", Value: "?1"}, {Name: "capsule-protocol", Value: "?0"},
		}, expected: "403"},
		{label: "duplicate true true", capsule: []hpack.HeaderField{
			{Name: "capsule-protocol", Value: "?1"}, {Name: "capsule-protocol", Value: "?1"},
		}, expected: "403"},
		{label: "combined list", capsule: single("?1,?0"), expected: "403"},
		{label: "nonboolean", capsule: single("1"), expected: "403"},
		{label: "malformed parameter", capsule: single("?1;ext=?2"), expected: "403"},
		{label: "content length", capsule: single("?1"), extra: []hpack.HeaderField{
			{Name: "content-length", Value: "0"},
		}, expected: "403"},
		{label: "content type", capsule: single("?1"), extra: []hpack.HeaderField{
			{Name: "content-type", Value: "application/octet-stream"},
		}, expected: "403"},
		{label: "transfer encoding", capsule: single("?1"), extra: []hpack.HeaderField{
			{Name: "transfer-encoding", Value: "chunked"},
		}, expected: "403"},
		{label: "valid unpadded base64", capsule: single("?1;bytes=:dGVzdA:"), expected: "200"},
		{label: "valid partially padded base64", capsule: single("?1;bytes=:dGVzdA=:"), expected: "200"},
		{label: "valid UTF-8 display", capsule: single("?1;display=%\"caf%c3%a9\""), expected: "200"},
		{label: "malformed base64", capsule: single("?1;bytes=:dGVzdA!:"), expected: "403"},
		{label: "malformed display invalid UTF-8", capsule: single("?1;label=%\"%ff\""), expected: "403"},
		{label: "malformed display uppercase escape", capsule: single("?1;label=%\"%FF\""), expected: "403"},
		{label: "malformed parameter whitespace", capsule: single("?1 ;flag"), expected: "403"},
		{label: "valid true unknown parameters", capsule: single("?1;flag;version=2;note=\"ok\""), expected: "200"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			addr, roots, token, pipe := publicH2WireFixture(t)
			bearer := hpack.HeaderField{Name: "authorization", Value: "Bearer " + token}
			extra := append([]hpack.HeaderField{bearer}, tc.extra...)
			status := rawPublicH2ConnectStatusWithCapsules(t, addr, roots, "", "",
				tc.capsule, extra)
			if status != tc.expected {
				t.Errorf("%s: HTTP %s, expected %s", tc.label, status, tc.expected)
			}
			select {
			case packet := <-pipe.toServer:
				t.Fatalf("%s reached private packet interface: %x", tc.label, packet)
			default:
			}
		})
	}
}

// A requester that already used stream 1 for an ordinary HEAD must not
// resurrect that HTTP/2 stream as authenticated CONNECT-IP on the same
// socket, even with an otherwise valid per-Link bearer.
func TestMASQUEPublicH2CannotReusePublicStreamForCONNECTIP(t *testing.T) {
	addr, roots, token, pipe := publicH2WireFixture(t)
	p := newPublicH2WirePeer(t, addr, roots, 65535)
	p.get(t, 1, "HEAD", "/")
	p.headers(t, 1, "200", true)

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: net.JoinHostPort("masque-test.invalid", p.port)},
		{Name: ":path", Value: "/.well-known/masque/ip/"},
		{Name: ":protocol", Value: "connect-ip"},
		{Name: "capsule-protocol", Value: "?1"},
		{Name: "authorization", Value: "Bearer " + token},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.writer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, EndHeaders: true, BlockFragment: block.Bytes(),
	}); err != nil {
		t.Fatal(err)
	}
	p.flush(t)
	frame := p.next(t)
	goaway, ok := frame.(*http2.GoAwayFrame)
	if !ok || goaway.ErrCode != http2.ErrCodeProtocol {
		t.Fatalf("reused closed stream should trigger PROTOCOL_ERROR GOAWAY, never HEADERS: %+v", frame)
	}
	select {
	case packet := <-pipe.toServer:
		t.Fatalf("reused HTTP/2 public stream reached private TUN: %x", packet)
	default:
	}
}

// An RFC 9113 maximum concurrency advertisement is enforced even when
// a peer ignores it. Under stream-window zero, public replies remain
// bounded and new HEADERS do not cause O(N) blocked-response scans.
func TestMASQUEPublicH2PendingZeroWindowBudgetAndRecovery(t *testing.T) {
	addr, roots, _, pipe := publicH2WireFixture(t)
	p := newPublicH2WirePeer(t, addr, roots, 0)
	if p.advertisedConcurrency != publicH2ConcurrentStreams {
		t.Fatalf("expected advertised public H2 concurrency %d, got %d",
			publicH2ConcurrentStreams, p.advertisedConcurrency)
	}
	page := []byte("STL MASQUE HTTP/2 endpoint\n")
	for i := 0; i < publicH2ConcurrentStreams; i++ {
		id := uint32(2*i + 1)
		p.get(t, id, "GET", "/")
		p.headers(t, id, "200", false)
	}
	p.noFrame(t)

	refusedID := uint32(2*publicH2ConcurrentStreams + 1)
	p.get(t, refusedID, "GET", "/")
	reset, ok := p.next(t).(*http2.RSTStreamFrame)
	if !ok || reset.StreamID != refusedID || reset.ErrCode != http2.ErrCodeRefusedStream {
		t.Fatalf("excess pending GET was not refused on its own stream: %+v", reset)
	}

	// RFC 9113 counts all active streams, including requests whose
	// response is only HEADERS. At capacity, both HEAD and unsupported
	// POST are refused on their own IDs rather than bypassing the limit.
	headRefusedID := refusedID + 2
	p.get(t, headRefusedID, "HEAD", "/")
	reset, ok = p.next(t).(*http2.RSTStreamFrame)
	if !ok || reset.StreamID != headRefusedID || reset.ErrCode != http2.ErrCodeRefusedStream {
		t.Fatalf("excess HEAD was not refused on its own stream: %+v", reset)
	}
	postRefusedID := headRefusedID + 2
	p.get(t, postRefusedID, "POST", "/")
	reset, ok = p.next(t).(*http2.RSTStreamFrame)
	if !ok || reset.StreamID != postRefusedID || reset.ErrCode != http2.ErrCodeRefusedStream {
		t.Fatalf("excess unsupported POST was not refused on its own stream: %+v", reset)
	}

	// WINDOW_UPDATE for the connection does not help zero-credit streams;
	// repeated updates must not inspect or emit from the blocked map.
	for i := 0; i < 20; i++ {
		p.credit(t, 0, 1)
	}
	p.noFrame(t)

	// A completed response frees one slot. HEAD below capacity succeeds
	// without DATA, then a new GET occupies the freed slot.
	p.credit(t, 1, uint32(len(page)))
	p.data(t, 1, page, true)
	headAllowedID := postRefusedID + 2
	p.get(t, headAllowedID, "HEAD", "/")
	p.headers(t, headAllowedID, "200", true)
	nextID := headAllowedID + 2
	p.get(t, nextID, "GET", "/")
	p.headers(t, nextID, "200", false)

	// Cancel another blocked response; it also releases its pending slot.
	if err := p.writer.WriteRSTStream(3, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	p.flush(t)
	afterCancelID := nextID + 2
	p.get(t, afterCancelID, "GET", "/")
	p.headers(t, afterCancelID, "200", false)

	p.credit(t, nextID, uint32(len(page)))
	p.data(t, nextID, page, true)
	p.credit(t, afterCancelID, uint32(len(page)))
	p.data(t, afterCancelID, page, true)
	select {
	case packet := <-pipe.toServer:
		t.Fatalf("anonymous public HTTP entered private TUN: %x", packet)
	default:
	}
}

func TestMASQUEPublicH2PendingSchedulerExcludesZeroWindowStreams(t *testing.T) {
	var writer bytes.Buffer
	buf := bufio.NewWriter(&writer)
	h := &h2ServerConn{
		fr: http2.NewFramer(buf, nil), buf: buf,
		peerFrameSize: 16384, peerInitialWindow: 0, connWindow: 65535,
	}
	for i := 0; i < publicH2ConcurrentStreams; i++ {
		if err := h.replyPublicHTTP(uint32(2*i+1), "GET", true); err != nil {
			t.Fatal(err)
		}
		if got := h.publicReady.Len(); got != 0 {
			t.Fatalf("zero-credit GET caused queued work on iteration %d: %d", i, got)
		}
	}
	if got := len(h.publicReplies); got != publicH2ConcurrentStreams {
		t.Fatalf("stored %d pending replies, wanted %d", got, publicH2ConcurrentStreams)
	}
	// Admission on every new H2 stream is enforced in the live framer
	// before calling replyPublicHTTP, exercised by the exact-wire test
	// above. This unit only probes the no-scan ready-list behavior.
	// Processing has zero eligible streams regardless of how many blocked
	// streams exist, so a no-credit update requires no per-request scan.
	for i := 0; i < 200; i++ {
		if err := h.flushPublicData(); err != nil {
			t.Fatal(err)
		}
		if got := h.publicReady.Len(); got != 0 {
			t.Fatalf("blocked replies unexpectedly queued work: %d", got)
		}
	}
	h.dropPublicReply(1)
	if len(h.publicReplies) != publicH2ConcurrentStreams-1 || h.publicReady.Len() != 0 {
		t.Fatal("public response cancellation did not release bounded pending state")
	}
}

func TestMASQUEPublicH2RejectedMethodsUseTheirOwnStreams(t *testing.T) {
	addr, roots, _, pipe := publicH2WireFixture(t)
	p := newPublicH2WirePeer(t, addr, roots, 65535)
	page := []byte("STL MASQUE HTTP/2 endpoint\n")

	// First, close stream 1 with HEAD. Unsupported method on 3 must be
	// rejected on 3, not reopen stream 1.
	p.get(t, 1, "HEAD", "/")
	p.headers(t, 1, "200", true)
	p.get(t, 3, "POST", "/")
	p.headers(t, 3, "400", true)

	// On a new, legal stream 5, CONNECT-IP is rejected on 5 as well.
	p.get(t, 5, "CONNECT", "/.well-known/masque/ip/")
	p.headers(t, 5, "403", true)

	// Multiple different methods and stream IDs may safely share one
	// connection; invalid requests never poison later GET/HEAD.
	p.get(t, 7, "GET", "/")
	p.headers(t, 7, "200", false)
	p.data(t, 7, page, true)
	p.get(t, 9, "POST", "/missing")
	p.headers(t, 9, "400", true)
	p.get(t, 11, "HEAD", "/")
	p.headers(t, 11, "200", true)

	// A rejected request without END_STREAM must be reset, not left as
	// a half-closed HTTP/2 stream that bypasses concurrency accounting.
	p.request(t, 13, "POST", "/", false)
	reset, ok := p.next(t).(*http2.RSTStreamFrame)
	if !ok || reset.StreamID != 13 || reset.ErrCode != http2.ErrCodeProtocol {
		t.Fatalf("open unsupported request not reset on its own stream: %+v", reset)
	}
	p.get(t, 15, "GET", "/")
	p.headers(t, 15, "200", false)
	p.data(t, 15, page, true)

	select {
	case packet := <-pipe.toServer:
		t.Fatalf("rejected request reached private packet path: %x", packet)
	default:
	}
}

// A malformed Capsule-Protocol Display String is parsed before the full
// Authorization result is available. The exact two-byte opening prefix used
// to give make() a negative capacity, crashing the entire production helper.
// Exercise it repeatedly as an anonymous TLS/H2 peer and then prove this
// listener still admits a properly authenticated private packet session.
func TestMASQUEPublicH2UnauthenticatedTruncatedDisplayDoesNotCrashListener(t *testing.T) {
	addr, roots, token, pipe := publicH2WireFixture(t)
	for _, value := range []string{
		"?1;flag=%\"",
		"?1;flag=%\"x",
		"?1;flag=%\"%",
		"?1;flag=%\"%f",
	} {
		for attempt := 0; attempt < 3; attempt++ {
			status := rawPublicH2ConnectStatusWithCapsules(t, addr, roots, "", "",
				[]hpack.HeaderField{{Name: "capsule-protocol", Value: value}}, nil)
			if status != "403" {
				t.Fatalf("anonymous malformed capsule %q attempt %d: HTTP %s; want 403",
					value, attempt, status)
			}
		}
	}
	select {
	case packet := <-pipe.toServer:
		t.Fatalf("anonymous malformed request reached private TUN: %x", packet)
	default:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	link, err := DialH2(ctx, H2Config{
		Address: addr, ServerName: "masque-test.invalid", Roots: roots,
		ExpectedIPv4:   netip.MustParseAddr("10.251.95.2"),
		ConnectTimeout: 2 * time.Second, BearerToken: token,
	})
	if err != nil {
		t.Fatalf("valid authorized CONNECT-IP after anonymous malformed requests failed: %v", err)
	}
	defer link.Close()

	request := testPacket()
	if err := link.SendPackets(ctx, [][]byte{request}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-pipe.toServer:
		if !bytes.Equal(got, request) {
			t.Fatalf("valid authenticated private inbound IP differs: got %x want %x", got, request)
		}
	case <-ctx.Done():
		t.Fatal("authenticated private inbound IP was not forwarded after malformed HTTP/2 requests")
	}

	reply := bytes.Clone(request)
	copy(reply[12:16], []byte{10, 251, 95, 1})
	copy(reply[16:20], []byte{10, 251, 95, 2})
	pipe.toClient <- reply
	got, err := link.ReadPacket(ctx)
	if err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("valid authenticated private reply after malformed requests: %v", err)
	}
}
