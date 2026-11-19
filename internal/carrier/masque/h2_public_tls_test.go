package masque

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestMASQUEPublicTLSRealHTTP2AndAuthenticatedL3(t *testing.T) {
	serverIdentity, roots := testTLS(t)
	rawToken := bytes.Repeat([]byte{0x47}, 32)
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	pipe := &channelPrivatePipe{toServer: make(chan []byte, 8), toClient: make(chan []byte, 8)}
	addr := availableListener(t)
	srv, err := NewH2Server(H2ListenConfig{
		ListenAddress: addr, TLSServerName: "masque-test.invalid",
		ServerCert: serverIdentity, PublicTLS: true, BearerToken: []byte(token),
		LocalIPv4: netip.MustParseAddr("10.251.95.1"),
		PeerIPv4:  netip.MustParseAddr("10.251.95.2"),
	}, pipe)
	if err != nil {
		t.Fatal(err)
	}
	if srv.TLSConfig().ClientAuth != tls.NoClientCert {
		t.Fatal("public TLS listener unexpectedly asks for a client certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	for i := 0; i < 60; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if i == 59 {
			t.Fatal("public TLS test server never bound:", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A stock x/net/http2 client with NO TLS client certificate must be
	// able to make normal GET/HEAD requests on the exact CONNECT-IP listener.
	var transportDials atomic.Int32
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "masque-test.invalid", MinVersion: tls.VersionTLS12},
		DialTLSContext: func(ctx context.Context, network, _ string, config *tls.Config) (net.Conn, error) {
			transportDials.Add(1)
			raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, config)
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	_, port, _ := net.SplitHostPort(addr)
	url := "https://masque-test.invalid:" + port + "/"
	for _, tc := range []struct {
		method, path string
		status       int
		want         string
	}{
		{method: "GET", path: "", status: 200, want: "STL MASQUE HTTP/2 endpoint\n"},
		{method: "HEAD", path: "", status: 200, want: ""},
		{method: "GET", path: "not-found", status: 404, want: "Not Found\n"},
	} {
		req, err := http.NewRequestWithContext(ctx, tc.method, url+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("stock H2 %s %s: %v", tc.method, tc.path, err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.ProtoMajor != 2 || res.StatusCode != tc.status || string(body) != tc.want {
			t.Fatalf("stock H2 %s %s: status %d proto %s body %q err=%v", tc.method, tc.path, res.StatusCode, res.Proto, body, err)
		}
		if tc.method == "HEAD" && res.ContentLength != int64(len("STL MASQUE HTTP/2 endpoint\n")) {
			t.Fatal("HEAD content length differs from GET")
		}
	}

	if got := transportDials.Load(); got != 1 {
		t.Fatalf("ordinary GET/HEAD/404 did not reuse a real HTTP/2 connection; TLS dial count=%d", got)
	}

	// Exercise the receiver's actual HTTP/2 request gate, not merely the
	// dialer's client-side field validation. These are real TLS connections
	// without client certificates and genuine encoded extended CONNECT.
	for _, tc := range []struct {
		label, path, protocol string
		headers               []hpack.HeaderField
	}{
		{label: "missing request authorization"},
		{label: "wrong bearer", headers: []hpack.HeaderField{{Name: "authorization", Value: "Bearer wrong"}}},
		{label: "duplicated bearer", headers: []hpack.HeaderField{
			{Name: "authorization", Value: "Bearer " + token},
			{Name: "authorization", Value: "Bearer " + token},
		}},
		{label: "wrong extended CONNECT path", path: "/wrong", headers: []hpack.HeaderField{{Name: "authorization", Value: "Bearer " + token}}},
		{label: "wrong extended CONNECT protocol", protocol: "other", headers: []hpack.HeaderField{{Name: "authorization", Value: "Bearer " + token}}},
	} {
		status := rawPublicH2ConnectStatus(t, addr, roots, tc.path, tc.protocol, tc.headers)
		if status != "403" {
			t.Fatalf("%s was not rejected on real H2 wire: HTTP %s", tc.label, status)
		}
		select {
		case <-pipe.toServer:
			t.Fatal("unauthorized extended CONNECT opened private TUN packet access")
		default:
		}
	}

	base := H2Config{
		Address: addr, ServerName: "masque-test.invalid", Roots: roots,
		ExpectedIPv4:   netip.MustParseAddr("10.251.95.2"),
		ConnectTimeout: 2 * time.Second,
	}
	// Invalid or absent request authorization never opens TUN packet access,
	// and these probes cannot consume the Link's single authorized session.
	for _, tc := range []struct {
		label string
		token string
		path  string
	}{
		{label: "missing bearer"},
		{label: "wrong bearer", token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x91}, 32))},
		{label: "wrong CONNECT path", token: token, path: "/no-tunnel"},
	} {
		cfg := base
		cfg.BearerToken, cfg.Path = tc.token, tc.path
		if _, err := DialH2(ctx, cfg); err == nil {
			t.Fatalf("%s unexpectedly opened private MASQUE tunnel", tc.label)
		}
		select {
		case <-pipe.toServer:
			t.Fatal("rejected H2 session reached private TUN")
		default:
		}
	}
	base.BearerToken = token
	link, err := DialH2(ctx, base)
	if err != nil {
		t.Fatal("authorized public TLS CONNECT-IP failed:", err)
	}
	defer link.Close()
	request := testPacket()
	if err := link.SendPackets(ctx, [][]byte{request}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-pipe.toServer:
		if !bytes.Equal(got, request) {
			t.Fatal("authorized inbound private IP packet mismatch")
		}
	case <-ctx.Done():
		t.Fatal("authorized private IP packet was not forwarded")
	}
	reply := bytes.Clone(request)
	copy(reply[12:16], []byte{10, 251, 95, 1})
	copy(reply[16:20], []byte{10, 251, 95, 2})
	pipe.toClient <- reply
	got, err := link.ReadPacket(ctx)
	if err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("authorized private reply failed: %v", err)
	}

	cancel()
	link.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("public TLS listener shutdown failed:", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("public TLS listener did not stop")
	}
}

func TestMASQUEPublicTLSDeniesMalformedBearerAndClientModeConflict(t *testing.T) {
	serverIdentity, roots := testTLS(t)
	cfg := H2ListenConfig{
		ListenAddress: "127.0.0.1:443", TLSServerName: "masque-test.invalid",
		ServerCert: serverIdentity, PublicTLS: true,
		LocalIPv4: netip.MustParseAddr("10.251.95.1"), PeerIPv4: netip.MustParseAddr("10.251.95.2"),
	}
	for _, token := range []string{"", "short", strings.Repeat("A", 42) + "!"} {
		cfg.BearerToken = []byte(token)
		if ValidBearerToken(cfg.BearerToken) {
			t.Fatal("malformed token was mistakenly treated as a valid fixture")
		}
		if _, err := NewH2Server(cfg, &channelPrivatePipe{}); err == nil {
			t.Fatalf("accepted malformed public request bearer of length %d", len(token))
		}
	}
	config := H2Config{
		Address: "127.0.0.1:443", ServerName: "masque-test.invalid",
		Roots: roots, ExpectedIPv4: netip.MustParseAddr("10.251.95.2"),
		BearerToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
	}
	if err := validateH2Config(config); err != nil {
		t.Fatal(err)
	}
	config.Username = "unsafe-second-auth"
	config.Password = "x"
	if err := validateH2Config(config); err == nil {
		t.Fatal("accepted a mixed public TLS bearer and Basic credential")
	}
}

// A deliberate test-only request generator avoids the normal H2 client
// admission preflight so missing/duplicate authorization reaches the actual
// receiver and proves request-level rejection, not only local validation.
func rawPublicH2ConnectStatus(t *testing.T, addr string, roots *x509.CertPool,
	path, protocol string, extra []hpack.HeaderField) string {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{
		RootCAs: roots, ServerName: "masque-test.invalid", NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	})
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatalf("public TLS handshake without client identity failed: %v", err)
	}
	writer := bufio.NewWriter(conn)
	fr := http2.NewFramer(writer, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if _, err := writer.WriteString(http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	enabled := false
	for !enabled {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatal("public HTTP/2 server SETTINGS unavailable:", err)
		}
		if settings, ok := frame.(*http2.SettingsFrame); ok {
			_ = settings.ForeachSetting(func(setting http2.Setting) error {
				if setting.ID == http2.SettingEnableConnectProtocol && setting.Val == 1 {
					enabled = true
				}
				return nil
			})
		}
	}
	if path == "" {
		path = "/.well-known/masque/ip/"
	}
	if protocol == "" {
		protocol = "connect-ip"
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	_, port, _ := net.SplitHostPort(addr)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: net.JoinHostPort("masque-test.invalid", port)},
		{Name: ":path", Value: path}, {Name: ":protocol", Value: protocol},
		{Name: "capsule-protocol", Value: "?1"},
	}
	fields = append(fields, extra...)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatal("public MASQUE rejection HTTP/2 frame missing:", err)
		}
		if headers, ok := frame.(*http2.MetaHeadersFrame); ok && headers.StreamID == 1 {
			return headers.PseudoValue("status")
		}
	}
}

// Default HTTPS origin-form :authority omits the port, including bracketed
// IPv6 literals. A public website-like GET must accept it without allowing
// a different hostname or nondefault port to impersonate this listener.
func TestMASQUEPublicHTTPAuthorityStandard443Semantics(t *testing.T) {
	for _, tc := range []struct {
		name, bind, authority string
		want                  bool
	}{
		{"masque.example.org", "0.0.0.0:443", "masque.example.org", true},
		{"masque.example.org", "0.0.0.0:443", "MASQUE.EXAMPLE.ORG", true},
		{"masque.example.org", "0.0.0.0:443", "masque.example.org:443", true},
		{"masque.example.org", "0.0.0.0:443", "other.example.org", false},
		{"masque.example.org", "0.0.0.0:443", "masque.example.org:444", false},
		{"masque.example.org", "0.0.0.0:8443", "masque.example.org", false},
		{"masque.example.org", "0.0.0.0:8443", "masque.example.org:8443", true},
		{"2001:db8::1", "[::]:443", "[2001:db8::1]", true},
		{"2001:db8::1", "[::]:443", "[2001:db8::1]:443", true},
		{"2001:db8::1", "[::]:443", "[2001:db8::2]", false},
	} {
		if got := publicHTTPAuthorityMatches(tc.name, tc.bind, tc.authority); got != tc.want {
			t.Errorf("name=%q bind=%q authority=%q: got %v want %v", tc.name, tc.bind, tc.authority, got, tc.want)
		}
	}
}
