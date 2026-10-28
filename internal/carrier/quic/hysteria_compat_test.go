package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// pinnedHelper represents one exact started Hysteria process with a
// separately retained exit result. A UDP read timeout is never sufficient
// evidence of authorization rejection: negative tests must observe an
// upstream-specific failure after the helper actually attempted admission.
type pinnedHelper struct {
	name    string
	logPath string
	done    chan struct{}
	waitErr error // published by closing done; do not read until done closes
}

func (h *pinnedHelper) exited() (bool, error) {
	select {
	case <-h.done:
		return true, h.waitErr
	default:
		return false, nil
	}
}

func (h *pinnedHelper) logBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(h.logPath)
	if err != nil {
		t.Fatalf("%s helper log unavailable: %v", h.name, err)
	}
	return b // Private test fixture only: never print raw log bytes.
}

func (h *pinnedHelper) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		log := h.logBytes(t)
		ready := bytes.Contains(log, []byte("UDP forwarding listening"))
		clear(log)
		exited, err := h.exited()
		if exited {
			t.Fatalf("%s helper exited instead of completing QUIC authentication and local UDP bind: %v", h.name, err)
		}
		if ready {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s helper did not produce the post-authentication UDP listener readiness marker", h.name)
}

// Hysteria v2.13.0 emits this server INFO event only after successful
// TLS/mTLS and bearer authentication. Check the server separately rather
// than assuming that a client-local UDP port proves remote admission.
func (h *pinnedHelper) waitClientAdmissions(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		log := h.logBytes(t)
		count := bytes.Count(log, []byte("client connected"))
		clear(log)
		if count >= want {
			if exited, err := h.exited(); exited {
				t.Fatalf("QUIC server exited after recording %d authenticated sessions: %v", count, err)
			}
			return
		}
		if exited, err := h.exited(); exited {
			t.Fatalf("QUIC server exited while awaiting authenticated session: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("QUIC server did not record %d authenticated sessions", want)
}

// Actual upstream v2.13.0 client initialization is eager; a failed TLS
// handshake or bearer rejection terminates initialization before opening the
// local forwarder. Require its *specific* fatal reason, not an absent socket.
func (h *pinnedHelper) waitRejected(t *testing.T, reason string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		exited, err := h.exited()
		if exited {
			log := h.logBytes(t)
			defer clear(log)
			if err == nil {
				t.Fatalf("%s helper exited successfully despite expected rejection", h.name)
			}
			if !pinnedRejectionEvidence(log, reason) {
				// Print only Boolean evidence, never private credentials or
				// untrusted error text from the helper log.
				t.Fatalf("%s helper exit is not proven %s rejection (init-failed=%t, auth-http-404=%t, tls-certificate=%t)",
					h.name, reason, bytes.Contains(log, []byte("failed to initialize client")),
					bytes.Contains(log, []byte("authentication error, HTTP status code: 404")),
					bytes.Contains(log, []byte("certificate")))
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s helper did not complete the expected %s rejection within the bounded window", h.name, reason)
}

func pinnedRejectionEvidence(log []byte, reason string) bool {
	if !bytes.Contains(log, []byte("failed to initialize client")) {
		return false
	}
	switch reason {
	case "bearer":
		return bytes.Contains(log, []byte("authentication error, HTTP status code: 404"))
	case "client-ca":
		return bytes.Contains(log, []byte("CRYPTO_ERROR")) &&
			bytes.Contains(log, []byte("remote")) &&
			bytes.Contains(log, []byte("unknown certificate authority"))
	default:
		return false
	}
}

// A missing/unstarted helper, a configuration failure and unrelated network
// timeouts must NEVER satisfy the security-negative proof requirements.
func TestPinnedHysteriaRejectionEvidenceFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		reason string
		log    string
		ok     bool
	}{
		{"bearer", "", false},
		{"bearer", "failed to initialize client: timeout", false},
		{"bearer", "authentication error, HTTP status code: 404", false},
		{"bearer", "failed to initialize client: authentication error, HTTP status code: 404", true},
		{"client-ca", "", false},
		{"client-ca", "failed to initialize client: timeout", false},
		{"client-ca", "failed to initialize client: certificate rejected", false},
		{"client-ca", "failed to initialize client: CRYPTO_ERROR (remote): tls: unknown certificate authority", true},
		{"other", "failed to initialize client: certificate rejected", false},
	} {
		if got := pinnedRejectionEvidence([]byte(tc.log), tc.reason); got != tc.ok {
			t.Fatalf("incorrect %s log rejection classification: got=%v want=%v", tc.reason, got, tc.ok)
		}
	}
}

// TestPinnedHysteriaRealQUICLoopback is deliberately opt-in: CI without a
// pinned official helper skips it, rather than fetching/trusting the network.
// It runs the exact restricted JSON rendered by Build through the actual
// upstream v2.13.0 parser, TLS1.3/mTLS, client authorization and 1200-byte
// UDP forwarding. All sockets stay on loopback and never touch STL State,
// WireGuard, nftables, systemd, kernel routes or physical peer servers.
func TestPinnedHysteriaRealQUICLoopback(t *testing.T) {
	bin := os.Getenv("STL_QUIC_HYSTERIA_BIN")
	if bin == "" {
		t.Skip("set STL_QUIC_HYSTERIA_BIN to the separately SHA-256 verified official app/v2.13.0 binary")
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal("pinned helper unavailable:", err)
	}
	const linuxAMD64SHA256 = "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
	const linuxARM64SHA256 = "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7"
	sum := sha256.Sum256(raw)
	archDigest := hex.EncodeToString(sum[:])
	if archDigest != linuxAMD64SHA256 && archDigest != linuxARM64SHA256 {
		t.Fatalf("not an approved pinned official v2.13.0 helper: SHA256=%s", archDigest)
	}
	clear(raw)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL is required only for isolated, ephemeral E2E TLS test credentials")
	}
	root := t.TempDir()
	link := domainTestLinkID()
	private := filepath.Join(root, "credentials", "quic", string(link))
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	// Generate credentials purely for this disposable loopback scenario.
	openssl := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "openssl", args...)
		c.Dir = private
		// Never put any key or secret bytes in Go test output.
		c.Stdout, c.Stderr = io.Discard, io.Discard
		if err := c.Run(); err != nil {
			t.Fatalf("OpenSSL test fixture step failed (%s): %v", args[0], err)
		}
	}
	openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", filepath.Join(private, "ca.key"),
		"-out", filepath.Join(private, "ca.crt"),
		"-days", "1", "-subj", "/CN=STL QUIC Test Only CA",
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign")
	for _, item := range []struct {
		prefix, subject, eku, extra string
	}{
		{"server", "/CN=quic-probe.invalid", "serverAuth", "subjectAltName=DNS:quic-probe.invalid\n"},
		{"client", "/CN=stl-local-client", "clientAuth", ""},
	} {
		key := filepath.Join(private, item.prefix+".key")
		csr := filepath.Join(private, item.prefix+".csr")
		crt := filepath.Join(private, item.prefix+".crt")
		openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
			"-out", csr, "-subj", item.subject)
		ext := filepath.Join(private, item.prefix+".ext")
		if err := os.WriteFile(ext, []byte("extendedKeyUsage="+item.eku+
			"\nkeyUsage=digitalSignature,keyEncipherment\n"+item.extra), 0o600); err != nil {
			t.Fatal(err)
		}
		openssl("x509", "-req", "-in", csr,
			"-CA", filepath.Join(private, "ca.crt"),
			"-CAkey", filepath.Join(private, "ca.key"), "-CAcreateserial",
			"-out", crt, "-days", "1", "-extfile", ext)
	}
	for name, value := range map[string]string{
		"server-ca.pem": "ca.crt", "client-ca.pem": "ca.crt",
		"server-cert.pem": "server.crt", "server-key.pem": "server.key",
		"client-cert.pem": "client.crt", "client-key.pem": "client.key",
	} {
		b, err := os.ReadFile(filepath.Join(private, value))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(private, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
		clear(b)
	}
	reserve := func() uint16 {
		t.Helper()
		s, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(s.LocalAddr().(*net.UDPAddr).Port)
		s.Close()
		return port
	}
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			if err := echo.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return
			}
			n, peer, err := echo.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			_, _ = echo.WriteTo(buf[:n], peer)
		}
	}()
	defer func() { echo.Close(); wg.Wait() }()
	// Separate per-Link credential: intentionally NOT copied into Plan.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(tokenBytes)
	clear(tokenBytes)
	serverPort := reserve()
	clientPort := reserve()
	echoPort := uint16(echo.LocalAddr().(*net.UDPAddr).Port)
	base := Plan{
		LinkID: link, Underlay: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), serverPort),
		TLSName: "quic-probe.invalid",
	}
	srv := base
	srv.Role = Listen
	srv.LocalWGUDPPort = echoPort
	dial := base
	dial.Role = Dial
	dial.LocalForwardUDPPort = clientPort
	dial.PeerWGUDPPort = echoPort
	serverCmd, err := Build(srv, bin, root, token)
	if err != nil {
		t.Fatal(err)
	}
	clientCmd, err := Build(dial, bin, root, token)
	if err != nil {
		t.Fatal(err)
	}
	saveConfig := func(cmd Command, name string) string {
		t.Helper()
		b := cmd.ProtectedConfigBytes()
		defer clear(b)
		target := filepath.Join(root, name+".json")
		if err := os.WriteFile(target, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return target
	}
	// The two roles share a credential directory in this disposable single
	// process fixture only. Real hosts use disjoint protected State roots.
	serverPath := saveConfig(serverCmd, "server")
	clientPath := saveConfig(clientCmd, "client")
	run := func(command Command, conf, name string) *pinnedHelper {
		t.Helper()
		args := append([]string(nil), command.Args...)
		for i := range args {
			if args[i] == command.ConfigPath {
				args[i] = conf
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		c := exec.CommandContext(ctx, bin, args...)
		path := filepath.Join(root, name+".log")
		out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		c.Stdout, c.Stderr = out, out
		if err := c.Start(); err != nil {
			_ = out.Close()
			cancel()
			t.Fatalf("%s helper could not launch: %v", name, err)
		}
		p := &pinnedHelper{name: name, logPath: path, done: make(chan struct{})}
		go func() {
			p.waitErr = c.Wait()
			close(p.done)
		}()
		t.Cleanup(func() {
			cancel()
			<-p.done
			_ = out.Close()
		})
		return p
	}
	serverProcess := run(serverCmd, serverPath, "server")
	clientProcess := run(clientCmd, clientPath, "client")
	clientProcess.waitReady(t)
	if exited, _ := serverProcess.exited(); exited {
		t.Fatal("positive control server exited before authentication completed")
	}
	serverProcess.waitClientAdmissions(t, 1)
	conn, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(clientPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var success int
	for i := 0; i < 100; i++ {
		payload := make([]byte, 1200)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		// Each echo receipt demonstrates actual traffic over the generated
		// local forwarding topology (not merely a process starting).
		for retry := 0; retry < 4; retry++ {
			if err := conn.SetDeadline(time.Now().Add(1100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			out := make([]byte, 1500)
			n, err := conn.Read(out)
			if err == nil && bytes.Equal(out[:n], payload) {
				success++
				break
			}
			if retry == 3 {
				for _, name := range []string{"server", "client", "bad-auth", "bad-destination"} {
					raw, logErr := os.ReadFile(filepath.Join(root, name+".log"))
					if logErr == nil {
						if bytes.Contains(raw, []byte(token)) {
							t.Fatal("secret appeared in Hysteria INFO log")
						}
						text := string(raw)
						if len(text) > 1300 {
							text = text[len(text)-1300:]
						}
						t.Logf("%s Hysteria helper diagnostic: %s", name, text)
					}
				}
				t.Fatalf("pinned QUIC helper could not relay byte-identical UDP payload %d; successful=%d", i, success)
			}
		}
		clear(payload)
	}
	if success != 100 {
		t.Fatal("QUIC UDP transfer incomplete")
	}
	// Negative tests exercise actual JSON generated by Build, not a
	// hand-written alternate Hysteria ACL or client configuration.
	noAck := func(p *pinnedHelper, localPort uint16, label string) {
		t.Helper()
		p.waitReady(t)
		c, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(localPort)))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := c.SetDeadline(time.Now().Add(1100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte("not-allowed-to-forward")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 100)
		if n, err := c.Read(buf); err == nil {
			t.Fatalf("%s unexpectedly forwarded %d bytes of forbidden private payload", label, n)
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%s failed for a transport/process error rather than a verified destination denial: %v", label, err)
		}
		if exited, err := p.exited(); exited {
			t.Fatalf("%s client exited during ACL check: %v", label, err)
		}
	}
	badToken := token[:len(token)-1] + "0"
	if badToken == token {
		badToken = token[:len(token)-1] + "1"
	}
	rejectedAuth := dial
	rejectedAuth.LocalForwardUDPPort = reserve()
	badAuthCmd, err := Build(rejectedAuth, bin, root, badToken)
	if err != nil {
		t.Fatal(err)
	}
	badAuthPath := saveConfig(badAuthCmd, "bad-auth")
	badAuthProcess := run(badAuthCmd, badAuthPath, "bad-auth")
	badAuthProcess.waitRejected(t, "bearer")
	// Rejected bearer must not be counted as a remotely authenticated peer.
	observedServerLog := serverProcess.logBytes(t)
	if n := bytes.Count(observedServerLog, []byte("client connected")); n != 1 {
		t.Fatal("invalid bearer unexpectedly authenticated a QUIC client")
	}
	clear(observedServerLog)
	forbidden, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer forbidden.Close()
	restricted := dial
	restricted.LocalForwardUDPPort = reserve()
	restricted.PeerWGUDPPort = uint16(forbidden.LocalAddr().(*net.UDPAddr).Port)
	forbiddenCmd, err := Build(restricted, bin, root, token)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenPath := saveConfig(forbiddenCmd, "bad-destination")
	forbiddenProcess := run(forbiddenCmd, forbiddenPath, "bad-destination")
	serverProcess.waitClientAdmissions(t, 2)
	noAck(forbiddenProcess, restricted.LocalForwardUDPPort, "unlisted-destination")
	if err := forbidden.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 256)
	if _, _, err := forbidden.ReadFrom(data); err == nil {
		t.Fatal("unlisted UDP endpoint received unauthorized data")
	}
	// A valid destination through the same authenticated server must still
	// work after the forbidden destination attempt; deny-all is scoped.
	if err := conn.SetDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	canary := []byte("allowed-after-acl-rejection")
	if _, err := conn.Write(canary); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(canary)+8)
	if n, err := conn.Read(reply); err != nil || !bytes.Equal(reply[:n], canary) {
		t.Fatal("allowed destination control failed after ACL rejection")
	}
	// Explicitly keep sensitive helper configs out of logging and reporting.
	for _, name := range []string{"server", "client", "bad-auth", "bad-destination"} {
		b, err := os.ReadFile(filepath.Join(root, name+".log"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(token)) || bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Fatal("Hysteria INFO log exposed live per-Link credentials")
		}
	}
	t.Logf("pinned Hysteria v2.13.0 generated JSON E2E: TLS/mTLS + bearer UDP 100/100; invalid token and foreign UDP target denied")
}

func domainTestLinkID() domain.LinkID {
	return "lnk_0123456789abcdef0123456789abcdef"
}
