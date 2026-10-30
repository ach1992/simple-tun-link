package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
	cancel  context.CancelFunc
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

// Hysteria v2.13.0 emits tab-separated server INFO/WARN events with
// structured JSON fields. Do not mistake generic log text for ACL proof.
type pinnedServerEvent struct {
	Addr      string `json:"addr"`
	ID        string `json:"id"`
	SessionID uint32 `json:"sessionID"`
	Error     string `json:"error"`
}

func pinnedServerLogEvents(log []byte, name string) ([]pinnedServerEvent, error) {
	var result []pinnedServerEvent
	tag := []byte("\t" + name)
	for _, line := range bytes.Split(log, []byte("\n")) {
		lastTab := bytes.LastIndexByte(line, '\t')
		if lastTab < 0 || !bytes.HasSuffix(line[:lastTab], tag) {
			continue
		}
		var item pinnedServerEvent
		if err := json.Unmarshal(line[lastTab+1:], &item); err != nil ||
			item.Addr == "" || item.ID == "" {
			return nil, fmt.Errorf("malformed Hysteria %s event", name)
		}
		result = append(result, item)
	}
	return result, nil
}

// Prove rejection using upstream's exact "rejected" error for the
// authenticated forbidden QUIC client, not absent UDP response alone.
func pinnedACLRejected(log []byte, client pinnedServerEvent) (bool, error) {
	events, err := pinnedServerLogEvents(log, "UDP error")
	if err != nil {
		return false, err
	}
	for _, event := range events {
		if event.Addr == client.Addr && event.ID == client.ID && event.Error == "rejected" {
			return true, nil
		}
	}
	return false, nil
}

func (h *pinnedHelper) waitACLRejected(t *testing.T, client pinnedServerEvent) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		log := h.logBytes(t)
		rejected, err := pinnedACLRejected(log, client)
		clear(log)
		if err != nil {
			t.Fatalf("pinned Hysteria ACL log cannot be parsed: %v", err)
		}
		if rejected {
			if exited, e := h.exited(); exited {
				t.Fatalf("server exited after supposed ACL rejection: %v", e)
			}
			return
		}
		if exited, e := h.exited(); exited {
			t.Fatalf("server exited before ACL rejection: %v", e)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("server did not record a correlated ACL rejection; UDP timeout is not proof")
}

// Missing helpers, unrelated forwarding errors and other client sessions
// must not satisfy the ACL policy rejection assertion.
func TestPinnedHysteriaServerACLRejectionEvidenceFailsClosed(t *testing.T) {
	client := pinnedServerEvent{Addr: "127.0.0.1:52001", ID: "user"}
	const warn = "2026-10-28\tWARN\t"
	for _, tc := range []struct {
		name string
		log  string
		want bool
	}{
		{"absent-helper", "", false},
		{"admission-only", "2026-10-28\tINFO\tclient connected\t{\"addr\":\"127.0.0.1:52001\",\"id\":\"user\"}\n", false},
		{"unrelated-timeout", warn + "UDP error\t{\"addr\":\"127.0.0.1:52001\",\"id\":\"user\",\"sessionID\":9,\"error\":\"i/o timeout\"}\n", false},
		{"wrong-client", warn + "UDP error\t{\"addr\":\"127.0.0.1:52002\",\"id\":\"user\",\"sessionID\":9,\"error\":\"rejected\"}\n", false},
		{"wrong-id", warn + "UDP error\t{\"addr\":\"127.0.0.1:52001\",\"id\":\"other\",\"sessionID\":9,\"error\":\"rejected\"}\n", false},
		{"non-event-text", "UDP error rejected with no structured event", false},
		{"exact-reject", warn + "UDP error\t{\"addr\":\"127.0.0.1:52001\",\"id\":\"user\",\"sessionID\":9,\"error\":\"rejected\"}\n", true},
	} {
		got, err := pinnedACLRejected([]byte(tc.log), client)
		if err != nil || got != tc.want {
			t.Fatalf("%s got=%t want=%t err=%v", tc.name, got, tc.want, err)
		}
	}
	if _, err := pinnedACLRejected([]byte(warn+"UDP error\t{invalid-json}\n"), client); err == nil {
		t.Fatal("malformed ACL event must fail closed")
	}
}

// Hysteria v2.13.0 emits this server INFO event only after successful
// TLS/mTLS and bearer authentication. Check the server separately rather
// than assuming that a client-local UDP port proves remote admission.
func (h *pinnedHelper) waitClientAdmissions(t *testing.T, want int) []pinnedServerEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		log := h.logBytes(t)
		events, parseErr := pinnedServerLogEvents(log, "client connected")
		clear(log)
		if parseErr != nil {
			t.Fatalf("QUIC server admission event is unparseable: %v", parseErr)
		}
		if len(events) >= want {
			if exited, err := h.exited(); exited {
				t.Fatalf("QUIC server exited after recording %d authenticated sessions: %v", len(events), err)
			}
			return events
		}
		if exited, err := h.exited(); exited {
			t.Fatalf("QUIC server exited while awaiting authenticated session: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("QUIC server did not record %d authenticated sessions", want)
	return nil
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
	for _, mode := range []string{domain.QUICObfuscationPlain, domain.QUICObfuscationSalamander} {
		name := mode
		if name == "" {
			name = "plain"
		}
		t.Run(name, func(t *testing.T) {
			for _, tlsName := range []string{"quic-probe.invalid", "127.0.0.1"} {
				t.Run(tlsName, func(t *testing.T) {
					runPinnedHysteriaLoopbackScenario(t, tlsName, mode)
				})
			}
		})
	}
}

func runPinnedHysteriaLoopbackScenario(t *testing.T, tlsName, mode string) {
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
	root := t.TempDir()
	link := domainTestLinkID()
	private := filepath.Join(root, "credentials", "quic", string(link))
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	// The real Go issuer supplies the exact Hysteria config's TLS/mTLS and
	// independent per-Link bearer; no OpenSSL fixture or stored CA keys.
	serverBundle, clientBundle, err := GeneratePairWithObfuscation(link, tlsName, mode)
	if err != nil {
		t.Fatal(err)
	}
	defer serverBundle.Clear()
	defer clientBundle.Clear()
	secrets := clientBundle.ProtectedFiles()
	token := strings.TrimSuffix(string(secrets["authorization-token"]), "\n")
	obfuscationSecret := strings.TrimSuffix(string(secrets[obfuscationSecretFile]), "\n")
	clearProtectedCopies(secrets)
	if !validToken(token) {
		t.Fatal("issued QUIC authorization token malformed")
	}
	stage := func(bundle *CredentialBundle) {
		t.Helper()
		files := bundle.ProtectedFiles()
		defer clearProtectedCopies(files)
		for name, raw := range files {
			path := filepath.Join(private, name)
			if existing, err := os.ReadFile(path); err == nil {
				same := bytes.Equal(existing, raw)
				clear(existing)
				if !same {
					t.Fatalf("role credential collision %s", name)
				}
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Only this disposable same-process local test combines two otherwise
	// separate host role directories. Both copies of the token must agree.
	stage(&serverBundle)
	stage(&clientBundle)
	serverBundle.Clear()
	clientBundle.Clear()
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
	// Issued token remains separate from the public Plan.
	serverPort := reserve()
	clientPort := reserve()
	echoPort := uint16(echo.LocalAddr().(*net.UDPAddr).Port)
	base := Plan{
		LinkID: link, Underlay: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), serverPort),
		TLSName: tlsName, Obfuscation: mode,
	}
	srv := base
	srv.Role = Listen
	srv.LocalWGUDPPort = echoPort
	dial := base
	dial.Role = Dial
	dial.LocalForwardUDPPort = clientPort
	dial.PeerWGUDPPort = echoPort
	serverCmd, err := BuildWithObfuscation(srv, bin, root, token, obfuscationSecret)
	if err != nil {
		t.Fatal(err)
	}
	clientCmd, err := BuildWithObfuscation(dial, bin, root, token, obfuscationSecret)
	if err != nil {
		t.Fatal(err)
	}
	saveConfig := func(cmd *Command, name string) string {
		defer cmd.Clear()
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
	serverPath := saveConfig(&serverCmd, "server")
	clientPath := saveConfig(&clientCmd, "client")
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
		p := &pinnedHelper{name: name, logPath: path, done: make(chan struct{}), cancel: cancel}
		go func() {
			p.waitErr = c.Wait()
			close(p.done)
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-p.done:
			case <-time.After(2 * time.Second):
				t.Errorf("%s helper did not stop within the cleanup deadline", name)
			}
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
				for _, name := range []string{"server", "client", "bad-auth", "bad-mtls", "bad-destination"} {
					raw, logErr := os.ReadFile(filepath.Join(root, name+".log"))
					if logErr == nil {
						// Never print arbitrary upstream logs on a failure path.
						t.Logf("%s helper evidence: ready=%t auth-http-404=%t udp-error=%t",
							name, bytes.Contains(raw, []byte("UDP forwarding listening")),
							bytes.Contains(raw, []byte("authentication error, HTTP status code: 404")),
							bytes.Contains(raw, []byte("UDP error")))
						clear(raw)
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
	var mismatchLogs []string
	if mode == domain.QUICObfuscationSalamander && tlsName == "quic-probe.invalid" {
		// These are bounded nonadmission observations, not positive
		// cryptographic rejection evidence. The same already authenticated
		// session must relay before and after each mismatch; an unavailable
		// server cannot satisfy this fixture merely by producing a timeout.
		healthyControl := func(label string) {
			t.Helper()
			payload := []byte("healthy-control-" + label)
			if err := conn.SetDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 1500)
			if n, err := conn.Read(reply); err != nil || !bytes.Equal(reply[:n], payload) {
				t.Fatal("authenticated healthy control failed around obfuscation mismatch")
			}
		}
		wrongSecret := strings.Repeat("0", 64)
		for _, digit := range []string{"0", "1", "2"} {
			candidate := strings.Repeat(digit, 64)
			if candidate != obfuscationSecret && candidate != token {
				wrongSecret = candidate
				break
			}
		}
		for _, mismatch := range []struct{ name, mode, secret string }{
			{"wrong-obfs-secret", domain.QUICObfuscationSalamander, wrongSecret},
			{"plain-to-salamander", domain.QUICObfuscationPlain, ""},
		} {
			healthyControl(mismatch.name + "-before")
			negative := dial
			negative.LocalForwardUDPPort = reserve()
			negative.Obfuscation = mismatch.mode
			command, err := BuildWithObfuscation(negative, bin, root, token, mismatch.secret)
			if err != nil {
				t.Fatal(err)
			}
			config := saveConfig(&command, mismatch.name)
			process := run(command, config, mismatch.name)
			mismatchLogs = append(mismatchLogs, mismatch.name)
			probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(negative.LocalForwardUDPPort)}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if exited, err := process.exited(); exited {
					t.Fatalf("%s helper exited before the bounded observation completed: %v", mismatch.name, err)
				}
				if _, err := probe.WriteTo([]byte("obfuscation-mismatch-must-not-forward"), target); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatal(err)
				}
				if err := probe.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 128)
				if _, _, err := probe.ReadFrom(buf); err == nil {
					t.Fatalf("%s unexpectedly relayed application data", mismatch.name)
				} else if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatal(err)
				}
				// An unbound eager forwarder may return UDP refusal. Neither
				// that refusal nor a read timeout is the admission assertion.
				log := process.logBytes(t)
				ready := bytes.Contains(log, []byte("UDP forwarding listening"))
				clear(log)
				if ready {
					t.Fatalf("%s unexpectedly completed authentication", mismatch.name)
				}
				time.Sleep(25 * time.Millisecond)
			}
			probe.Close()
			log := process.logBytes(t)
			started := bytes.Contains(log, []byte("client mode"))
			clear(log)
			if !started {
				t.Fatal("mismatch helper produced no upstream client startup evidence")
			}
			if exited, err := process.exited(); exited {
				t.Fatalf("%s helper exited before controlled termination: %v", mismatch.name, err)
			}
			process.cancel()
			select {
			case <-process.done:
			case <-time.After(2 * time.Second):
				t.Fatal("bounded mismatch helper did not stop")
			}
			healthyControl(mismatch.name + "-after")
			log = serverProcess.logBytes(t)
			admitted, err := pinnedServerLogEvents(log, "client connected")
			clear(log)
			if err != nil || len(admitted) != 1 {
				t.Fatal("obfuscation mismatch changed the server's authenticated session set")
			}
			t.Logf("%s: 2s observation, client startup observed, no new server admission or application echo, healthy control before/after passed", mismatch.name)
		}
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
	badAuthCmd, err := BuildWithObfuscation(rejectedAuth, bin, root, badToken, obfuscationSecret)
	if err != nil {
		t.Fatal(err)
	}
	badAuthPath := saveConfig(&badAuthCmd, "bad-auth")
	badAuthProcess := run(badAuthCmd, badAuthPath, "bad-auth")
	badAuthProcess.waitRejected(t, "bearer")
	// The server must not mistake a bad bearer for an authorized client.
	observedServerLog := serverProcess.logBytes(t)
	if n := bytes.Count(observedServerLog, []byte("client connected")); n != 1 {
		t.Fatal("invalid bearer unexpectedly authenticated a QUIC client")
	}
	clear(observedServerLog)
	// A correct bearer is insufficient without the exact per-Link client CA.
	// Use a different isolated per-Link issuer while trusting the genuine
	// server CA; this checks actual upstream client-certificate rejection.
	foreignLink := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	foreignServer, foreignClient, err := GeneratePair(foreignLink, base.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignServer.Clear()
	defer foreignClient.Clear()
	foreignRoot := filepath.Join(root, "credentials", "quic", string(foreignLink))
	if err := os.MkdirAll(foreignRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignFiles := foreignClient.ProtectedFiles()
	serverCA, err := os.ReadFile(filepath.Join(private, "server-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	clear(foreignFiles["server-ca.pem"])
	foreignFiles["server-ca.pem"] = serverCA
	for name, raw := range foreignFiles {
		if err := os.WriteFile(filepath.Join(foreignRoot, name), raw, 0o600); err != nil {
			clearProtectedCopies(foreignFiles)
			t.Fatal(err)
		}
	}
	clearProtectedCopies(foreignFiles)
	foreignPlan := dial
	foreignPlan.LinkID = foreignLink
	foreignPlan.LocalForwardUDPPort = reserve()
	foreignCmd, err := BuildWithObfuscation(foreignPlan, bin, root, token, obfuscationSecret)
	if err != nil {
		t.Fatal(err)
	}
	foreignConfig := saveConfig(&foreignCmd, "bad-mtls")
	foreignProcess := run(foreignCmd, foreignConfig, "bad-mtls")
	foreignProcess.waitRejected(t, "client-ca")
	observedServerLog = serverProcess.logBytes(t)
	if n := bytes.Count(observedServerLog, []byte("client connected")); n != 1 {
		t.Fatal("foreign client CA unexpectedly authenticated a QUIC client")
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
	forbiddenCmd, err := BuildWithObfuscation(restricted, bin, root, token, obfuscationSecret)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenPath := saveConfig(&forbiddenCmd, "bad-destination")
	forbiddenProcess := run(forbiddenCmd, forbiddenPath, "bad-destination")
	admitted := serverProcess.waitClientAdmissions(t, 2)
	if len(admitted) != 2 || admitted[0].Addr == admitted[1].Addr {
		t.Fatal("forbidden client needs a distinct authenticated QUIC session")
	}
	beforeLog := serverProcess.logBytes(t)
	alreadyRejected, err := pinnedACLRejected(beforeLog, admitted[1])
	clear(beforeLog)
	if err != nil || alreadyRejected {
		t.Fatal("forbidden client's ACL rejection appeared before its test packet")
	}
	noAck(forbiddenProcess, restricted.LocalForwardUDPPort, "unlisted-destination")
	serverProcess.waitACLRejected(t, admitted[1])
	if err := forbidden.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 256)
	if _, _, err := forbidden.ReadFrom(data); err == nil {
		t.Fatal("unlisted UDP endpoint received unauthorized data")
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("forbidden UDP endpoint returned unexpected error: %v", err)
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
	for _, name := range append([]string{"server", "client", "bad-auth", "bad-mtls", "bad-destination"}, mismatchLogs...) {
		b, err := os.ReadFile(filepath.Join(root, name+".log"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(token)) || bytes.Contains(b, []byte("PRIVATE KEY")) ||
			(obfuscationSecret != "" && bytes.Contains(b, []byte(obfuscationSecret))) {
			t.Fatal("Hysteria INFO log exposed live per-Link credentials")
		}
		clear(b)
	}
	t.Logf("pinned Hysteria v2.13.0 generated JSON E2E: issued TLS/mTLS + bearer UDP 100/100; invalid token, foreign client CA and UDP destination denied")
}

func domainTestLinkID() domain.LinkID {
	return "lnk_0123456789abcdef0123456789abcdef"
}
