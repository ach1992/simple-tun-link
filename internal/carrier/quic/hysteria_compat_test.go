package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

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
	root := t.TempDir()
	link := domainTestLinkID()
	private := filepath.Join(root, "credentials", "quic", string(link))
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	// The real Go issuer supplies the exact Hysteria config's TLS/mTLS and
	// independent per-Link bearer; no OpenSSL fixture or stored CA keys.
	serverBundle, clientBundle, err := GeneratePair(link, "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer serverBundle.Clear()
	defer clientBundle.Clear()
	secrets := clientBundle.ProtectedFiles()
	token := strings.TrimSuffix(string(secrets["authorization-token"]), "\n")
	clearProtectedCopies(secrets)
	if !validToken(token) {
		t.Fatal("issued QUIC authorization token malformed")
	}
	stage := func(bundle CredentialBundle) {
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
	stage(serverBundle)
	stage(clientBundle)
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
	run := func(command Command, conf, name string) {
		t.Helper()
		args := append([]string(nil), command.Args...)
		for i := range args {
			if args[i] == command.ConfigPath {
				args[i] = conf
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		c := exec.CommandContext(ctx, bin, args...)
		out, err := os.OpenFile(filepath.Join(root, name+".log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		c.Stdout, c.Stderr = out, out
		if err := c.Start(); err != nil {
			out.Close()
			cancel()
			t.Fatalf("%s helper failed to start: %v", name, err)
		}
		t.Cleanup(func() {
			cancel()
			_ = c.Wait()
			_ = out.Close()
		})
	}
	run(serverCmd, serverPath, "server")
	time.Sleep(350 * time.Millisecond)
	run(clientCmd, clientPath, "client")
	// Hysteria binds the selected loopback UDP listener asynchronously.
	// Give the verified helper a bounded startup window before probing it.
	time.Sleep(1400 * time.Millisecond)
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
	noAck := func(localPort uint16, label string) {
		t.Helper()
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
		if _, err := c.Read(buf); err == nil {
			t.Fatalf("%s unexpectedly forwarded forbidden private payload", label)
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
	run(badAuthCmd, badAuthPath, "bad-auth")
	time.Sleep(400 * time.Millisecond)
	noAck(rejectedAuth.LocalForwardUDPPort, "invalid-token")
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
	foreignCmd, err := Build(foreignPlan, bin, root, token)
	if err != nil {
		t.Fatal(err)
	}
	foreignConfig := saveConfig(foreignCmd, "bad-mtls")
	run(foreignCmd, foreignConfig, "bad-mtls")
	time.Sleep(400 * time.Millisecond)
	noAck(foreignPlan.LocalForwardUDPPort, "untrusted-client-certificate")
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
	run(forbiddenCmd, forbiddenPath, "bad-destination")
	time.Sleep(400 * time.Millisecond)
	noAck(restricted.LocalForwardUDPPort, "unlisted-destination")
	if err := forbidden.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 256)
	if _, _, err := forbidden.ReadFrom(data); err == nil {
		t.Fatal("unlisted UDP endpoint received unauthorized data")
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
	t.Logf("pinned Hysteria v2.13.0 generated JSON E2E: issued TLS/mTLS + bearer UDP 100/100; invalid token, foreign client CA and UDP destination denied")
}

func domainTestLinkID() domain.LinkID {
	return "lnk_0123456789abcdef0123456789abcdef"
}
