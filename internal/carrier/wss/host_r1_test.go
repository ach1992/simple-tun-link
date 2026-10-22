package wss

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// No secret is needed to validate that a same-name transient unit cannot
// smuggle a different TLS verification mode, destination, or log level.
func TestR1ExactWSSUnitInvocationRejectsForeignOptions(t *testing.T) {
	expected := Command{Binary: DefaultExecutable, Args: []string{
		"client", "--log-lvl", "INFO", "--tls-verify-certificate",
		"--tls-certificate", "/var/lib/simple-tun-link/credentials/wss/lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/client-cert.pem",
		"--tls-private-key", "/var/lib/simple-tun-link/credentials/wss/lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/client-key.pem",
		"--http-headers-file", "/var/lib/simple-tun-link/credentials/wss/lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/authorization-headers",
		"-L", "udp://127.0.0.1:53001:127.0.0.1:51821?timeout_sec=0",
		"wss://198.51.100.21:59443",
	}}
	render := func(args []string) string {
		return "{ path=" + expected.Binary + " ; argv[]=" + strings.Join(args, " ") + " ; ignore_errors=no ; }"
	}
	actual := append([]string{expected.Binary}, expected.Args...)
	if !matchesExactWSSExecStart(render(actual), expected) {
		t.Fatal("rejected exact observed systemd service argv")
	}
	variants := map[string][]string{
		"dropped-tls-validation": append([]string(nil), actual[:4]...),
		"extra-untrusted-flag":   append(append([]string(nil), actual...), "--log-lvl", "DEBUG"),
		"changed-destination":    append([]string(nil), actual...),
		"different-executable":   append([]string{"/tmp/foreign-wstunnel"}, actual[1:]...),
	}
	variants["dropped-tls-validation"] = append(append([]string{}, actual[:3]...), actual[4:]...)
	variants["changed-destination"][len(actual)-1] = "wss://203.0.113.1:59443"
	for label, args := range variants {
		if matchesExactWSSExecStart(render(args), expected) {
			t.Errorf("accepted foreign %s unit", label)
		}
	}
	if matchesExactWSSExecStart(render(actual)+" argv[]=extra", expected) {
		t.Fatal("accepted ambiguous repeated argv[]")
	}
}

func TestR1RetirementRequiresPrivateDirectoryAndNeverDeletesForeign(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	link := wssTestLink()
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443, TLSServerName: "198.51.100.21"}
	id := link.ID
	listen, dial, err := GeneratePair(id, "198.51.100.21")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	if err := Stage(root, link, listen); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "credentials", "wss", string(id))
	outsider := filepath.Join(private, "foreign-credential")
	if err := os.WriteFile(outsider, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RetireOwnedTLS(root, link); err == nil {
		t.Fatal("deleted directory with unowned file")
	}
	if raw, err := os.ReadFile(outsider); err != nil || string(raw) != "preserve" {
		t.Fatalf("lost foreign file: %v", err)
	}
	if err := os.Remove(outsider); err != nil {
		t.Fatal(err)
	}
	if err := RetireOwnedTLS(root, link); err != nil {
		t.Fatal(err)
	}
	if absent, err := TLSAbsent(root, link); err != nil || !absent {
		t.Fatalf("TLS still present: %v", err)
	}
	// An already retired Link ID must reject new private material.
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if absent, err := TLSAbsent(root, link); err != nil || absent {
		t.Fatalf("reappeared material treated absent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(private, "authorization-token"), []byte("do-not-delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if absent, err := TLSAbsent(root, link); err != nil || absent {
		t.Fatal("reappeared credential treated absent")
	}
}
