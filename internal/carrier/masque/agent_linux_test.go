//go:build linux

package masque

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func testDialAgentConfig() DialAgentConfig {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	name, _ := AgentInterfaceName(id)
	return DialAgentConfig{
		SchemaVersion: 1, LinkID: id, Interface: name,
		PrivateIPv4: "10.251.95.2", PeerIPv4: "10.251.95.1",
		MTU: 1280, Address: "[::1]:443", ServerName: "masque-test.invalid",
		CACertFile: "/tmp/test-ca", ClientCertFile: "/tmp/test-leaf",
		ClientKeyFile: "/tmp/test-key",
	}
}

func TestDialAgentConfigValidation(t *testing.T) {
	valid := testDialAgentConfig()
	if _, _, err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*DialAgentConfig){
		func(c *DialAgentConfig) { c.SchemaVersion = 0 },
		func(c *DialAgentConfig) { c.Interface = "tun0" },
		func(c *DialAgentConfig) { c.PeerIPv4 = "10.251.95.2" },
		func(c *DialAgentConfig) { c.PrivateIPv4 = "fe80::1" },
		func(c *DialAgentConfig) { c.MTU = 1 },
		func(c *DialAgentConfig) { c.ServerName = "" },
		func(c *DialAgentConfig) { c.ClientKeyFile = "" },
		func(c *DialAgentConfig) { c.ClientCertFile = ""; c.ClientKeyFile = "" },
		func(c *DialAgentConfig) { c.User = "tester" },
	} {
		test := valid
		mutate(&test)
		if _, _, err := test.Validate(); err == nil {
			t.Fatalf("accepted invalid helper configuration: %+v", test)
		}
	}
}

func TestMASQUEOutboundPrivatePacketAdmission(t *testing.T) {
	own := netip.MustParseAddr("10.251.95.2")
	peer := netip.MustParseAddr("10.251.95.1")
	if yes, err := validateOutboundIPv4Packet(testPacket(), own, peer); !yes || err != nil {
		t.Fatalf("good IPv4 rejected: %v", err)
	}
	if yes, err := validateOutboundIPv4Packet([]byte{0x60, 0, 0, 0}, own, peer); yes || err != nil {
		t.Fatalf("kernel IPv6 control traffic must be dropped harmlessly: %v", err)
	}
	foreign := testPacket()
	foreign[16] = 12
	if yes, err := validateOutboundIPv4Packet(foreign, own, peer); yes || err == nil {
		t.Fatal("foreign peer destination was not rejected")
	}
	invalid := testPacket()
	invalid[2] = 0
	invalid[3] = 5
	if yes, err := validateOutboundIPv4Packet(invalid, own, peer); yes || err == nil {
		t.Fatal("malformed private IPv4 length was not rejected")
	}
}

func TestProtectedHelperFileNeverFollowsSymlink(t *testing.T) {
	root := t.TempDir()
	normal := filepath.Join(root, "agent.json")
	payload, err := json.Marshal(testDialAgentConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(normal, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedAgentConfig(normal); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "link.json")
	if err := os.Symlink(normal, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedAgentConfig(alias); err == nil {
		t.Fatal("followed protected configuration symlink")
	}
	if err := os.Chmod(normal, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedAgentConfig(normal); err == nil {
		t.Fatal("accepted world-readable protected configuration")
	}
	if err := os.Chmod(normal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(normal, []byte(strings.Repeat("a", 32769)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedAgentConfig(normal); err == nil {
		t.Fatal("accepted oversized protected configuration")
	}
}
