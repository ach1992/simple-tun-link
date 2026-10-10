package ipsec

import (
	"bytes"
	"strings"
	"testing"
)

func TestNativeExclusiveConfigIsIsolatedAndSecretSafe(t *testing.T) {
	content := NativeExclusiveConfigV1()
	text := string(content)
	if NativeExclusiveConfigPath != "/var/lib/simple-tun-link/ipsec/strongswan.conf" ||
		NativeExclusiveVICIPath != "/run/simple-tun-link/ipsec/charon.vici" ||
		!strings.Contains(text, "socket = unix://"+NativeExclusiveVICIPath) ||
		!strings.Contains(text, "charon-systemd {") ||
		!strings.Contains(text, "journal {") ||
		!strings.Contains(text, "cfg = 1") ||
		!strings.Contains(text, "default = 1") ||
		!strings.Contains(text, "install_routes = no") ||
		!strings.Contains(text, "install_virtual_ip = no") {
		t.Fatal("native config lacks reviewed private endpoint, safe logging or route boundaries")
	}
	for _, unsafe := range []string{"include ", "cfg = 4", "default = 4", "filelog", "syslog", "load-all", "clear-creds", "PSK=", "private_key"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("unsafe strongSwan config directive present: %s", unsafe)
		}
	}
	if err := CheckNativeExclusiveConfigV1(content); err != nil {
		t.Fatal(err)
	}
	// No caller may mutate a singleton slice used as a later policy baseline.
	content[0] = '!'
	if bytes.Equal(content, NativeExclusiveConfigV1()) {
		t.Fatal("native config result aliases mutable shared memory")
	}
}

func TestNativeExclusiveConfigRejectsTamperingWithoutEchoingIt(t *testing.T) {
	original := NativeExclusiveConfigV1()
	changes := [][]byte{
		nil,
		append(bytes.Clone(original), []byte("\ninclude /etc/strongswan.d/*.conf\n")...),
		bytes.Replace(bytes.Clone(original), []byte("cfg = 1"), []byte("cfg = 4"), 1),
		bytes.Replace(bytes.Clone(original), []byte("default = 1"), []byte("default = 4"), 1),
		bytes.Replace(bytes.Clone(original), []byte(NativeExclusiveVICIPath), []byte("/run/charon.vici"), 1),
		append(bytes.Clone(original), []byte("\nPSK=DO_NOT_PRINT\n")...),
	}
	for n, altered := range changes {
		err := CheckNativeExclusiveConfigV1(altered)
		if err == nil {
			t.Fatalf("accepted altered daemon policy %d", n)
		}
		if strings.Contains(err.Error(), "DO_NOT_PRINT") || strings.Contains(err.Error(), "PSK=") ||
			strings.Contains(err.Error(), "/etc/strongswan.d") {
			t.Fatalf("configuration error leaked untrusted bytes: %q", err)
		}
	}
}
