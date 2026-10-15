package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// The embedded script is a SOURCE-IDENTICAL snapshot, never a separately
// maintained implementation or an uncontrolled download at root TTY.
func TestCanonicalInstallerEmbeddedSourceIdentity(t *testing.T) {
	expected, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, canonicalInstaller) {
		t.Fatal("embedded package installer drifted from canonical source; resync before packaging")
	}
	if err := menuEmbeddedInstallerSanity(); err != nil {
		t.Fatal(err)
	}
}
func TestSelectedPackagePlanIsTypedAndReadOnly(t *testing.T) {
	for _, tc := range []struct {
		sel  tunnelOption
		want string
	}{
		{tunnelOption{backend: domain.BackendGRE, mode: domain.EncapFOU}, "native"},
		{tunnelOption{backend: domain.BackendIPIP, mode: domain.EncapNative}, "native"},
		{tunnelOption{backend: domain.BackendWireGuard, mode: domain.EncapUDP}, "native,wireguard"},
		{tunnelOption{backend: domain.BackendIPsec, mode: domain.EncapESP}, "native,ipsec"},
	} {
		if got := selectedPackageBackends(tc.sel); got != tc.want {
			t.Fatalf("%s: %s", tc.want, got)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		plan, err := readSelectedPackagePreview(ctx, tc.sel)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", tc.want, err)
		}
		if !strings.Contains(plan.packages, "iproute2 iptables kmod") {
			t.Fatalf("missing baseline requirements: %+v", plan)
		}
	}
	if selectedPackageBackends(tunnelOption{}) != "" {
		t.Fatal("invalid selector gained package provisioning")
	}
}
func TestUnprivilegedOrRedirectedPackagePreviewCannotConsumeCreateInput(t *testing.T) {
	var output, errors bytes.Buffer
	reader := strings.NewReader("PREPARE\nALLOW-IPSEC-PACKAGES\n")
	plan := tunnelOption{backend: domain.BackendIPsec, mode: domain.EncapESP}
	// A read-only inventory is permitted, but root operation is not.
	// Redirected/scripted input cannot authorize managed IPsec preparation;
	// a false return requests root-TTY PREPARE, never a privileged effect.
	_ = menuPrepareSelectedPackages(reader, nil, &output, &errors, plan, nil)
	if strings.Contains(output.String(), "Canonical installer verifying") ||
		strings.Contains(output.String(), "Selected packages now pass") {
		t.Fatalf("scripted package preview claimed mutation or success: %q", output.String())
	}
	if errors.Len() != 0 {
		t.Fatalf("leaked error: %q", errors.String())
	}
}

// Bash inherits BASH_ENV for a noninteractive script unless its execution
// environment is sanitized. The embedded privileged invocation MUST NOT
// interpret inherited shell startup code before the canonical installer.
func TestCanonicalPackageInstallerDoesNotSourceInheritedBashEnv(t *testing.T) {
	tmp := t.TempDir()
	hook := tmp + "/injected.sh"
	if err := os.WriteFile(hook, []byte("touch "+tmp+"/WRONG\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", hook)
	t.Setenv("ENV", hook)
	t.Setenv("PATH", tmp)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := readSelectedPackagePreview(ctx, tunnelOption{backend: domain.BackendGRE, mode: domain.EncapNative}); err != nil {
		t.Fatalf("sanitized canonical plan failed: %v", err)
	}
	if _, err := os.Stat(tmp + "/WRONG"); !os.IsNotExist(err) {
		t.Fatalf("untrusted shell environment executed before installer: %v", err)
	}
}

func TestMissingStrongSwanPackagePlanCannotAuthorizeAPT(t *testing.T) {
	for _, tc := range []struct {
		missing string
		manual  bool
	}{
		{"iptables charon-systemd strongswan-swanctl", true},
		{"libstrongswan-standard-plugins", true},
		{"wireguard-tools", false},
		{"iproute2 kmod", false},
		{"", false},
	} {
		if got := missingStrongSwanPackages(tc.missing); got != tc.manual {
			t.Fatalf("missing=%q manual=%t expected=%t", tc.missing, got, tc.manual)
		}
	}
}

func TestBlockedIPsecWarningPreservesEarlierPackageAndServiceEffects(t *testing.T) {
	for _, attempted := range []bool{false, true} {
		var out bytes.Buffer
		menuIPsecBlockedNotice(&out, attempted)
		body := out.String()
		if !strings.Contains(body, "may have changed") && !strings.Contains(body, "may have started or enabled") {
			t.Fatalf("unverified service/package effects were concealed: %q", body)
		}
		if strings.Contains(body, "No keys, services, packages or tunnels were changed") ||
			strings.Contains(body, "No packages or services changed") {
			t.Fatalf("false no-effect assertion after possible APT: %q", body)
		}
		if !strings.Contains(body, "No Link or keys") && !strings.Contains(body, "No IPsec Link or keys") {
			t.Fatalf("failure no-Link semantics missing: %q", body)
		}
	}
}
