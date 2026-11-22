package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/spoofhost"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestSpoofRPFilterCLIReadOnlyPreviewApprovalOffAndRestore(t *testing.T) {
	root, proc := t.TempDir(), t.TempDir()
	for _, nic := range []string{"all", "enp5s0"} {
		path := filepath.Join(proc, "net", "ipv4", "conf", nic, "rp_filter")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	link := domain.Link{
		ID: "lnk_1234567890abcdef1234567890abcdef", Backend: domain.BackendSpoof, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("10.246.52.1"), Peer: netip.MustParseAddr("10.246.52.2")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.248.55.1/32"), Peer: netip.MustParsePrefix("10.248.55.2/32")},
		Spoof:     domain.SpoofOptions{Role: "creator", SourceFile: "/root/stl/spoof/sources.txt", OuterProtocol: "udp", ListenPort: 48001, PeerPort: 48002, IngressInterface: "enp5s0", LocalPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), MaterialSHA256: strings.Repeat("a", 64)},
	}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	if err := store.Update(context.Background(), func(s *state.Snapshot) error { s.Upsert(state.LinkRecord{Desired: link}); return nil }); err != nil {
		t.Fatal(err)
	}
	options := &runtimeOptions{stateRoot: root, configureEngine: func(e *app.Engine) { e.SetSpoofRPFilterManager(spoofhost.ManagedRPFilter{Root: root, ProcRoot: proc}) }}
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errs bytes.Buffer
		rc := runWithRuntime(args, &out, &errs, options)
		return rc, out.String(), errs.String()
	}
	path := filepath.Join(proc, "net", "ipv4", "conf", "all", "rp_filter")
	rc, out, errOut := run("link", "rp-filter", "plan", string(link.ID), "--mode", "off", "--json")
	if rc != 0 {
		t.Fatalf("preview failed: %s", errOut)
	}
	var plan struct {
		Operation string                `json:"operation"`
		Plan      app.SpoofRPFilterPlan `json:"plan"`
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil || !plan.Plan.GlobalImpact || plan.Plan.EffectiveAfter != 0 {
		t.Fatalf("incorrect preview %v %+v", err, plan)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "1\n" {
		t.Fatal("read-only preview mutated the host")
	}
	if rc, _, _ := run("link", "rp-filter", "apply", string(link.ID), "--mode", "off"); rc == 0 {
		t.Fatal("unconfirmed mutation accepted")
	}
	if rc, _, _ := run("link", "rp-filter", "apply", string(link.ID), "--mode", "off", "--confirm", "lnk_00000000000000000000000000000000"); rc == 0 {
		t.Fatal("wrong confirmation accepted")
	}
	if rc, out, errOut := run("link", "rp-filter", "apply", string(link.ID), "--mode", "off", "--confirm", string(link.ID)); rc != 0 || !strings.Contains(out, "Applied and verified") {
		t.Fatalf("actual change rejected: %s %s", out, errOut)
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != "0" {
		t.Fatalf("confirmed global off not applied: %q", raw)
	}
	if rc, out, errOut := run("link", "rp-filter", "restore", string(link.ID), "--confirm", string(link.ID)); rc != 0 {
		t.Fatalf("restore failed %s %s", out, errOut)
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != "1" {
		t.Fatalf("global policy not restored: %q", raw)
	}
}
