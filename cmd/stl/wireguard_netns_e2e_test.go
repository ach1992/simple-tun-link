//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Explicit opt-in REAL kernel acceptance using two disposable veth-backed
// netns only. No mutation may run in the init namespace; every allowed path,
// address and ID belongs to the purpose-built runner fixture. No real keys or
// Setup Links are printed. Normal Go CI compiles but skips this test.
func TestWireGuardNetnsE2E(t *testing.T) {
	if os.Getenv("STL_WG_NETNS_E2E") != "1" {
		t.Skip("privileged WG two-peer acceptance: scripts/e2e/wireguard-netns.sh")
	}
	if os.Geteuid() != 0 {
		t.Fatal("refusing non-root WireGuard E2E")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil || self == init {
		t.Fatal("refusing WireGuard mutation outside disposable netns")
	}
	root := os.Getenv("STL_WG_E2E_STATE_ROOT")
	crossMode := os.Getenv("STL_WG_CROSS_E2E") == "1"
	fixtureDir := filepath.Base(filepath.Dir(root))
	allowedFixture := strings.HasPrefix(fixtureDir, "stl-wg-e2e.")
	if crossMode {
		allowedFixture = strings.HasPrefix(fixtureDir, "stl-gre-e2e.")
	}
	if root != filepath.Clean(root) || filepath.Dir(filepath.Dir(root)) != "/tmp" ||
		!allowedFixture || (filepath.Base(root) != "a" && filepath.Base(root) != "b") {
		t.Fatal("refusing non-disposable credential root")
	}
	const testID = domain.LinkID("lnk_88888888888888888888888888888888")
	runner := linux.ExecRunner{}
	locks := state.NewLockManager(root)
	keys, err := wgbackend.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	backendWG, err := wgbackend.New(wgbackend.Options{Runner: runner, Routes: linux.RouteResolver{Runner: runner},
		Firewall:   linux.IPTablesFirewall{Runner: runner, Locks: locks},
		Collisions: linux.CollisionInspector{Snapshotter: linux.HostSnapshotter{Runner: runner}}, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{backendWG}, probeRunner: runner}
	action := os.Getenv("STL_WG_E2E_ACTION")
	handoff := filepath.Join(filepath.Dir(root), "a", "receiver.stl")
	call := func(args []string, input []byte) map[string]any {
		t.Helper()
		var out, errOut bytes.Buffer
		result := runWithRuntimeInput(args, bytes.NewReader(input), &out, &errOut, opts)
		if result != 0 || errOut.Len() > 0 {
			// Never print input, private key, Setup Link or source-sensitive stdout.
			t.Fatalf("WG E2E action %q returned exit=%d stderr-present=%t", args[1], result, errOut.Len() > 0)
		}
		var obj map[string]any
		if err := json.Unmarshal(out.Bytes(), &obj); err != nil {
			t.Fatalf("WG E2E invalid redacted JSON action=%s", args[1])
		}
		if obj["schema_version"] != float64(1) {
			t.Fatalf("WG E2E wrong machine schema action=%s", args[1])
		}
		return obj
	}
	readHandoff := func() []byte {
		t.Helper()
		raw, err := os.ReadFile(handoff)
		if err != nil {
			t.Fatal("protected sender handoff unavailable", err)
		}
		return raw
	}
	switch action {
	case "create":
		if filepath.Base(root) != "a" {
			t.Fatal("sender Create requires a namespace")
		}
		request := wireGuardSenderRequestV1{SchemaVersion: 1, LinkID: testID,
			Underlay:   desiredUnderlayV1{Local: mustWGAddr(t, "192.0.2.10"), Peer: mustWGAddr(t, "192.0.2.11")},
			Addresses:  desiredLinkAddressesV1{Local: mustWGPrefix(t, "10.83.10.0/31"), Peer: mustWGPrefix(t, "10.83.10.1/31")},
			ListenPort: 51871, PeerPort: 51872, LocalKeepalive: 25, PeerKeepalive: 25}
		publicRequest, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		response := call([]string{"link", "create-wireguard", "--stdin", "--output", handoff, "--json"}, publicRequest)
		if response["link_id"] != string(testID) || response["sensitive"] != true || response["changed"] != true || response["handoff_file"] != handoff {
			t.Fatal("real sender did not create a protected identity-bound Quick Link")
		}
		file, err := os.Stat(handoff)
		if err != nil || file.Mode().Perm() != 0o600 {
			t.Fatal("real handoff file not mode 0600")
		}
	case "import":
		if filepath.Base(root) != "b" {
			t.Fatal("receiver Import requires b namespace")
		}
		raw := readHandoff()
		pre := call([]string{"link", "preview", "--stdin", "--json"}, raw)
		digest, ok := pre["import_confirmation"].(string)
		if !ok || len(digest) != 64 || pre["sensitive"] != true || pre["pairing_schema_version"] != float64(3) {
			t.Fatal("receiver cannot review bound v3 Quick Link")
		}
		resp := call([]string{"link", "import", "--stdin", "--confirm", digest, "--json"}, raw)
		if resp["link_id"] != string(testID) || resp["changed"] != true {
			t.Fatal("receiver did not activate Link")
		}
	case "resume":
		if filepath.Base(root) != "a" {
			t.Fatal("sender resume requires a namespace")
		}
		raw := readHandoff()
		token := setupLinkConfirmation(strings.TrimSpace(string(raw)))
		resp := call([]string{"link", "resume-wireguard", "--stdin", "--confirm", token, "--json"}, raw)
		if resp["changed"] != false {
			t.Fatal("verified sender retry should be idempotent")
		}
	case "status":
		resp := call([]string{"link", "status", string(testID), "--json"}, nil)
		wg, ok := resp["wireguard_state"].(map[string]any)
		if !ok || resp["connectivity"] != "not_measured" || resp["interface_verified"] != true ||
			wg["rx_bytes"].(float64) < 1 || wg["tx_bytes"].(float64) < 1 || wg["latest_handshake_unix"].(float64) < 1 {
			t.Fatal("real WireGuard status lacks handshake or bidirectional transfer evidence")
		}
		t.Logf("WG_REAL_E2E public_counters_verified handshake=%v rx=%v tx=%v", wg["latest_handshake_unix"], wg["rx_bytes"], wg["tx_bytes"])
	case "diagnose":
		resp := call([]string{"link", "diagnose", string(testID), "--json"}, nil)
		quality, ok := resp["quality"].(map[string]any)
		if !ok || quality["reachable"] != true || resp["backend"] != string(domain.BackendWireGuard) {
			t.Fatal("real WireGuard active diagnostic did not prove Link Address reachability")
		}
		mtu, ok := resp["mtu"].(map[string]any)
		if !ok {
			t.Fatal("real WireGuard active diagnostic lacks MTU result")
		}
		selected, selectedOK := mtu["selected_mtu"].(float64)
		ceiling, ceilingOK := mtu["ceiling_mtu"].(float64)
		if !selectedOK || !ceilingOK || selected < 68 || selected > ceiling ||
			mtu["verified"] != true || mtu["choice"] != "probe_confirmed" {
			t.Fatal("real WireGuard MTU probe did not establish a bounded, verified inner MTU")
		}
		state, ok := resp["state"].(map[string]any)
		if !ok {
			t.Fatal("real WireGuard diagnostic lacks identity-verified interface state")
		}
		interfaceName, ok := state["interface"].(string)
		if !ok || interfaceName == "" {
			t.Fatal("real WireGuard diagnostic interface identity is missing")
		}
		rx, rxOK := state["rx_bytes"].(float64)
		tx, txOK := state["tx_bytes"].(float64)
		if !rxOK || !txOK || rx < 1 || tx < 1 {
			t.Fatal("real WireGuard diagnostic lacks bidirectional public transfer counters")
		}
		t.Logf("WG_REAL_DIAGNOSIS reachability=PASS selected_mtu=%v ceiling_mtu=%v verified=true rx_bytes=%v tx_bytes=%v",
			selected, ceiling, rx, tx)
	case "remove":
		resp := call([]string{"link", "remove", string(testID), "--confirm", string(testID), "--json"}, nil)
		if resp["removed"] != true || resp["link_id"] != string(testID) {
			t.Fatal("real owned WireGuard removal unconfirmed")
		}
	case "retire":
		local, err := keys.Load(testID)
		if err != nil {
			t.Fatal("retirement key unavailable", err)
		}
		pub, err := local.PublicKey()
		local.Zeroize()
		if err != nil {
			t.Fatal(err)
		}
		resp := call([]string{"link", "credential", "retire", string(testID), "--confirm", string(testID), "--public-key", pub, "--json"}, nil)
		if resp["retired"] != true {
			t.Fatal("real private credential retirement unconfirmed")
		}
	case "list", "cross-list":
		if action == "cross-list" && !crossMode {
			t.Fatal("four-Link list requires an explicitly opted-in cross-backend fixture")
		}
		resp := call([]string{"link", "list", "--json"}, nil)
		links, ok := resp["links"].([]any)
		if !ok {
			t.Fatal("real WireGuard Link listing unavailable")
		}
		if crossMode {
			// The exact 3 GRE siblings are persisted before and after the
			// fourth WireGuard Link, with no lost or extra identities.
			expected := map[string]bool{
				"lnk_11111111111111111111111111111111": true,
				"lnk_22222222222222222222222222222222": true,
				"lnk_33333333333333333333333333333333": true,
			}
			if action == "cross-list" {
				expected[string(testID)] = true
			}
			if len(links) != len(expected) {
				t.Fatal("cross-backend Link collection has incorrect number of identities")
			}
			for _, value := range links {
				item, ok := value.(map[string]any)
				if !ok {
					t.Fatal("cross-backend Link collection contains a malformed entry")
				}
				id, ok := item["id"].(string)
				if !ok || !expected[id] {
					t.Fatal("cross-backend Link collection has an unexpected identity")
				}
				delete(expected, id)
			}
			if len(expected) != 0 {
				t.Fatal("cross-backend Link collection lost a Link identity")
			}
		} else if len(links) != 0 {
			t.Fatal("real removed WireGuard Link still in committed state")
		}
	default:
		t.Fatal(fmt.Sprintf("unsupported WG E2E action %q", action))
	}
	t.Logf("WG_REAL_NETNS action=%s PASS", action)
}

func mustWGAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	v, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func mustWGPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()
	v, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
