//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	ipipbackend "github.com/ach1992/simple-tun-link/internal/backend/ipip"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Issue #12: opt-in, namespace-only IPIP integration through the production
// CLI -> Engine -> backend path. No test process may target host networking.
func TestIPIPNetnsE2E(t *testing.T) {
	if os.Getenv("STL_IPIP_NETNS_E2E") != "1" {
		t.Skip("IPIP requires the separately authorized disposable netns runner")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged IPIP acceptance requires disposable-test root")
	}
	selfNS, selfErr := os.Readlink("/proc/self/ns/net")
	initNS, initErr := os.Readlink("/proc/1/ns/net")
	if selfErr != nil || initErr != nil || selfNS == initNS {
		t.Fatal("refusing IPIP test outside a separate network namespace")
	}
	required := func(key string) string {
		value := os.Getenv(key)
		if value == "" {
			t.Fatalf("missing IPIP E2E parameter %s", key)
		}
		return value
	}
	root := required("STL_IPIP_E2E_STATE_ROOT")
	if root != filepath.Clean(root) || filepath.Dir(filepath.Dir(root)) != "/tmp" ||
		!strings.HasPrefix(filepath.Base(filepath.Dir(root)), "stl-gre-e2e.") ||
		(filepath.Base(root) != "a" && filepath.Base(root) != "b") {
		t.Fatal("refusing IPIP state outside the scoped temporary namespace runner")
	}
	action := required("STL_IPIP_E2E_ACTION")
	id := domain.LinkID(required("STL_IPIP_E2E_ID"))
	if err := id.Validate(); err != nil {
		t.Fatal("invalid synthetic IPIP Link ID")
	}
	allowedIDs := map[domain.LinkID]bool{
		"lnk_44444444444444444444444444444444": true,
		"lnk_55555555555555555555555555555555": true,
		"lnk_66666666666666666666666666666666": true,
		"lnk_77777777777777777777777777777777": true,
	}
	if !allowedIDs[id] {
		t.Fatal("refusing non-fixture IPIP Link identity")
	}
	encap := domain.Encapsulation(required("STL_IPIP_E2E_ENCAP"))
	if encap != domain.EncapNative && encap != domain.EncapFOU && encap != domain.EncapGUE {
		t.Fatal("invalid IPIP test encapsulation")
	}
	localUL, err := netip.ParseAddr(required("STL_IPIP_E2E_UL_LOCAL"))
	if err != nil {
		t.Fatal("invalid synthetic local underlay")
	}
	peerUL, err := netip.ParseAddr(required("STL_IPIP_E2E_UL_PEER"))
	if err != nil {
		t.Fatal("invalid synthetic peer underlay")
	}
	local, err := netip.ParsePrefix(required("STL_IPIP_E2E_LINK_LOCAL"))
	if err != nil {
		t.Fatal("invalid synthetic local Link Address")
	}
	peer, err := netip.ParsePrefix(required("STL_IPIP_E2E_LINK_PEER"))
	if err != nil {
		t.Fatal("invalid synthetic peer Link Address")
	}
	allowedSubnet := map[string]bool{
		"10.82.50.0/31": true,
		"10.82.60.0/31": true,
		"10.82.70.0/31": true,
		"10.82.99.0/31": true,
	}
	if !((localUL.String() == "192.0.2.10" && peerUL.String() == "192.0.2.11") ||
		(localUL.String() == "192.0.2.11" && peerUL.String() == "192.0.2.10")) ||
		!local.IsValid() || !peer.IsValid() || local.Bits() != 31 ||
		peer.Bits() != 31 || local.Masked() != peer.Masked() ||
		!allowedSubnet[local.Masked().String()] || local.Addr() == peer.Addr() {
		t.Fatal("refusing non-fixture underlay or Link Addresses")
	}
	link := domain.Link{
		ID:            id,
		Backend:       domain.BackendIPIP,
		Encapsulation: encap,
		Underlay:      domain.Underlay{Local: localUL, Peer: peerUL},
		Addresses:     domain.LinkAddresses{Local: local, Peer: peer},
	}
	if err := link.Validate(); err != nil {
		t.Fatal("invalid synthetic IPIP Link")
	}
	runner := linux.ExecRunner{}
	locks := state.NewLockManager(root)
	adapter, err := ipipbackend.New(ipipbackend.Options{
		Runner: runner, Routes: linux.RouteResolver{Runner: runner},
		Firewall: linux.IPTablesFirewall{Runner: runner, Locks: locks},
		Collisions: linux.CollisionInspector{Snapshotter: linux.HostSnapshotter{Runner: runner}},
	})
	if err != nil {
		t.Fatal("initialize production IPIP backend", err)
	}
	options := &runtimeOptions{
		stateRoot: root, backends: []backend.Backend{adapter}, probeRunner: runner,
	}
	desired, err := json.Marshal(map[string]any{"schema_version": 1, "link": link})
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	switch action {
	case "ensure", "reensure", "conflict":
		args = []string{"link", "ensure", "--stdin", "--json"}
	case "status":
		args = []string{"link", "status", string(id), "--json"}
	case "diagnose":
		args = []string{"link", "diagnose", string(id), "--json"}
	case "remove":
		args = []string{"link", "remove", string(id), "--confirm", string(id), "--json"}
	case "list":
		args = []string{"link", "list", "--json"}
	default:
		t.Fatalf("unsupported IPIP E2E action %q", action)
	}
	var stdout, stderr bytes.Buffer
	exit := runWithRuntimeInput(args, bytes.NewReader(desired), &stdout, &stderr, options)
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid IPIP machine JSON action=%s exit=%d stdout=%q stderr=%q: %v",
			action, exit, stdout.String(), stderr.String(), err)
	}
	if result["schema_version"] != float64(1) {
		t.Fatalf("missing IPIP machine schema: %s", stdout.String())
	}
	if action == "conflict" {
		errObj, ok := result["error"].(map[string]any)
		if exit != 1 || !ok || errObj["code"] != "conflict" {
			t.Fatalf("expected typed IPIP endpoint conflict; exit=%d output=%s", exit, stdout.String())
		}
		t.Logf("IPIP_SAME_PEER_CONFLICT_REJECTED link_id=%s", id)
		return
	}
	if exit != 0 || stderr.Len() != 0 {
		t.Fatalf("IPIP %s/%s %s failed: exit=%d stdout=%q stderr=%q",
			encap, id, action, exit, stdout.String(), stderr.String())
	}
	switch action {
	case "ensure", "reensure":
		if result["link_id"] != string(id) || result["changed"] != (action == "ensure") || result["removed"] == true {
			t.Fatalf("IPIP ensure/idempotency mismatch: %s", stdout.String())
		}
	case "status":
		if result["interface_verified"] != true || result["ipip_state"] == nil ||
			result["gre_state"] != nil || result["connectivity"] != "not_measured" {
			t.Fatalf("IPIP status lacks real inspected interface identity: %s", stdout.String())
		}
	case "diagnose":
		quality, ok := result["quality"].(map[string]any)
		if !ok || quality["reachable"] != true {
			t.Fatalf("IPIP diagnostic probe did not verify reachability: %s", stdout.String())
		}
		observed, ok := result["state"].(map[string]any)
		if !ok {
			t.Fatalf("IPIP diagnostic lacks owned counter state: %s", stdout.String())
		}
		rx, rxOK := observed["rx_packets"].(float64)
		tx, txOK := observed["tx_packets"].(float64)
		if !rxOK || !txOK || rx < 1 || tx < 1 {
			t.Fatalf("IPIP bidirectional traffic produced no verified RX/TX counters: %s", stdout.String())
		}
		t.Logf("IPIP_E2E_COUNTERS mode=%s rx_packets=%v tx_packets=%v", encap, rx, tx)
	case "remove":
		if result["link_id"] != string(id) || result["removed"] != true {
			t.Fatalf("IPIP owned removal was not confirmed: %s", stdout.String())
		}
	case "list":
		// The shared state intentionally still contains unrelated GRE Links.
		// Never mistake their presence for IPIP cleanup failure.
		links, ok := result["links"].([]any)
		if !ok {
			t.Fatalf("IPIP cleanup returned no machine Link collection: %s", stdout.String())
		}
		for _, item := range links {
			m, ok := item.(map[string]any)
			if !ok || m["id"] == string(id) {
				t.Fatalf("IPIP Link persists or listing is invalid: %s", stdout.String())
			}
		}
	}
	t.Logf("IPIP_NETNS_VERIFIED mode=%s action=%s link_id=%s", encap, action, id)
}
