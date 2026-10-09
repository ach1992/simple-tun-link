//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// This test is compiled into the normal test binary but never changes a host
// unless an explicitly approved disposable netns runner opts in. It exercises
// the production CLI -> Engine -> GRE backend path, not a parallel lifecycle.
func TestGRENetnsE2E(t *testing.T) {
	if os.Getenv("STL_GRE_NETNS_E2E") != "1" {
		t.Skip("privileged GRE acceptance runs only via scripts/e2e/gre-netns.sh")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged GRE acceptance requires disposable-test root")
	}
	selfNetNS, selfErr := os.Readlink("/proc/self/ns/net")
	initNetNS, initErr := os.Readlink("/proc/1/ns/net")
	if selfErr != nil || initErr != nil || selfNetNS == initNetNS {
		t.Fatal("refusing GRE mutation outside a separate network namespace")
	}
	required := func(key string) string {
		value := os.Getenv(key)
		if value == "" {
			t.Fatalf("missing GRE netns test parameter %s", key)
		}
		return value
	}
	root := required("STL_GRE_E2E_STATE_ROOT")
	if root != filepath.Clean(root) || filepath.Dir(filepath.Dir(root)) != "/tmp" ||
		!strings.HasPrefix(filepath.Base(filepath.Dir(root)), "stl-gre-e2e.") ||
		(filepath.Base(root) != "a" && filepath.Base(root) != "b") {
		t.Fatal("refusing GRE test state outside the scoped temporary runner directory")
	}
	action := required("STL_GRE_E2E_ACTION")
	id := domain.LinkID(required("STL_GRE_E2E_ID"))
	encap := domain.Encapsulation(required("STL_GRE_E2E_ENCAP"))
	localUnderlay, err := netip.ParseAddr(required("STL_GRE_E2E_UL_LOCAL"))
	if err != nil {
		t.Fatal("invalid synthetic local underlay", err)
	}
	peerUnderlay, err := netip.ParseAddr(required("STL_GRE_E2E_UL_PEER"))
	if err != nil {
		t.Fatal("invalid synthetic peer underlay", err)
	}
	localAddress, err := netip.ParsePrefix(required("STL_GRE_E2E_LINK_LOCAL"))
	if err != nil {
		t.Fatal("invalid synthetic local Link Address", err)
	}
	peerAddress, err := netip.ParsePrefix(required("STL_GRE_E2E_LINK_PEER"))
	if err != nil {
		t.Fatal("invalid synthetic peer Link Address", err)
	}
	port, err := strconv.ParseUint(required("STL_GRE_E2E_PORT"), 10, 16)
	if err != nil {
		t.Fatal("invalid synthetic GRE UDP port", err)
	}
	if !((localUnderlay.String() == "192.0.2.10" && peerUnderlay.String() == "192.0.2.11") ||
		(localUnderlay.String() == "192.0.2.11" && peerUnderlay.String() == "192.0.2.10")) ||
		!strings.HasPrefix(localAddress.String(), "10.81.") ||
		!strings.HasPrefix(peerAddress.String(), "10.81.") {
		t.Fatal("refusing any non-synthetic GRE namespace test endpoints")
	}
	greOptions := domain.GREOptions{UDPPort: uint16(port)}
	if keyText := os.Getenv("STL_GRE_E2E_KEY"); keyText != "" {
		key, err := strconv.ParseUint(keyText, 10, 32)
		if err != nil {
			t.Fatal("invalid synthetic GRE test key")
		}
		greOptions.KeyEnabled, greOptions.Key = true, uint32(key)
	}
	link := domain.Link{
		ID:            id,
		Backend:       domain.BackendGRE,
		Encapsulation: encap,
		Underlay:      domain.Underlay{Local: localUnderlay, Peer: peerUnderlay},
		Addresses:     domain.LinkAddresses{Local: localAddress, Peer: peerAddress},
		GRE:           greOptions,
	}
	if err := link.Validate(); err != nil {
		t.Fatal("invalid synthetic GRE test Link", err)
	}

	runner := linux.ExecRunner{}
	locks := state.NewLockManager(root)
	gre, err := grebackend.New(grebackend.Options{
		Runner:     runner,
		Routes:     linux.RouteResolver{Runner: runner},
		Firewall:   linux.IPTablesFirewall{Runner: runner, Locks: locks},
		Collisions: linux.CollisionInspector{Snapshotter: linux.HostSnapshotter{Runner: runner}},
	})
	if err != nil {
		t.Fatal("initialize production GRE backend", err)
	}
	options := &runtimeOptions{
		stateRoot: root, backends: []backend.Backend{gre}, probeRunner: runner,
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
		t.Fatalf("unsupported GRE test action %q", action)
	}
	var stdout, stderr bytes.Buffer
	exit := runWithRuntimeInput(args, bytes.NewReader(desired), &stdout, &stderr, options)
	if action == "conflict" {
		var rejected struct {
			SchemaVersion int `json:"schema_version"`
			Error         struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(stdout.Bytes(), &rejected) != nil ||
			exit != 1 || rejected.SchemaVersion != 1 || rejected.Error.Code != "conflict" {
			t.Fatalf("expected typed, non-mutating GRE receive conflict: exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
		}
		t.Logf("GRE_RECEIVE_CONFLICT_REJECTED link_id=%s", id)
		return
	}
	if exit != 0 {
		t.Fatalf("GRE %s/%s %s: exit=%d stdout=%q stderr=%q",
			encap, id, action, exit, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid machine JSON for %s: %v", action, err)
	}
	if result["schema_version"] != float64(1) {
		t.Fatalf("%s: missing expected CLI schema_version", action)
	}
	switch action {
	case "ensure", "reensure":
		if result["link_id"] != string(id) || result["changed"] != (action == "ensure") {
			t.Fatalf("%s: wrong idempotent ensure outcome: %s", action, stdout.String())
		}
	case "status":
		if result["interface_verified"] != true || result["connectivity"] != "not_measured" || result["gre_state"] == nil {
			t.Fatalf("status must verify real GRE ownership without claiming traffic: %s", stdout.String())
		}
	case "diagnose":
		quality, ok := result["quality"].(map[string]any)
		if !ok || quality["reachable"] != true {
			t.Fatalf("diagnose did not prove Link Address reachability: %s", stdout.String())
		}
		state, ok := result["state"].(map[string]any)
		if !ok {
			t.Fatalf("diagnose lacks identity-checked GRE counter state: %s", stdout.String())
		}
		rx, rxOK := state["rx_packets"].(float64)
		tx, txOK := state["tx_packets"].(float64)
		if !rxOK || !txOK || rx < 1 || tx < 1 {
			t.Fatalf("bidirectional probe produced no observed GRE RX/TX packets: %s", stdout.String())
		}
		t.Logf("GRE_E2E_COUNTERS mode=%s rx_packets=%v tx_packets=%v", encap, rx, tx)
	case "remove":
		if result["link_id"] != string(id) || result["removed"] != true {
			t.Fatalf("remove did not confirm owned Link removal: %s", stdout.String())
		}
	case "list":
		links, ok := result["links"].([]any)
		if !ok || len(links) != 0 {
			t.Fatalf("expected no persisted Links after cleanup: %s", stdout.String())
		}
	}
	t.Logf("GRE_NETNS_VERIFIED mode=%s action=%s link_id=%s", encap, action, id)
}
