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
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/managedmtu"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Canonical immutable fixture identities shared by input and result checks.
const (
	greMultiPeerABID = "lnk_abababababababababababababababab"
	greMultiPeerACID = "lnk_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

// This test is compiled into the normal test binary but never changes a host
// unless an explicitly approved disposable netns runner opts in. It exercises
// the production CLI -> Engine -> GRE backend path, not a parallel lifecycle.
func TestGRENetnsE2E(t *testing.T) {
	if os.Getenv("STL_GRE_NETNS_E2E") != "1" {
		t.Skip("privileged GRE acceptance requires an approved disposable GRE runner")
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
	multiPeer := os.Getenv("STL_GRE_MULTI_PEER_E2E") == "approved"
	root := required("STL_GRE_E2E_STATE_ROOT")
	parent := filepath.Base(filepath.Dir(root))
	side := filepath.Base(root)
	if root != filepath.Clean(root) || filepath.Dir(filepath.Dir(root)) != "/tmp" ||
		!(multiPeer && strings.HasPrefix(parent, "stl-gre-multipeer.") &&
			(side == "a" || side == "b" || side == "c") ||
			!multiPeer && strings.HasPrefix(parent, "stl-gre-e2e.") &&
				(side == "a" || side == "b")) {
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
	if multiPeer {
		// Two immutable native GRE pairs, one shared A-side desired-state root.
		matchPair := func(wantID domain.LinkID, ulLocal, ulPeer, local, peer string) bool {
			return id == wantID && localUnderlay.String() == ulLocal &&
				peerUnderlay.String() == ulPeer && localAddress.String() == local &&
				peerAddress.String() == peer
		}
		ab := domain.LinkID(greMultiPeerABID)
		ac := domain.LinkID(greMultiPeerACID)
		allowed := matchPair(ab, "192.0.2.10", "192.0.2.11", "10.85.10.0/31", "10.85.10.1/31") ||
			matchPair(ab, "192.0.2.11", "192.0.2.10", "10.85.10.1/31", "10.85.10.0/31") ||
			matchPair(ac, "192.0.2.20", "192.0.2.21", "10.85.20.0/31", "10.85.20.1/31") ||
			matchPair(ac, "192.0.2.21", "192.0.2.20", "10.85.20.1/31", "10.85.20.0/31")
		if !allowed || encap != domain.EncapNative || port != 0 || os.Getenv("STL_GRE_E2E_KEY") != "" {
			t.Fatal("refusing noncanonical multi-peer GRE fixture")
		}
	} else if !((localUnderlay.String() == "192.0.2.10" && peerUnderlay.String() == "192.0.2.11") ||
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
		// Production runtime always registers the MTU Engine writer, even for
		// v1 reensure of a Link that previously saved a managed MTU. The
		// test's per-action process must reflect the same invariant.
		mtuManager: managedmtu.HostMTUManager{
			Runner: runner, SetByIndex: linux.SetLinkMTUByIndex,
		},
	}
	version := 1
	if action == "mtu" || action == "mtu-reapply" {
		if multiPeer || encap != domain.EncapNative || localUnderlay.String() != "192.0.2.10" {
			t.Fatal("managed MTU acceptance requires canonical isolated first-side native GRE fixture")
		}
		link.MTU = domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1300}
		version = managedMTUSchemaVersion
	}
	desired, err := json.Marshal(map[string]any{"schema_version": version, "link": link})
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	switch action {
	case "ensure", "reensure", "conflict", "repair", "race", "mtu", "mtu-reapply":
		args = []string{"link", "ensure", "--stdin", "--json"}
	case "status":
		args = []string{"link", "status", string(id), "--json"}
	case "diagnose":
		args = []string{"link", "diagnose", string(id), "--json"}
	case "parallel-health":
		// The existing disposable three-GRE Link fixture gives this
		// operator command authentic kernel identities and peer ICMP.
		// No fake observer, new host privilege or mutable adapter is used.
		if multiPeer {
			t.Fatal("parallel health acceptance uses the three-mode two-peer fixture")
		}
		args = []string{"link", "diagnose", "--all", "--parallel", "3", "--timeout", "60s", "--json"}
	case "remove":
		args = []string{"link", "remove", string(id), "--confirm", string(id), "--json"}
	case "list", "multi-list", "multi-survivor":
		args = []string{"link", "list", "--json"}
	default:
		t.Fatalf("unsupported GRE test action %q", action)
	}
	var stdout, stderr bytes.Buffer
	exit := runWithRuntimeInput(args, bytes.NewReader(desired), &stdout, &stderr, options)
	if action == "race" {
		if exit == 0 {
			var result map[string]any
			if json.Unmarshal(stdout.Bytes(), &result) != nil ||
				result["schema_version"] != float64(1) || result["link_id"] != string(id) ||
				result["changed"] != true {
				t.Fatal("concurrent GRE claim returned malformed success")
			}
			t.Logf("GRE_RESOURCE_RACE_ACCEPTED link_id=%s", id)
			return
		}
		var rejected struct {
			SchemaVersion int `json:"schema_version"`
			Error         struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if exit != 1 || json.Unmarshal(stdout.Bytes(), &rejected) != nil ||
			rejected.SchemaVersion != 1 || rejected.Error.Code != "conflict" {
			t.Fatalf("concurrent GRE claim returned neither owned success nor typed conflict: exit=%d", exit)
		}
		t.Logf("GRE_RESOURCE_RACE_REJECTED link_id=%s", id)
		return
	}
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
	case "ensure", "reensure", "repair", "mtu", "mtu-reapply":
		if result["link_id"] != string(id) ||
			result["changed"] != (action != "reensure" && action != "mtu-reapply") {
			t.Fatalf("%s: wrong idempotent ensure outcome: %s", action, stdout.String())
		}
		if action == "mtu" || action == "mtu-reapply" {
			// The real Linux device, NOT the desired-state JSON, proves that
			// canonical Engine Apply updated the exact GRE interface.
			name, err := grebackend.InterfaceName(id)
			if err != nil {
				t.Fatal(err)
			}
			output, err := runner.Run(t.Context(), "ip", "-json", "link", "show", "dev", name)
			if err != nil {
				t.Fatal("managed GRE MTU inspection failed")
			}
			var actual []struct {
				MTU int `json:"mtu"`
			}
			if err := json.Unmarshal(output.Stdout, &actual); err != nil || len(actual) != 1 || actual[0].MTU != 1300 {
				t.Fatalf("real owned GRE MTU was not applied: %+v %v", actual, err)
			}
			snap, err := state.NewFileStore(root).Load(t.Context())
			record, ok := snap.Find(id)
			if err != nil || !ok || record.Desired.MTU != link.MTU {
				t.Fatalf("actual managed MTU policy not persisted: %+v %v", record, err)
			}
			t.Logf("GRE_REAL_MANAGED_MTU=PASS desired=%d observed=%d mode=%s", link.MTU.Bytes, actual[0].MTU, action)
		}
	case "status":
		if result["interface_verified"] != true || result["connectivity"] != "not_measured" || result["gre_state"] == nil {
			t.Fatalf("status must verify real GRE ownership without claiming traffic: %s", stdout.String())
		}
	case "parallel-health":
		var batch healthCenterResponse
		if err := json.Unmarshal(stdout.Bytes(), &batch); err != nil {
			t.Fatalf("parallel real-kernel health JSON invalid: %v", err)
		}
		if batch.SchemaVersion != jsonSchemaVersion || batch.Operation != "link_diagnose_all" ||
			batch.Outcome != "complete" || batch.Total != 3 || batch.Observed != 3 ||
			batch.Unknown != 0 || batch.Blocked != 0 || len(batch.Checks) != 3 {
			t.Fatalf("parallel real-kernel Link inventory incomplete: %+v", batch)
		}
		wantIDs := []domain.LinkID{
			"lnk_11111111111111111111111111111111",
			"lnk_22222222222222222222222222222222",
			"lnk_33333333333333333333333333333333",
		}
		wantModes := []domain.Encapsulation{domain.EncapNative, domain.EncapFOU, domain.EncapGUE}
		for i, check := range batch.Checks {
			if check.Link.ID != wantIDs[i] || check.Link.Backend != domain.BackendGRE ||
				check.Link.Encapsulation != wantModes[i] ||
				check.Status != "observed" || check.ReasonCode != "link_peer_replied" ||
				check.Observed == nil || check.Observed.MTU.SelectedMTU < 1280 ||
				check.Observed.Quality.Status != diagnostics.QualityMeasured ||
				!check.Observed.Quality.Reachable ||
				check.Observed.Quality.PacketsSent != diagnostics.DefaultQualitySamples ||
				check.Observed.Quality.PacketsReceived < 1 ||
				check.Observed.Quality.PacketsReceived > check.Observed.Quality.PacketsSent ||
				check.Observed.CounterUnit != "packets" ||
				check.Observed.RX == nil || check.Observed.TX == nil ||
				*check.Observed.RX == 0 || *check.Observed.TX == 0 {
				t.Fatalf("parallel real-kernel peer proof missing or Link order changed: index=%d check=%+v", i, check)
			}
		}
		t.Log("GRE_THREE_LINK_PARALLEL_HEALTH_REAL_KERNEL=PASS")
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
	case "multi-list", "multi-survivor":
		if !multiPeer {
			t.Fatal("multi-peer list check requires isolated opt-in")
		}
		ab := greMultiPeerABID
		ac := greMultiPeerACID
		var expected []string
		if action == "multi-list" {
			switch side {
			case "a":
				expected = []string{ab, ac}
			case "b":
				expected = []string{ab}
			case "c":
				expected = []string{ac}
			}
		} else {
			switch side {
			case "a", "c":
				expected = []string{ac}
			case "b":
				expected = []string{}
			}
		}
		links, ok := result["links"].([]any)
		if !ok || len(links) != len(expected) {
			t.Fatalf("%s: expected %d Links in %s: %s", action, len(expected), side, stdout.String())
		}
		seen := make(map[string]bool, len(links))
		for _, raw := range links {
			item, ok := raw.(map[string]any)
			if !ok {
				t.Fatalf("invalid Link list entry: %s", stdout.String())
			}
			got, ok := item["id"].(string)
			if !ok || seen[got] {
				t.Fatalf("missing or duplicate Link ID: %s", stdout.String())
			}
			seen[got] = true
		}
		for _, want := range expected {
			if !seen[want] {
				t.Fatalf("wrong persisted Link IDs for %s: %s", side, stdout.String())
			}
		}
	case "list":
		links, ok := result["links"].([]any)
		if !ok || len(links) != 0 {
			t.Fatalf("expected no persisted Links after cleanup: %s", stdout.String())
		}
	}
	t.Logf("GRE_NETNS_VERIFIED mode=%s action=%s link_id=%s", encap, action, id)
}
