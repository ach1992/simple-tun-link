package spoofhost

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestPersistentPreviouslyAuthenticatedPathsAndNoExpiration(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "spoof", string(id))
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	a := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.11"), Profile: carrier.ProfileUDP}
	b := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.99"), Profile: carrier.ProfileICMP}
	c := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.99"), Profile: carrier.ProfileL2TPv3}
	var paths []carrier.SourcePath
	for _, p := range []carrier.SourcePath{a, b, c, a, b} {
		paths, _ = rememberPath(paths, p)
		if err := writeHistory(root, id, paths); err != nil {
			t.Fatal(err)
		}
	}
	reloaded, err := readHistory(root, id)
	if err != nil || !reflect.DeepEqual(paths, reloaded) {
		t.Fatalf("reboot lost learned sources: %v %v", reloaded, err)
	}
	if len(reloaded) != 3 {
		t.Fatal("recurring use lost history")
	}
	info, err := os.Stat(filepath.Join(dir, "history.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("history file must remain protected: %v %v", info, err)
	}
	// No auto expiry; a source not currently present in the local file is
	// filtered when scheduling but remains part of historical evidence.
	if paths, changed := rememberPath(reloaded, reloaded[0]); changed || !reflect.DeepEqual(paths, reloaded) {
		t.Fatal("unchanged successful candidate caused an unnecessary state write")
	}
	if err := os.Remove(filepath.Join(dir, "history.json")); err != nil {
		t.Fatal(err)
	}
	read, err := readHistory(root, id)
	if err != nil || len(read) != 0 {
		t.Fatalf("new link missing history is normal: %v %v", read, err)
	}
}

func TestRecoveryTriesAllPreviousGoodPathsBeforeExhaustiveMatrix(t *testing.T) {
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	link := domain.Link{ID: id, Spoof: domain.SpoofOptions{OuterProtocol: "auto"}}
	a := newAgent(t.TempDir(), link, Material{}, nil)
	first := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.11"), Profile: carrier.ProfileUDP}
	second := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.12"), Profile: carrier.ProfileICMP}
	// This source remains in the historical file but was removed from the
	// operator's live local Source file. Never attempt to send it again.
	removed := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.13"), Profile: carrier.ProfileTCP}
	a.historicalPaths = []carrier.SourcePath{first, removed, second}
	a.inventory = carrier.Inventory{Addresses: []netip.Addr{
		first.Source, second.Source, netip.MustParseAddr("198.18.0.99"),
	}}
	if err := a.cursor.ReplaceInventory(a.inventory); err != nil {
		t.Fatal(err)
	}
	a.beginRecovery()
	for pass := 0; pass < 3; pass++ {
		batch, err := a.nextCandidatePaths()
		if err != nil {
			t.Fatal(err)
		}
		if len(batch) != 2 || batch[0] != first || batch[1] != second {
			t.Fatalf("prior successful paths not preferred on warm pass %d: %v", pass, batch)
		}
	}
	seen := map[carrier.SourcePath]bool{}
	for len(seen) < len(a.inventory.Addresses)*len(carrier.AllProfiles()) {
		batch, err := a.nextCandidatePaths()
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range batch {
			if p == removed {
				t.Fatal("historical path missing from current operator file was retried")
			}
			if seen[p] {
				t.Fatalf("first exhaustive pass repeated %v", p)
			}
			seen[p] = true
		}
	}
	if a.stage != "EXHAUSTIVE_SOURCE_PROFILE_SCAN" || len(seen) != len(a.inventory.Addresses)*len(carrier.AllProfiles()) {
		t.Fatalf("warm retry starved complete matrix: stage=%s paths=%d", a.stage, len(seen))
	}
	// A second outage starts another bounded memory-first phase rather than
	// creating a new Link or losing every observed path.
	a.beginRecovery()
	batch, err := a.nextCandidatePaths()
	if err != nil || batch[0] != first {
		t.Fatalf("recurrent outage skipped memory-first: %v %v", batch, err)
	}
}

// The authenticated Source+Profile hint is only a candidate confirmation
// when both parts are in the CURRENT operator-approved local configuration.
func TestAuthenticatedFeedbackNeverSelectsMissingSourceOrDisabledProfile(t *testing.T) {
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	chosen := netip.MustParseAddr("198.18.0.33")
	a := newAgent(t.TempDir(), domain.Link{ID: id, Spoof: domain.SpoofOptions{OuterProtocol: "auto", TxProfile: "udp"}}, Material{}, nil)
	a.inventory = carrier.Inventory{Addresses: []netip.Addr{chosen}}
	if err := a.cursor.ReplaceInventory(a.inventory); err != nil {
		t.Fatal(err)
	}
	if a.applyAuthenticatedHint([]byte{198, 18, 0, 33, carrier.ProfileID(carrier.ProfileICMP)}) {
		t.Fatal("authenticated hint promoted outgoing protocol forbidden by local override")
	}
	if a.applyAuthenticatedHint([]byte{198, 18, 0, 99, carrier.ProfileID(carrier.ProfileUDP)}) {
		t.Fatal("authenticated hint promoted Source missing from current local file")
	}
	if a.applyAuthenticatedHint([]byte{198, 18, 0, 33, 255}) {
		t.Fatal("authenticated hint promoted unknown protocol ID")
	}
	if a.applyAuthenticatedHint([]byte{198, 18, 0, 33, carrier.ProfileID(carrier.ProfileUDP)}) != true {
		t.Fatal("valid authenticated outgoing Source/profile not selected")
	}
	if a.chosen != chosen || a.chosenProfile != carrier.ProfileUDP {
		t.Fatalf("selected unexpected outgoing path: %v/%s", a.chosen, a.chosenProfile)
	}
	if err := a.cursor.ReplaceInventory(carrier.Inventory{Addresses: []netip.Addr{netip.MustParseAddr("198.18.0.44")}}); err != nil {
		t.Fatal(err)
	}
	if a.applyAuthenticatedHint([]byte{198, 18, 0, 33, carrier.ProfileID(carrier.ProfileUDP)}) {
		t.Fatal("removed Source was reused after local list reload")
	}
}
