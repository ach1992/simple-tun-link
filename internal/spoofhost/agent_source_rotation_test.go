//go:build linux

package spoofhost

import (
	"github.com/ach1992/simple-tun-link/internal/domain"
	"net/netip"
	"strings"
	"testing"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

func TestSourceFileRotationPreservesNoiseSessionAndBackupPriority(t *testing.T) {
	current := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.99"), Profile: carrier.ProfileUDP}
	remaining := carrier.SourcePath{Source: netip.MustParseAddr("198.18.0.11"), Profile: carrier.ProfileICMP}
	a := newAgent(t.TempDir(), domain.Link{Spoof: domain.SpoofOptions{OuterProtocol: "auto"}}, Material{}, nil)
	a.inventory = carrier.Inventory{Addresses: []netip.Addr{remaining.Source}}
	if err := a.cursor.ReplaceInventory(a.inventory); err != nil {
		t.Fatal(err)
	}
	a.historicalPaths = []carrier.SourcePath{current, remaining}
	a.chosen = current.Source
	a.chosenProfile = current.Profile
	a.connected = true
	original := &carrier.Session{}
	a.session = original
	a.invalidateSelectedSource()
	if a.session != original || a.connected || a.chosen.IsValid() {
		t.Fatal("local Source inventory edit incorrectly discarded authenticated identity or retained dead route")
	}
	if a.stage != "RETRY_PREVIOUSLY_WORKING" || len(a.warmPaths) != 1 || a.warmPaths[0] != remaining {
		t.Fatalf("new Source recovery did not favor surviving verified path: %s %+v", a.stage, a.warmPaths)
	}
	if !strings.Contains(a.status.LastError, "Source disappeared") {
		t.Fatal("source replacement diagnostics absent")
	}
}
