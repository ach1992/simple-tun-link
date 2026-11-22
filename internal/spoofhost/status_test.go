package spoofhost

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	spoofbackend "github.com/ach1992/simple-tun-link/internal/backend/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestTrustedRuntimeStatusNeedsSameLiveHelperAndFreshAttestedReport(t *testing.T) {
	root := t.TempDir()
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "spoof", string(id))
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path, err := StatusPath(root, id)
	if err != nil {
		t.Fatal(err)
	}
	report := RuntimeStatus{SchemaVersion: 1, LinkID: id, PID: 1001,
		State: "CONNECTED", Authenticated: true, BilateralConfirmed: true,
		UpdatedAt: time.Now().UTC()}
	write := func() {
		t.Helper()
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	host := spoofbackend.HostObservation{UnitOwned: true, UnitActive: true, RuntimeReady: true, HelperPID: 1001}
	if got := TrustedRuntimeStatus(root, id, host); got.State != "CONNECTED" {
		t.Fatalf("matching original report rejected: %+v", got)
	}
	for _, tc := range []struct {
		name   string
		mutate func()
	}{
		{"wrong PID", func() { host.HelperPID = 1002 }},
		{"stopped service", func() { host.HelperPID = 1001; host.RuntimeReady = false }},
		{"future timestamp", func() { host.RuntimeReady = true; report.UpdatedAt = time.Now().Add(20 * time.Second); write() }},
		{"stale timestamp", func() { report.UpdatedAt = time.Now().Add(-20 * time.Second); write() }},
		{"fake bilateral claim", func() { report.UpdatedAt = time.Now(); report.BilateralConfirmed = false; write() }},
	} {
		tc.mutate()
		t.Run(tc.name, func(t *testing.T) {
			if got := TrustedRuntimeStatus(root, id, host); got.State != "STOPPED_OR_UNVERIFIED" {
				t.Fatalf("false authenticated status: %+v", got)
			}
		})
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if got := TrustedRuntimeStatus(root, id, host); got.State != "STOPPED_OR_UNVERIFIED" {
		t.Fatalf("followed untrusted status symlink: %+v", got)
	}
}
