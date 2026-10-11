package diagnostics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrongSwanServiceFilesReadOnlyFailClosed(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "foreign.service")
	if err := os.WriteFile(regular, []byte("PSK=DO_NOT_PRINT"), 0600); err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Lstat(regular)
	if err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(t.TempDir(), "foreign-symlink.service")
	if err := os.Symlink("/nonexistent/foreign-unit", dangling); err != nil {
		t.Fatal(err)
	}
	symlinkInfo, err := os.Lstat(dangling)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		foundAt     string
		foundInfo   os.FileInfo
		uncertainAt string
		wantStatus  string
		wantReason  string
	}{
		{
			name:       "all known identities absent",
			wantStatus: "observed", wantReason: "strongswan_service_not_observed",
		},
		{
			name:    "Ubuntu charon systemd package installed",
			foundAt: "/usr/lib/systemd/system/strongswan.service", foundInfo: fileInfo,
			wantStatus: "blocked", wantReason: "strongswan_service_observed",
		},
		{
			name:    "admin override is a dangling symlink",
			foundAt: "/etc/systemd/system/charon-systemd.service", foundInfo: symlinkInfo,
			wantStatus: "blocked", wantReason: "strongswan_service_observed",
		},
		{
			name:    "legacy SysV service script",
			foundAt: "/etc/init.d/ipsec", foundInfo: fileInfo,
			wantStatus: "blocked", wantReason: "strongswan_service_observed",
		},
		{
			name:        "inspection denied",
			uncertainAt: "/etc/systemd/system/strongswan.service",
			wantStatus:  "unknown", wantReason: "strongswan_service_inventory_unverified",
		},
		{
			name:        "foreign service outweighs earlier permission error",
			uncertainAt: "/etc/systemd/system/strongswan.service",
			foundAt:     "/usr/lib/systemd/system/strongswan.service", foundInfo: fileInfo,
			wantStatus: "blocked", wantReason: "strongswan_service_observed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			observe := func(path string) (os.FileInfo, error) {
				count++
				if path == tc.foundAt {
					return tc.foundInfo, nil
				}
				if path == tc.uncertainAt {
					return nil, errors.New("PSK=DO_NOT_PRINT")
				}
				return nil, os.ErrNotExist
			}
			check := inspectStrongSwanServiceFiles(context.Background(), observe)
			if check.Name != "strongswan_service" || check.Status != tc.wantStatus ||
				check.ReasonCode != tc.wantReason || check.Summary == "" || check.NextStep == "" ||
				count == 0 {
				t.Fatalf("service inventory did not fail closed: %+v", check)
			}
			if strings.Contains(check.Summary, "DO_NOT_PRINT") || strings.Contains(check.NextStep, "DO_NOT_PRINT") ||
				strings.Contains(check.Summary, regular) || strings.Contains(check.Summary, dangling) {
				t.Fatalf("service inventory leaked untrusted data: %+v", check)
			}
			if tc.foundAt == "" && tc.uncertainAt == "" && !strings.Contains(check.Summary, "not proof") {
				t.Fatalf("false exclusive-ownership claim: %+v", check)
			}
		})
	}
}

func TestStrongSwanServiceInventoryRequiresCompleteObservation(t *testing.T) {
	if check := inspectStrongSwanServiceFiles(nil, os.Lstat); check.Status != "unknown" {
		t.Fatalf("nil context accepted: %+v", check)
	}
	if check := inspectStrongSwanServiceFiles(context.Background(), nil); check.Status != "unknown" {
		t.Fatalf("nil reader accepted: %+v", check)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	check := inspectStrongSwanServiceFiles(ctx, func(string) (os.FileInfo, error) {
		calls++
		return nil, nil
	})
	if check.Status != "unknown" || calls != 0 {
		t.Fatalf("canceled inspection did not fail closed: %+v, calls=%d", check, calls)
	}
	check = inspectStrongSwanServiceFiles(context.Background(), func(string) (os.FileInfo, error) {
		return nil, nil // A malformed successful observation is NOT absence.
	})
	if check.Status != "unknown" {
		t.Fatalf("malformed successful stat treated as vacancy: %+v", check)
	}
}
