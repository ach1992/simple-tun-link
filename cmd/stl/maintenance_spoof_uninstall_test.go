package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Real field acceptance discovered that a canonical Spoof Remove leaves a
// retired, permanent ID reservation in State. This must not be interpreted
// as an unknown State schema during a read-only Uninstall preflight.
func TestSpoofRemovalMaintenanceAdmissionAndRPFilterRecovery(t *testing.T) {
	original := domain.Link{
		ID: "lnk_1234567890abcdef1234567890abcdef", Backend: domain.BackendSpoof,
		Encapsulation: domain.EncapUDP,
		Underlay:      domain.Underlay{Local: netip.MustParseAddr("10.246.52.1"), Peer: netip.MustParseAddr("10.246.52.2")},
		Addresses:     domain.LinkAddresses{Local: netip.MustParsePrefix("10.248.55.1/32"), Peer: netip.MustParsePrefix("10.248.55.2/32")},
		Spoof: domain.SpoofOptions{
			Role: "creator", SourceFile: "/root/stl/spoof/sources.txt", OuterProtocol: "udp",
			ListenPort: 48001, PeerPort: 48002, IngressInterface: "enp5s0",
			LocalPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
			MaterialSHA256: strings.Repeat("a", 64),
		},
	}
	if err := original.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		retired   bool
		claim     bool
		setting   bool
		wantReady bool
		reason    string
	}{
		{name: "retired original, no host policy", retired: true, wantReady: true},
		{name: "unretired original blocks uninstall", retired: false, reason: "protected credential retirement remains"},
		{name: "retired original with active rp_filter claim", retired: true, claim: true, setting: true, reason: "Spoof rp_filter host policy remains unreconciled"},
		{name: "retired original with orphan rp_filter journal", retired: true, setting: true, reason: "Spoof rp_filter host policy remains unreconciled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			store := state.NewFileStore(root)
			err := store.Update(context.Background(), func(s *state.Snapshot) error {
				s.SpoofRemovalReceipts = []state.SpoofRemovalReceipt{{Link: original, Retired: tc.retired}}
				if tc.setting {
					s.SpoofRPFilterSettings = []state.SpoofRPFilterSetting{{Interface: "enp5s0", Original: 1, Previous: 1, Desired: 2}}
				}
				if tc.claim {
					s.SpoofRPFilterClaims = []state.SpoofRPFilterClaim{{LinkID: original.ID, Interface: "enp5s0", Mode: "loose"}}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("canonical State write rejected: %v", err)
			}
			path := filepath.Join(root, "state.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := strictStateTopLevelFields(before); err != nil {
				t.Fatalf("valid Spoof State field rejected: %v", err)
			}
			got := inspectUninstallReady(context.Background(), root, fakeUninstallUnit{}, func(string) error { return nil })
			if (got == nil) != tc.wantReady {
				t.Fatalf("Uninstall ready=%t want=%t error=%v", got == nil, tc.wantReady, got)
			}
			if tc.reason != "" && !strings.Contains(got.Error(), tc.reason) {
				t.Fatalf("unhelpful refusal: %v", got)
			}
			if uninstallSnapshotEmpty(state.Snapshot{SpoofRemovalReceipts: []state.SpoofRemovalReceipt{{Link: original, Retired: true}}}) {
				t.Fatal("retained Spoof receipt incorrectly permits empty-only downgrade")
			}
			if err := inspectDowngradeReady(context.Background(), root, fakeUninstallUnit{}, func(string) error { return nil }); err == nil {
				t.Fatal("retained Spoof retirement/history allowed downgrade")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("read-only maintenance changed State")
			}
			if tc.wantReady {
				field := regexp.MustCompile(`"spoof_removal_receipts"\s*:`)
				retired := regexp.MustCompile(`"retired"\s*:\s*true`)
				schema := regexp.MustCompile(`"schema_version"\s*:`)
				for _, bad := range []string{
					field.ReplaceAllString(string(before), `"Spoof_Removal_Receipts":`),
					field.ReplaceAllString(string(before), `"spoof_removal_receipts":[],"spoof_removal_receipts":`),
					retired.ReplaceAllString(string(before), `"retired":false,"retired":true`),
					schema.ReplaceAllString(string(before), `"future_unverified":true,"schema_version":`),
				} {
					if bad == string(before) {
						t.Fatal("regression fixture had no target field")
					}
					if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
						t.Fatal(err)
					}
					if err := inspectUninstallReady(context.Background(), root, fakeUninstallUnit{}, func(string) error { return nil }); err == nil {
						t.Fatal("untrusted/ambiguous Spoof State granted destructive maintenance")
					}
					if err := os.WriteFile(path, before, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
	if uninstallSnapshotReady(state.Snapshot{SpoofRPFilterClaims: []state.SpoofRPFilterClaim{{}}}) ||
		uninstallSnapshotReady(state.Snapshot{SpoofRPFilterSettings: []state.SpoofRPFilterSetting{{}}}) ||
		uninstallSnapshotReady(state.Snapshot{SpoofRemovalReceipts: []state.SpoofRemovalReceipt{{Retired: false}}}) {
		t.Fatal("outstanding Spoof recovery obligations bypassed Uninstall admission")
	}
	if reason, _ := uninstallGateGuidance(context.DeadlineExceeded); reason != "uninstall_preflight_unverified" {
		t.Fatal(reason)
	}
	if reason, _ := uninstallGateGuidance(&testSpoofHostPolicyError{}); reason != "spoof_rp_filter_recovery_pending" {
		t.Fatal(reason)
	}
}

type testSpoofHostPolicyError struct{}

func (*testSpoofHostPolicyError) Error() string {
	return "Spoof rp_filter host policy remains unreconciled"
}
