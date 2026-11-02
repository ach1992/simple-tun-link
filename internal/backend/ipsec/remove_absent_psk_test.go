package ipsec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestIPsecProtectedCredentialAbsenceIsExactAndFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(t *testing.T, root string)
	}{
		{"valid-absent", func(t *testing.T, root string) {}},
		{"symlink", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Symlink("/etc/passwd", filepath.Join(root, "credentials", string(testPSKLink1)+".ipsecpsk")); err != nil {
				t.Fatal(err)
			}
		}},
		{"foreign-regular", func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, "credentials", string(testPSKLink1)+".ipsecpsk"), []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"credential-dir-missing", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Remove(filepath.Join(root, "credentials")); err != nil {
				t.Fatal(err)
			}
		}},
		{"unsafe-dir", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Chmod(filepath.Join(root, "credentials"), 0o777); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, root := makePSKStore(t)
			if err := store.PutNew(testPSKLink2, []byte("0123456789abcdef0123456789abcdef")); err != nil {
				t.Fatal(err)
			}
			// Keep another unrelated key intact except in the deliberately missing
			// credential directory case; there are no deletes in VerifyAbsent.
			if tc.name == "credential-dir-missing" {
				if err := os.Remove(filepath.Join(root, "credentials", string(testPSKLink2)+".ipsecpsk")); err != nil {
					t.Fatal(err)
				}
			}
			tc.alter(t, root)
			err := store.VerifyAbsent(testPSKLink1)
			if (err == nil) != (tc.name == "valid-absent") {
				t.Fatalf("VerifyAbsent mishandled %s: %v", tc.name, err)
			}
			if tc.name != "credential-dir-missing" && tc.name != "unsafe-dir" {
				if _, err := store.Load(testPSKLink2); err != nil {
					t.Fatal("verify-absent changed sibling key", err)
				}
			}
		})
	}
}

// This is a *Plan* acceptance matrix; the canonical Engine and backend
// revalidate everything under real maintenance/Link/resource locks.
func TestIPsecRemoveMissingPSKRequiresAllHostResourcesVerifiedAbsent(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		t.Run(string(encap), func(t *testing.T) {
			link := testIPsecLink(t, encap)
			profile, err := NewProfile(link)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			keys, err := NewPSKStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.PutNew(link.ID, []byte("0123456789abcdef0123456789abcdef")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, "credentials", string(link.ID)+".ipsecpsk")); err != nil {
				t.Fatal(err)
			}
			xfrm := goodXFRMFixture()
			offline := &unreachableIPsecUnderlay{}
			b := &OperationalBackend{OperationalOptions: OperationalOptions{Keys: keys, Routes: offline, XFRM: XFRMVacancyInspector{Runner: xfrm.Run}}}
			req := core.Request{Operation: core.OperationRemove, Link: link, Prior: &link, OwnedResources: profile.ResourceClaims()}
			vacant := operationalObservation{Profile: profile}
			plan, err := b.Plan(context.Background(), req, vacant)
			if err != nil || !plan.(operationalPlan).CredentialAbsent || !plan.(operationalPlan).Remove {
				t.Fatalf("vacant owned missing-PSK removal denied: %v %+v", err, plan)
			}
			if offline.calls != 0 {
				t.Fatal("removal contacted remote route")
			}
			ownerTag, _ := domain.OwnerTag(link.ID)
			ownedDevice := xfrmLink{Exists: true, Index: 17, ID: profile.InterfaceID, Alias: ownerTag, Up: true, HasAddress: true}
			for _, tc := range []struct {
				name string
				obs  operationalObservation
			}{
				{"live-interface", operationalObservation{Profile: profile, Iface: ownedDevice}},
				{"live-VICI", operationalObservation{Profile: profile, Connection: true, Shared: true}},
				{"partial-VICI", operationalObservation{Profile: profile, Shared: true}},
				{"unowned-device", operationalObservation{Profile: profile, Iface: xfrmLink{Exists: true, Index: 19, ID: profile.InterfaceID, Alias: "foreign", Up: true, HasAddress: true}}},
				{"missing-committed-claims", vacant},
			} {
				t.Run(tc.name, func(t *testing.T) {
					testReq := req
					if tc.name == "missing-committed-claims" {
						testReq.OwnedResources = nil
					}
					if plan, err := b.Plan(context.Background(), testReq, tc.obs); err == nil {
						t.Fatalf("accepted missing-PSK unowned/live/unknown state: %+v", plan)
					}
				})
			}
			// A matching XFRM SA or policy is not a vacant host, even when the
			// interface and daemon configuration both appear absent.
			xfrm.rows["ip -json xfrm policy"] = []byte(fmt.Sprintf(`[{"if_id":%d}]`, profile.InterfaceID))
			// An exact matching XFRM policy must fail closed without an interface.
			if _, err := b.Plan(context.Background(), req, vacant); err == nil {
				t.Fatal("ambiguous XFRM inventory admitted")
			}
			// A malicious credential path is NOT a missing credential.
			xfrm.rows["ip -json xfrm policy"] = []byte("[]")
			keyPath := filepath.Join(root, "credentials", string(link.ID)+".ipsecpsk")
			if err := os.Symlink("/etc/passwd", keyPath); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Plan(context.Background(), req, vacant); err == nil {
				t.Fatal("foreign credential symlink allowed credential-free IPsec removal")
			}
			if _, err := os.Lstat(keyPath); err != nil {
				t.Fatal("rejected plan altered foreign symlink", err)
			}
			if offline.calls != 0 {
				t.Fatal("negative tests contacted remote route")
			}
		})
	}
}
