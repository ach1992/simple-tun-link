package quic

import (
	"bytes"
	"context"
	"errors"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestQUICExpectedMaterialsPreflightAndProtectedStagingBothRoles(t *testing.T) {
	for _, role := range []Role{Listen, Dial} {
		t.Run(string(role), func(t *testing.T) {
			plan, localWG := helperConfigPlan(domainTestLinkID(), role)
			root := privateStateRoot(t)
			listen, dial, err := GeneratePair(plan.LinkID, plan.TLSName)
			if err != nil {
				t.Fatal(err)
			}
			defer listen.Clear()
			defer dial.Clear()
			bundle := listen
			if role == Dial {
				bundle = dial
			}
			expected, err := previewHelperConfig(root, plan, localWG, fixtureHysteriaPath, bundle, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "credentials", "quic", string(plan.LinkID))
			if _, err := os.Lstat(dir); !os.IsNotExist(err) {
				t.Fatalf("prepublication preview unexpectedly created private files: %v", err)
			}
			got, err := stageExpectedMaterials(context.Background(), root, plan, localWG, fixtureHysteriaPath, bundle, expected, fixtureHysteriaAdmission)
			if err != nil || got != expected {
				t.Fatalf("journal-bound material publication differs: %v", err)
			}
			readback, err := inspectHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission)
			if err != nil || readback != expected {
				t.Fatalf("real protected file readback differs: %v", err)
			}
			repeat, err := stageExpectedMaterials(context.Background(), root, plan, localWG, fixtureHysteriaPath, bundle, expected, fixtureHysteriaAdmission)
			if err != nil || repeat != expected {
				t.Fatalf("exact same-generation retry is not idempotent: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 5 {
				t.Fatalf("wrong protected file inventory: %v, %v", entries, err)
			}
			for _, entry := range entries {
				info, err := os.Lstat(filepath.Join(dir, entry.Name()))
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Sys() == nil {
					t.Fatalf("not an owned 0600 private material file: %s (%v)", entry.Name(), err)
				}
			}
		})
	}
}

func TestQUICExpectedMaterialsRejectsEveryFingerprintAndTopologyBeforeFileWrites(t *testing.T) {
	plan, port := helperConfigPlan(domainTestLinkID(), Dial)
	listen, dial, err := GeneratePair(plan.LinkID, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	for _, tc := range []struct {
		name   string
		change func(*HelperConfigIdentity)
	}{
		{"certificate", func(x *HelperConfigIdentity) { x.Credentials.CertificateSHA256 = strings.Repeat("f", 64) }},
		{"trust-CA", func(x *HelperConfigIdentity) { x.Credentials.TrustCASHA256 = strings.Repeat("f", 64) }},
		{"authorization", func(x *HelperConfigIdentity) { x.Credentials.AuthorizationSHA256 = strings.Repeat("f", 64) }},
		{"helper-config", func(x *HelperConfigIdentity) { x.ConfigSHA256 = strings.Repeat("f", 64) }},
		{"executable-SHA", func(x *HelperConfigIdentity) { x.Executable.SHA256 = strings.Repeat("f", 64) }},
		{"executable-device", func(x *HelperConfigIdentity) { x.Executable.Device++ }},
		{"executable-inode", func(x *HelperConfigIdentity) { x.Executable.Inode++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := privateStateRoot(t)
			expected, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, dial, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			tc.change(&expected)
			_, err = stageExpectedMaterials(context.Background(), root, plan, port, fixtureHysteriaPath, dial, expected, fixtureHysteriaAdmission)
			if err == nil {
				t.Fatal("incorrect expected identity accepted")
			}
			dir := filepath.Join(root, "credentials", "quic", string(plan.LinkID))
			if _, e := os.Lstat(dir); !os.IsNotExist(e) {
				t.Fatalf("fingerprint mismatch wrote any private file: %v", e)
			}
		})
	}
	t.Run("underlay", func(t *testing.T) {
		root := privateStateRoot(t)
		expected, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, dial, fixtureHysteriaAdmission)
		if err != nil {
			t.Fatal(err)
		}
		other := plan
		other.Underlay = netip.MustParseAddrPort("198.51.100.77:443")
		if _, err := stageExpectedMaterials(context.Background(), root, other, port, fixtureHysteriaPath, dial, expected, fixtureHysteriaAdmission); err == nil {
			t.Fatal("underlay change passed immutable config identity")
		}
		if _, err := os.Lstat(filepath.Join(root, "credentials")); !os.IsNotExist(err) {
			t.Fatalf("drift wrote private files: %v", err)
		}
	})
	t.Run("root", func(t *testing.T) {
		root := privateStateRoot(t)
		expected, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, dial, fixtureHysteriaAdmission)
		if err != nil {
			t.Fatal(err)
		}
		alternate := privateStateRoot(t)
		if _, err := stageExpectedMaterials(context.Background(), alternate, plan, port, fixtureHysteriaPath, dial, expected, fixtureHysteriaAdmission); err == nil {
			t.Fatal("re-rooted helper config accepted")
		}
		if _, err := os.Lstat(filepath.Join(alternate, "credentials")); !os.IsNotExist(err) {
			t.Fatalf("alternate root written: %v", err)
		}
	})
}

func TestQUICExpectedMaterialsKeepsPartialNoReplaceConflictForReconciliation(t *testing.T) {
	plan, port := helperConfigPlan(domain.LinkID("lnk_88888888888888888888888888888888"), Listen)
	root := privateStateRoot(t)
	listen, dial, err := GeneratePair(plan.LinkID, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	expected, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, listen, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "credentials", "quic", string(plan.LinkID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("foreign helper config must remain unchanged\n")
	file := filepath.Join(dir, "helper.json")
	if err := os.WriteFile(file, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageExpectedMaterials(context.Background(), root, plan, port, fixtureHysteriaPath, listen, expected, fixtureHysteriaAdmission); err == nil {
		t.Fatal("foreign no-replace config was adopted")
	}
	got, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(got, foreign) {
		t.Fatalf("uncertain helper config was changed or erased: %v", err)
	}
	clear(got)
	cred, err := InspectCredentials(root, plan)
	if err != nil || cred != expected.Credentials {
		t.Fatalf("partial protected credential publication not preserved: %v", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	} // fixture owner explicitly reconciles the simulated foreign file
	if out, err := stageExpectedMaterials(context.Background(), root, plan, port, fixtureHysteriaPath, listen, expected, fixtureHysteriaAdmission); err != nil || out != expected {
		t.Fatalf("exact-owned fixture retry failed after independent reconciliation: %v", err)
	}
}

// A cancellation during pinned-binary preflight cannot publish credential
// files after the caller has abandoned the operation.
func TestQUICExpectedMaterialsCancellationAfterPreviewWritesNothing(t *testing.T) {
	plan, port := helperConfigPlan(domain.LinkID("lnk_77777777777777777777777777777777"), Listen)
	root := privateStateRoot(t)
	listen, dial, err := GeneratePair(plan.LinkID, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	expected, err := previewHelperConfig(root, plan, port, fixtureHysteriaPath, listen, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	verifier := func(path string) (pinnedexec.Identity, error) {
		identity, err := fixtureHysteriaAdmission(path)
		cancel()
		return identity, err
	}
	if _, err := stageExpectedMaterials(ctx, root, plan, port, fixtureHysteriaPath, listen, expected, verifier); !errors.Is(err, context.Canceled) {
		t.Fatalf("prewrite cancellation not respected: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "credentials")); !os.IsNotExist(err) {
		t.Fatalf("cancelled publication created private files: %v", err)
	}
}
