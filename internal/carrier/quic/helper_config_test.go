package quic

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

const fixtureHysteriaPath = "/opt/stl/hysteria"

func fixtureHysteriaAdmission(path string) (linux.PinnedExecutableIdentity, error) {
	if path != fixtureHysteriaPath {
		return linux.PinnedExecutableIdentity{}, fmt.Errorf("untrusted test helper path")
	}
	// Test-only verification seam. The exported paths ALWAYS run the real
	// official pinned-executable verifier, never this stub.
	return linux.PinnedExecutableIdentity{
		SHA256: PinnedAMD64SHA256, Device: 42, Inode: 99,
	}, nil
}

func helperConfigPlan(id domain.LinkID, role Role) (Plan, uint16) {
	plan := materialPlan(id, role)
	if role == Listen {
		plan.LocalWGUDPPort = 51820
		return plan, 51820
	}
	plan.LocalForwardUDPPort = 52211
	plan.PeerWGUDPPort = 51820
	return plan, 51821
}

func issueAndStageQUICRole(t *testing.T, root string, p Plan) CredentialIdentity {
	t.Helper()
	listen, dial, err := GeneratePair(p.LinkID, p.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	bundle := listen
	if p.Role == Dial {
		bundle = dial
	}
	id, err := StageCredentials(root, p, bundle)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func helperConfigFile(root string, plan Plan) string {
	return filepath.Join(root, "credentials", "quic", string(plan.LinkID), "helper.json")
}

func TestQUICProtectedHelperConfigStagingAndStrictReadback(t *testing.T) {
	for _, role := range []Role{Listen, Dial} {
		t.Run(string(role), func(t *testing.T) {
			id := domainTestLinkID()
			plan, localWG := helperConfigPlan(id, role)
			root := privateStateRoot(t)
			creds := issueAndStageQUICRole(t, root, plan)
			got, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			if got.Credentials != creds || got.ConfigSHA256 == "" ||
				got.Executable.SHA256 != PinnedAMD64SHA256 || got.Executable.Inode != 99 {
				t.Fatal("staged helper config did not bind credential, config and helper identities")
			}
			again, err := inspectHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission)
			if err != nil || got != again {
				t.Fatalf("protected helper config readback differs: %v", err)
			}
			if stable, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err != nil || stable != got {
				t.Fatalf("identical helper config staging was not idempotent: %v", err)
			}
			path := helperConfigFile(root, plan)
			st, err := os.Lstat(path)
			if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
				t.Fatalf("helper configuration file is not owner-private: %v %v", st, err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(raw)
			if !bytes.Contains(raw, []byte("\"tls\"")) || !bytes.Contains(raw, []byte("\"auth\"")) {
				t.Fatal("helper config does not contain scoped Hysteria TLS and authorization")
			}
			bearer, err := os.ReadFile(filepath.Join(filepath.Dir(path), "authorization-token"))
			if err != nil {
				t.Fatal(err)
			}
			defer clear(bearer)
			token := bytes.TrimSpace(bearer)
			if !bytes.Contains(raw, token) {
				t.Fatal("config did not use its actual protected authorization token")
			}
			formatted := []byte(fmt.Sprintf("%+v / %#v", got, again))
			if bytes.Contains(formatted, token) || bytes.Contains(formatted, []byte("PRIVATE KEY")) {
				t.Fatal("public helper identity exposed protected content")
			}
		})
	}
}

func TestQUICProtectedHelperConfigRejectsDriftAndUnsafeFilesystem(t *testing.T) {
	plan, localWG := helperConfigPlan(domainTestLinkID(), Listen)
	root := privateStateRoot(t)
	issueAndStageQUICRole(t, root, plan)
	if _, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err != nil {
		t.Fatal(err)
	}
	path := helperConfigFile(root, plan)
	checkRejected := func() {
		t.Helper()
		if _, err := inspectHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
			t.Fatal("untrusted helper config passed inspection")
		}
		if _, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
			t.Fatal("untrusted helper config passed no-replace staging")
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	checkRejected()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "linked-helper")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	checkRejected()
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(path), "server-cert.pem"), path); err != nil {
		t.Fatal(err)
	}
	checkRejected()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("{\"server\":\"foreign\"}\n")
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	checkRejected()
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, corrupt) {
		t.Fatalf("failed stage overwrote or deleted uncertain helper config: %v", err)
	}
	clear(actual)
}

func TestQUICHelperConfigCannotBypassProtectedCredentialAndTopologyAdmission(t *testing.T) {
	plan, localWG := helperConfigPlan(domainTestLinkID(), Dial)
	root := privateStateRoot(t)
	if _, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
		t.Fatal("helper configuration staged without protected credentials")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("failed admission unexpectedly created State root: %v", err)
	}
	issueAndStageQUICRole(t, root, plan)
	for _, tc := range []struct {
		name string
		edit func(*Plan, *uint16)
	}{
		{"unknown Link", func(p *Plan, _ *uint16) { p.LinkID = "lnk_22222222222222222222222222222222" }},
		{"other role", func(p *Plan, _ *uint16) {
			p.Role = Listen
			p.LocalForwardUDPPort = 0
			p.PeerWGUDPPort = 0
			p.LocalWGUDPPort = 51821
		}},
		{"mismatched forwarder", func(p *Plan, _ *uint16) { p.LocalForwardUDPPort = 0 }},
		{"conflicting local WG port", func(p *Plan, wg *uint16) { *wg = p.LocalForwardUDPPort }},
		{"invalid TLS name syntax", func(p *Plan, _ *uint16) { p.TLSName = "https://different-quic.invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered, wg := plan, localWG
			tc.edit(&altered, &wg)
			if _, err := stageHelperConfig(root, altered, wg, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
				t.Fatal("unsafe role/topology/certificate scope admitted")
			}
		})
	}
	if _, err := os.Lstat(helperConfigFile(root, plan)); !os.IsNotExist(err) {
		t.Fatalf("invalid helper admission created a file: %v", err)
	}

	// An existing, independently verified credential file that changes its
	// Link authorization material can never be silently reconciled.
	name := filepath.Join(filepath.Dir(helperConfigFile(root, plan)), "authorization-token")
	if err := os.Chmod(name, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
		t.Fatal("invalid protected credential mode admitted")
	}
	if _, err := os.Lstat(helperConfigFile(root, plan)); !os.IsNotExist(err) {
		t.Fatal("unsafe credentials caused helper JSON publication")
	}
}

func TestQUICHelperConfigPinsRealExecutableOnPublicAdmission(t *testing.T) {
	plan, localWG := helperConfigPlan(domainTestLinkID(), Listen)
	root := privateStateRoot(t)
	issueAndStageQUICRole(t, root, plan)
	if _, err := StageHelperConfig(root, plan, localWG, "/nonexistent/approved-hysteria"); err == nil {
		t.Fatal("official executable admission was bypassed")
	}
	if _, err := InspectHelperConfig(root, plan, localWG, "/nonexistent/approved-hysteria"); err == nil {
		t.Fatal("read-only inspection trusted a missing official helper")
	}
	if _, err := os.Lstat(helperConfigFile(root, plan)); !os.IsNotExist(err) {
		t.Fatal("untrusted executable caused helper JSON publication")
	}
}

func TestQUICHelperConfigRetainsUncertainArtifactIfHelperChangesDuringReadback(t *testing.T) {
	plan, localWG := helperConfigPlan(domainTestLinkID(), Listen)
	root := privateStateRoot(t)
	issueAndStageQUICRole(t, root, plan)
	var count int
	alternatingVerifier := func(path string) (linux.PinnedExecutableIdentity, error) {
		id, err := fixtureHysteriaAdmission(path)
		count++
		if count == 2 {
			id.Inode++
		}
		return id, err
	}
	if _, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, alternatingVerifier); err == nil {
		t.Fatal("helper executable changed during protected readback")
	}
	if count != 2 {
		t.Fatalf("expected both executable admissions to occur, got %d", count)
	}
	if _, err := inspectHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err != nil {
		t.Fatalf("uncertain file should be inspectable by authorized owner: %v", err)
	}
	if _, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err != nil {
		t.Fatalf("owned idempotent retry could not reconcile identical on-disk config: %v", err)
	}
}

func TestQUICHelperConfigStagesIndependentLinksConcurrently(t *testing.T) {
	root := privateStateRoot(t)
	var plans [2]Plan
	var identities [2]HelperConfigIdentity
	for i, id := range []domain.LinkID{
		"lnk_11111111111111111111111111111111",
		"lnk_22222222222222222222222222222222",
	} {
		p, _ := helperConfigPlan(id, Dial)
		p.LocalForwardUDPPort += uint16(i)
		plans[i] = p
		issueAndStageQUICRole(t, root, p)
	}
	type result struct {
		index int
		id    HelperConfigIdentity
		err   error
	}
	start := make(chan struct{})
	out := make(chan result, len(plans))
	var wg sync.WaitGroup
	for i := range plans {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			p := plans[i]
			id, err := stageHelperConfig(root, p, 51821+uint16(i), fixtureHysteriaPath, fixtureHysteriaAdmission)
			out <- result{i, id, err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(out)
	var seen [2]bool
	for x := range out {
		if x.err != nil || seen[x.index] {
			t.Fatalf("independent Link helper staging failed: %+v", x)
		}
		seen[x.index] = true
		identities[x.index] = x.id
	}
	if !seen[0] || !seen[1] ||
		identities[0].ConfigSHA256 == identities[1].ConfigSHA256 ||
		identities[0].Credentials.AuthorizationSHA256 == identities[1].Credentials.AuthorizationSHA256 {
		t.Fatal("concurrent Link helper identities were not isolated")
	}
	for i, p := range plans {
		got, err := inspectHelperConfig(root, p, 51821+uint16(i), fixtureHysteriaPath, fixtureHysteriaAdmission)
		if err != nil || !reflect.DeepEqual(got, identities[i]) {
			t.Fatalf("independent Link %d readback failed: %v", i, err)
		}
	}
}

func TestQUICHelperConfigRejectsRoleAndTLSPlanDriftAfterPublication(t *testing.T) {
	for _, role := range []Role{Listen, Dial} {
		t.Run(string(role), func(t *testing.T) {
			plan, localWG := helperConfigPlan(domainTestLinkID(), role)
			root := privateStateRoot(t)
			issueAndStageQUICRole(t, root, plan)
			original, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission)
			if err != nil {
				t.Fatal(err)
			}
			file := helperConfigFile(root, plan)
			originalBytes, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(originalBytes)

			// Listen must reject the changed SAN against its real server
			// leaf; Dial's client leaf intentionally contains no server
			// SAN, so the already protected helper config's exact bytes
			// must instead reject a changed authenticated peer name.
			changed := plan
			changed.TLSName = "different-quic.invalid"
			if _, err := inspectHelperConfig(root, changed, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
				t.Fatal("changed authenticated peer identity passed protected inspection")
			}
			if _, err := stageHelperConfig(root, changed, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
				t.Fatal("changed authenticated peer identity replaced protected helper config")
			}
			readback, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(readback, originalBytes) {
				t.Fatalf("changed peer identity altered original file: %v", err)
			}
			clear(readback)
			if actual, err := inspectHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err != nil || actual != original {
				t.Fatalf("original protected helper identity was lost: %v", err)
			}
		})
	}
}

func TestQUICHelperConfigRejectsForeignRoleCAWithoutTouchingExistingFile(t *testing.T) {
	plan, localWG := helperConfigPlan(domainTestLinkID(), Listen)
	root := privateStateRoot(t)
	issueAndStageQUICRole(t, root, plan)
	original, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission)
	if err != nil {
		t.Fatal(err)
	}
	path := helperConfigFile(root, plan)
	originalBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(originalBytes)

	foreign := filepath.Join(filepath.Dir(path), "server-ca.pem")
	if err := os.WriteFile(foreign, []byte("orphan-foreign-role-CA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
		t.Fatal("foreign role CA passed protected helper inspection")
	}
	if _, err := stageHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err == nil {
		t.Fatal("foreign role CA passed protected helper staging")
	}
	readback, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(readback, originalBytes) {
		t.Fatalf("foreign-role refusal altered original helper config: %v", err)
	}
	clear(readback)
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if id, err := inspectHelperConfig(root, plan, localWG, fixtureHysteriaPath, fixtureHysteriaAdmission); err != nil || id != original {
		t.Fatalf("original helper lost after explicit test-owner reconciliation: %v", err)
	}
}

// This test is OPT-IN because normal CI must remain hermetic and has no
// Hysteria executable. A pinned *actual official* binary in the local Dev
// fixture provides integration evidence; no helper is spawned by this test.
func TestPinnedHysteriaProtectedHelperConfigWhenAvailable(t *testing.T) {
	binary := os.Getenv("STL_QUIC_HYSTERIA_BIN")
	if binary == "" {
		t.Skip("no explicitly provided official pinned Hysteria helper")
	}
	plan, localWG := helperConfigPlan(domainTestLinkID(), Listen)
	root := privateStateRoot(t)
	issueAndStageQUICRole(t, root, plan)
	identity, err := StageHelperConfig(root, plan, localWG, binary)
	if err != nil {
		t.Fatal(err)
	}
	readback, err := InspectHelperConfig(root, plan, localWG, binary)
	if err != nil || readback != identity {
		t.Fatalf("real verified pinned helper config readback failed: %v", err)
	}
}
