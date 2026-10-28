package quic

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestQUICForeignRoleCAFailsStagingAndInspectionWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		role        Role
		foreignName string
	}{
		{Listen, "server-ca.pem"},
		{Dial, "client-ca.pem"},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			id := domainTestLinkID()
			server, client, err := GeneratePair(id, "quic-probe.invalid")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Clear()
			defer client.Clear()
			bundle := server
			if tc.role == Dial {
				bundle = client
			}
			plan := materialPlan(id, tc.role)
			root := privateStateRoot(t)
			before, err := StageCredentials(root, plan, bundle)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "credentials", "quic", string(id))
			names, err := roleFiles(tc.role)
			if err != nil {
				t.Fatal(err)
			}
			originals := make(map[string][]byte, len(names))
			defer clearRoleFiles(originals)
			for _, name := range names {
				originals[name], err = os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
			}

			// A future helper.json may coexist with credentials. It must not
			// turn a role-exclusive check into an indiscriminate directory ban.
			helper := filepath.Join(dir, "helper.json")
			if err := os.WriteFile(helper, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := InspectCredentials(root, plan); err != nil || got != before {
				t.Fatalf("legitimate helper.json rejected: %v", err)
			}

			foreign := filepath.Join(dir, tc.foreignName)
			foreignBytes := []byte("test-only orphaned foreign CA\n")
			if err := os.WriteFile(foreign, foreignBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectCredentials(root, plan); err == nil {
				t.Fatal("foreign-role CA passed read-only credential inspection")
			}
			if _, err := StageCredentials(root, plan, bundle); err == nil {
				t.Fatal("foreign-role CA passed credential staging")
			}
			for _, name := range names {
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.Equal(raw, originals[name]) {
					t.Fatalf("failed admission changed existing credential %q: %v", name, err)
				}
				clear(raw)
			}
			extra, err := os.ReadFile(foreign)
			if err != nil || !bytes.Equal(extra, foreignBytes) {
				t.Fatalf("foreign artifact was removed or rewritten: %v", err)
			}
			clear(extra)

			// Explicit test-owner reconciliation restores the original
			// valid State. The API itself must not delete foreign material.
			if err := os.Remove(foreign); err != nil {
				t.Fatal(err)
			}
			if got, err := StageCredentials(root, plan, bundle); err != nil || got != before {
				t.Fatalf("original credentials did not survive rejected foreign CA: %v", err)
			}
		})
	}
}

func TestQUICStagingPreservesEarlierFilesAfterLateStageConflict(t *testing.T) {
	id := domainTestLinkID()
	listen := materialPlan(id, Listen)
	server, _, err := GeneratePair(id, listen.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	files := server.ProtectedFiles()
	defer clearRoleFiles(files)
	root := privateStateRoot(t)
	dir := filepath.Join(root, "credentials", "quic", string(id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	names, _ := roleFiles(Listen)
	last := filepath.Join(dir, names[3])
	existing := []byte("test-only conflicting preexisting bearer\n")
	if err := os.WriteFile(last, existing, 0o600); err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		if _, err := StageCredentials(root, listen, server); err == nil {
			t.Fatal("late-stage conflicting file unexpectedly accepted")
		}
		for _, name := range names[:3] {
			actual, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || !bytes.Equal(actual, files[name]) {
				t.Fatalf("earlier staged file lost or overwritten %q: %v", name, err)
			}
			clear(actual)
		}
		token, err := os.ReadFile(last)
		if err != nil || !bytes.Equal(token, existing) {
			t.Fatalf("late conflicting file lost or overwritten: %v", err)
		}
		clear(token)
		if _, err := InspectCredentials(root, listen); err == nil {
			t.Fatal("incomplete/conflicting credential generation passed inspection")
		}
	}
	// Leave the partial files intact until explicit owner reconciliation;
	// neither staging retry has silently rolled them back.
}

func TestQUICStagingSeparateLinksConcurrently(t *testing.T) {
	root := privateStateRoot(t)
	var plans [2]Plan
	var bundles [2]CredentialBundle
	for i, id := range []domain.LinkID{
		"lnk_11111111111111111111111111111111",
		"lnk_22222222222222222222222222222222",
	} {
		plans[i] = materialPlan(id, Listen)
		bundle, _, err := GeneratePair(id, plans[i].TLSName)
		if err != nil {
			t.Fatal(err)
		}
		bundles[i] = bundle
	}
	defer bundles[0].Clear()
	defer bundles[1].Clear()
	type outcome struct {
		n        int
		identity CredentialIdentity
		err      error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range plans {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			id, err := StageCredentials(root, plans[i], bundles[i])
			results <- outcome{n: i, identity: id, err: err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	var identities [2]CredentialIdentity
	var seen [2]bool
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if seen[result.n] {
			t.Fatal("duplicate result for concurrent Link")
		}
		seen[result.n] = true
		identities[result.n] = result.identity
	}
	if !seen[0] || !seen[1] ||
		identities[0].AuthorizationSHA256 == identities[1].AuthorizationSHA256 {
		t.Fatal("concurrent Links failed independent credential admission")
	}
	for i := range plans {
		got, err := InspectCredentials(root, plans[i])
		if err != nil || got != identities[i] {
			t.Fatalf("concurrent Link %d readback mismatch: %v", i, err)
		}
	}
}
