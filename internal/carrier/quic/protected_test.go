package quic

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func materialPlan(id domain.LinkID, role Role) Plan {
	p := fixturePlan(role)
	p.LinkID = id
	return p
}

func privateStateRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state")
}

func TestQUICProtectedRoleFilesAndReadbackAreIndependent(t *testing.T) {
	id := domainTestLinkID()
	server, client, err := GeneratePair(id, "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	defer client.Clear()
	serverRoot := privateStateRoot(t)
	clientRoot := privateStateRoot(t)
	listen := materialPlan(id, Listen)
	dial := materialPlan(id, Dial)
	serverID, err := StageCredentials(serverRoot, listen, server)
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := StageCredentials(clientRoot, dial, client)
	if err != nil {
		t.Fatal(err)
	}
	if serverID.AuthorizationSHA256 != clientID.AuthorizationSHA256 ||
		serverID.CertificateSHA256 == clientID.CertificateSHA256 ||
		serverID.TrustCASHA256 == clientID.TrustCASHA256 {
		t.Fatal("each role must have independent leaf/CA while sharing exact bearer")
	}
	for _, tc := range []struct {
		root string
		plan Plan
		b    CredentialBundle
		id   CredentialIdentity
	}{
		{serverRoot, listen, server, serverID},
		{clientRoot, dial, client, clientID},
	} {
		got, err := InspectCredentials(tc.root, tc.plan)
		if err != nil || got != tc.id {
			t.Fatalf("protected identity readback mismatch: %+v, %v", got, err)
		}
		got, err = StageCredentials(tc.root, tc.plan, tc.b)
		if err != nil || got != tc.id {
			t.Fatalf("same-bundle idempotent staging changed identity: %+v, %v", got, err)
		}
		parent := filepath.Join(tc.root, "credentials", "quic", string(id))
		info, err := os.Stat(parent)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("Link directory not private: %v, %v", info, err)
		}
		names, _ := roleFiles(tc.plan.Role)
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != len(names) {
			t.Fatalf("unexpected role-private files: %v, %v", entries, err)
		}
		for _, name := range names {
			info, err := os.Lstat(filepath.Join(parent, name))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("private file permissions: %s %v %v", name, info, err)
			}
		}
	}
	// Reissued identities MUST NOT replace a committed Link, even when all
	// roles and TLS names match. Readback still proves the original identity.
	changedServer, _, err := GeneratePair(id, "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer changedServer.Clear()
	if _, err := StageCredentials(serverRoot, listen, changedServer); err == nil {
		t.Fatal("reissued credential silently overwrote existing Link")
	}
	if got, err := InspectCredentials(serverRoot, listen); err != nil || got != serverID {
		t.Fatalf("failed replacement changed original identity: %+v, %v", got, err)
	}
}

func TestQUICCredentialTamperingAndForeignRoleFailClosed(t *testing.T) {
	id := domainTestLinkID()
	listen := materialPlan(id, Listen)
	server, client, err := GeneratePair(id, listen.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	defer client.Clear()
	root := privateStateRoot(t)
	if _, err := StageCredentials(root, listen, server); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "credentials", "quic", string(id))
	path := filepath.Join(parent, "server-key.pem")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCredentials(root, listen); err == nil {
		t.Fatal("publicly readable secret admitted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "hardlink")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCredentials(root, listen); err == nil {
		t.Fatal("hardlinked private secret admitted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(parent, "server-cert.pem"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCredentials(root, listen); err == nil {
		t.Fatal("symlinked credential admitted")
	}
	if _, err := StageCredentials(root, listen, server); err == nil {
		t.Fatal("symlinked credential overwritten")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := StageCredentials(root, listen, server); err != nil {
		t.Fatal(err)
	}
	if _, err := StageCredentials(root, materialPlan(id, Dial), client); err == nil {
		t.Fatal("client and server identities mixed in one Link directory")
	}
}

func TestQUICStagingRejectsInvalidInputsBeforeWriting(t *testing.T) {
	id := domainTestLinkID()
	plan := materialPlan(id, Listen)
	server, _, err := GeneratePair(id, plan.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	for _, tc := range []struct {
		name string
		edit func(map[string][]byte)
	}{
		{"missing-token", func(m map[string][]byte) { delete(m, "authorization-token") }},
		{"wrong-token", func(m map[string][]byte) { m["authorization-token"] = []byte("short\n") }},
		{"broken-ca", func(m map[string][]byte) { m["client-ca.pem"] = []byte("not CA") }},
		{"broken-leaf", func(m map[string][]byte) { m["server-cert.pem"] = []byte("invalid") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := server.ProtectedFiles()
			defer clearProtectedCopies(files)
			tc.edit(files)
			root := privateStateRoot(t)
			if _, err := StageCredentials(root, plan, CredentialBundle{files: files}); err == nil {
				t.Fatal("unsafe credentials admitted")
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("invalid credentials unexpectedly touched State root: %v", err)
			}
		})
	}
	for _, altered := range []Plan{
		func() Plan { p := plan; p.LinkID = "bad"; return p }(),
		func() Plan { p := plan; p.Role = "both"; return p }(),
		func() Plan { p := plan; p.TLSName = "other.invalid"; return p }(),
		func() Plan { p := plan; p.Underlay = netip.AddrPort{}; return p }(),
	} {
		root := privateStateRoot(t)
		if _, err := StageCredentials(root, altered, server); err == nil {
			t.Fatal("invalid credential scope admitted")
		}
	}
}

func TestQUICStagingSeparatesTwoLinksInOneStateRoot(t *testing.T) {
	root := privateStateRoot(t)
	idA := domain.LinkID("lnk_11111111111111111111111111111111")
	idB := domain.LinkID("lnk_22222222222222222222222222222222")
	a, _, err := GeneratePair(idA, "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Clear()
	b, _, err := GeneratePair(idB, "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Clear()
	id1, err := StageCredentials(root, materialPlan(idA, Listen), a)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := StageCredentials(root, materialPlan(idB, Listen), b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal([]byte(id1.AuthorizationSHA256), []byte(id2.AuthorizationSHA256)) {
		t.Fatal("independent Links share authorization fingerprints")
	}
	if got, err := InspectCredentials(root, materialPlan(idA, Listen)); err != nil || got != id1 {
		t.Fatal("Link A drifted after staging B", err)
	}
}

// The issued server leaf must bind its owner Link ID. Otherwise a valid
// bundle from a different Link could be transplanted to an empty directory.
func TestQUICCredentialBundleCannotBeReusedForAnotherLink(t *testing.T) {
	origin := domain.LinkID("lnk_11111111111111111111111111111111")
	foreign := domain.LinkID("lnk_22222222222222222222222222222222")
	server, client, err := GeneratePair(origin, "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	defer client.Clear()
	for _, tc := range []struct {
		role   Role
		bundle CredentialBundle
	}{
		{Listen, server}, {Dial, client},
	} {
		root := privateStateRoot(t)
		plan := materialPlan(foreign, tc.role)
		if _, err := StageCredentials(root, plan, tc.bundle); err == nil {
			t.Fatalf("reused %s identity of foreign Link", tc.role)
		}
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("failed foreign Link admission wrote to State root: %v", err)
		}
	}
}

func TestQUICProtectedStorageRefusesUnsafeDirectorySubstitution(t *testing.T) {
	id := domainTestLinkID()
	p := materialPlan(id, Listen)
	server, _, err := GeneratePair(id, p.TLSName)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	root := privateStateRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "credentials"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "credentials", "quic")); err != nil {
		t.Fatal(err)
	}
	if _, err := StageCredentials(root, p, server); err == nil {
		t.Fatal("symlinked carrier directory admitted")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("foreign symlink target touched: %v %v", entries, err)
	}
	if err := os.Remove(filepath.Join(root, "credentials", "quic")); err != nil {
		t.Fatal(err)
	}
	if _, err := StageCredentials(root, p, server); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "credentials", "quic", string(id))
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCredentials(root, p); err == nil {
		t.Fatal("nonprivate Link directory trusted")
	}
	if _, err := StageCredentials(root, p, server); err == nil {
		t.Fatal("nonprivate Link directory reused for staging")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCredentials(root, p); err != nil {
		t.Fatal("verified directory did not recover after restoring private mode", err)
	}
}
