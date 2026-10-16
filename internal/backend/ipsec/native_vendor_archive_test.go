package ipsec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVendorOptionalPackageStatusReceiptStrict(t *testing.T) {
	pkg := "libcharon-extauth-plugins"
	cases := []struct {
		name          string
		exit          int
		out, diag     string
		wantInstalled bool
		wantOK        bool
	}{
		{"official installed", 0, "install ok installed", "", true, true},
		{"genuine absent", 1, "", "dpkg-query: no packages found matching " + pkg + "\n", false, true},
		{"unpacked", 0, "install ok unpacked", "", false, false},
		{"half configured", 0, "install ok half-configured", "", false, false},
		{"config files remain", 0, "deinstall ok config-files", "", false, false},
		{"installed warning", 0, "install ok installed", "warning\n", false, false},
		{"unknown error", 1, "", "dpkg-query: database unavailable\n", false, false},
		{"missing with nonmatching output", 1, "foreign", "dpkg-query: no packages found matching " + pkg + "\n", false, false},
		{"wrong error exit", 2, "", "dpkg-query: no packages found matching " + pkg + "\n", false, false},
		{"unexpected newline", 0, "install ok installed\n", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installed, err := vendorOptionalPackageStatusReceipt(pkg, tc.exit, []byte(tc.out), []byte(tc.diag))
			if (err == nil) != tc.wantOK || installed != tc.wantInstalled {
				t.Fatalf("installed=%v error=%v; want installed=%v ok=%v", installed, err, tc.wantInstalled, tc.wantOK)
			}
		})
	}
	if _, err := vendorOptionalPackageStatusReceipt("foreign-owner", 0, []byte("install ok installed"), nil); err == nil {
		t.Fatal("foreign optional package accepted")
	}
}

func vendorBuildDisposableDeb(t *testing.T) ([]byte, string) {
	t.Helper()
	root := t.TempDir()
	live := filepath.Join(root, "installed.cfg")
	if err := os.WriteFile(live, []byte("official distro file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "staging")
	control := filepath.Join(stage, "DEBIAN")
	if err := os.MkdirAll(control, 0755); err != nil {
		t.Fatal(err)
	}
	// The aiworker may use a restrictive umask; dpkg-deb requires its
	// disposable control directory to have at least mode 0755.
	if err := os.Chmod(control, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(control, "control"), []byte(
		"Package: stl-archive-fixture\nVersion: 1.0\nArchitecture: all\nMaintainer: STL Test <stl@example.invalid>\nDescription: Disposable package checksum test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(stage, strings.TrimPrefix(live, "/"))
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("official distro file\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "fixture.deb")
	cmd := exec.Command("/usr/bin/dpkg-deb", "--build", stage, dest)
	cmd.Env = nativeSystemdFixedEnvironment()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("disposable .deb build failed: %v (%s)", err, out)
	}
	deb, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	return deb, live
}

func TestVendorSignedArchiveMatchesActualFiles(t *testing.T) {
	deb, live := vendorBuildDisposableDeb(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := vendorLiveFilesMatchOfficialArchive(ctx, deb); err != nil {
		t.Fatalf("unchanged official-style archive rejected: %v", err)
	}
	if err := os.WriteFile(live, []byte("locally modified bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := vendorLiveFilesMatchOfficialArchive(ctx, deb); err == nil {
		t.Fatal("locally repacked/modified live bytes accepted against signed archive")
	}
}

func TestVendorLiveArchiveMustMatchSignedSHA256(t *testing.T) {
	deb, _ := vendorBuildDisposableDeb(t)
	sha := sha256.Sum256(deb)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(deb)
	}))
	defer server.Close()
	good := vendorSignedPackage{name: "fixture", version: "1.0", filename: "pool/fixture.deb",
		digest: hex.EncodeToString(sha[:]), repo: server.URL + "/", size: int64(len(deb))}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := vendorCompareOfficialPayload(ctx, good); err != nil {
		t.Fatalf("signed archive fixture refused: %v", err)
	}
	// Replacing the archive with an internally consistent local .deb cannot
	// satisfy a different digest from the signed Packages index.
	good.digest = strings.Repeat("0", 64)
	if bytes.Equal(sha[:], make([]byte, len(sha))) {
		t.Fatal("test fixture hash unexpectedly zero")
	}
	if err := vendorCompareOfficialPayload(ctx, good); err == nil {
		t.Fatal("third-party archive accepted in place of signed distro digest")
	}
}
