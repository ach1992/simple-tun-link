package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func updateTestDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func updateTestFilename() string {
	return "stl_v0.1.99_linux_" + runtime.GOARCH + "_local-install.sh"
}

func TestVerifiedUpdateRequiresExplicitIndependentDigestAndExactSource(t *testing.T) {
	hash := strings.Repeat("a", 64)
	local := "/root/stl/" + updateTestFilename()
	valid := [][]string{
		{"--local", local, "--sha256", hash},
		{"--mirror", "https://mirror.example.com/install.sh", "--sha256", hash},
	}
	for _, args := range valid {
		if _, err := parseVerifiedUpdate(args); err != nil {
			t.Fatalf("refused valid explicit update %q: %v", args, err)
		}
	}
	wrongArch := "arm64"
	if runtime.GOARCH == "arm64" {
		wrongArch = "amd64"
	}
	for _, args := range [][]string{
		nil,
		{"--local", local},
		{"--local", local, "--sha256", ""},
		{"--local", local, "--sha256", strings.Repeat("A", 64)},
		{"--local", local, "--sha256", hash + "x"},
		{"--local", "/tmp/" + updateTestFilename(), "--sha256", hash},
		{"--local", "/root/stl/temporary/../" + updateTestFilename(), "--sha256", hash},
		{"--local", "/root/stl//" + updateTestFilename(), "--sha256", hash},
		{"--local", "/root/stl/stl_v1.2.3-rc.1_linux_" + runtime.GOARCH + "_local-install.sh", "--sha256", hash},
		{"--local", "/root/stl/stl_v1.2.3_linux_" + wrongArch + "_local-install.sh", "--sha256", hash},
		{"--local", local, "--sha256", hash, "--with-wss"},
		{"--mirror", "http://mirror.example.com/install.sh", "--sha256", hash},
		{"--remote", local, "--sha256", hash},
	} {
		if _, err := parseVerifiedUpdate(args); err == nil {
			t.Fatalf("accepted unsafe or incomplete update arguments: %q", args)
		}
	}
	var out, errOut bytes.Buffer
	if exit := run([]string{"update", "--mirror", "https://mirror.example.com/install.sh"}, &out, &errOut); exit != 2 ||
		!strings.Contains(errOut.String(), "--sha256") || out.Len() != 0 {
		t.Fatalf("CLI exposed unsafe implicit trust: exit=%d stdout=%q stderr=%q", exit, out.String(), errOut.String())
	}
}

func TestVerifiedUpdateMirrorURLRejectsUntrustedOrigins(t *testing.T) {
	for _, good := range []string{"https://mirror.example.com/install.sh", "https://127.0.0.1:443/install.sh"} {
		if err := verifyUpdateMirrorURL(good); err != nil {
			t.Fatalf("valid mirror %q: %v", good, err)
		}
	}
	for _, bad := range []string{
		"http://mirror.example.com/install.sh", "https://mirror.example.com",
		"https://mirror.example.com/install.sh/../install.sh",
		"https://mirror.example.com/install.sh?sha256=abc",
		"https://mirror.example.com/install.sh#fragment",
		"https://name:secret@mirror.example.com/install.sh",
		"https://mirror.example.com:0/install.sh",
		"https://mirror.example.com:99999/install.sh",
		"https://mirror..example.com/install.sh",
		"https://mirror.example.com.evil/install.sh/extra",
		"https://mirror.example.com/%69nstall.sh",
		"https://mirror.example.com/install.sh?",
		"https://mirror.example.com:443@evil.example.com/install.sh",
	} {
		if err := verifyUpdateMirrorURL(bad); err == nil {
			t.Fatalf("accepted unsafe mirror URL: %q", bad)
		}
	}
}

func TestVerifiedUpdateLocalSnapshotTrustAndIsolation(t *testing.T) {
	root := t.TempDir()
	transfer := filepath.Join(root, "stl")
	if err := os.Mkdir(transfer, 0700); err != nil {
		t.Fatal(err)
	}
	name := updateTestFilename()
	source := filepath.Join(transfer, name)
	original := []byte("#!/bin/bash\nprintf 'SOURCE_NOT_EXECUTED\\n'\n")
	if err := os.WriteFile(source, original, 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	pin := updateTestDigest(original)
	dir, file, err := verifiedUpdateSnapshot(source, root, transfer, uid, pin)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(file) != name || filepath.Dir(file) != dir || !strings.HasPrefix(dir, root+string(os.PathSeparator)+".stl-preflight.") {
		t.Fatalf("wrong private snapshot: dir=%q file=%q", dir, file)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("staging must be private: %v %v", info, err)
	}
	if err := os.WriteFile(source, []byte("different bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(copied, original) {
		t.Fatalf("staging reopened transferred file: %q %v", copied, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	if _, _, err := verifiedUpdateSnapshot(source, root, transfer, uid, pin); err == nil ||
		!strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Fatalf("tampered transferred file accepted: %v", err)
	}
	stages, err := filepath.Glob(filepath.Join(root, ".stl-preflight.*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("failed snapshot left staging: %v %v", stages, err)
	}
	// File contents now deliberately differ, but no safety test executes them.
	if err := os.Chmod(source, 0666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifiedUpdateSnapshot(source, root, transfer, uid, updateTestDigest([]byte("different bytes"))); err == nil {
		t.Fatal("writable source admitted")
	}
	if err := os.Chmod(source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, filepath.Join(transfer, "shared-link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifiedUpdateSnapshot(source, root, transfer, uid, updateTestDigest([]byte("different bytes"))); err == nil {
		t.Fatal("hardlinked installer admitted")
	}
	if err := os.Remove(filepath.Join(transfer, "shared-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/true", source); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifiedUpdateSnapshot(source, root, transfer, uid, pin); err == nil {
		t.Fatal("symlink admitted")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(source, verifiedLocalMaxBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifiedUpdateSnapshot(source, root, transfer, uid, pin); err == nil {
		t.Fatal("oversized installer admitted")
	}
	if err := os.Chmod(transfer, 0770); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifiedUpdateSnapshot(source, root, transfer, uid, pin); err == nil {
		t.Fatal("group-writable transfer directory admitted")
	}
}

func TestVerifiedUpdateCopyBoundsAndExactDigest(t *testing.T) {
	payload := []byte("complete-and-bounded-script")
	cases := []struct {
		name      string
		max, size int64
		sha       string
		wantPass  bool
	}{
		{"valid", int64(len(payload)), int64(len(payload)), updateTestDigest(payload), true},
		{"too big for streaming cap", int64(len(payload) - 1), int64(len(payload)), updateTestDigest(payload), false},
		{"changed during snapshot", 100, int64(len(payload) + 1), updateTestDigest(payload), false},
		{"incorrect hash", 100, int64(len(payload)), strings.Repeat("0", 64), false},
		{"not independently pinned", 100, int64(len(payload)), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "private")
			err := writeVerifiedUpdateCopy(target, bytes.NewReader(payload), tc.max, tc.size, tc.sha)
			if (err == nil) != tc.wantPass {
				t.Fatalf("unexpected copy outcome: %v", err)
			}
			if tc.wantPass {
				copied, e := os.ReadFile(target)
				if e != nil || !bytes.Equal(copied, payload) {
					t.Fatalf("wrong private copy: %q %v", copied, e)
				}
			}
		})
	}
}

func TestVerifiedUpdateMirrorSnapshotHTTPSPinAndBoundedTransport(t *testing.T) {
	payload := []byte("#!/bin/bash\necho TRUSTED_SCRIPT_WAS_NOT_EXECUTED\n")
	var mode atomic.Value
	mode.Store("ok")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/install.sh" {
			http.NotFound(w, r)
			return
		}
		switch mode.Load().(string) {
		case "redirect":
			http.Redirect(w, r, "https://untrusted.example/install.sh", http.StatusFound)
		case "status":
			http.Error(w, "not found", http.StatusNotFound)
		case "oversize":
			_, _ = io.WriteString(w, strings.Repeat("X", int(verifiedMirrorMaxBytes)+1))
		case "truncated":
			// This body is shorter than its declared length; never stage it.
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)+20))
			_, _ = w.Write(payload)
		default:
			_, _ = w.Write(payload)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = verifiedUpdateHTTPClient().CheckRedirect
	root := t.TempDir()
	uid := uint32(os.Geteuid())
	url := server.URL + "/install.sh"
	dir, path, err := verifiedMirrorSnapshot(context.Background(), url, updateTestDigest(payload), root, uid, client)
	if err != nil {
		t.Fatalf("verified pinned TLS snapshot failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("mismatched staged HTTPS bytes %q %v", got, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, pin string
	}{
		{"wrong pin", strings.Repeat("0", 64)},
		{"redirect", updateTestDigest(payload)},
		{"status", updateTestDigest(payload)},
		{"oversize", updateTestDigest(payload)},
		{"truncated", updateTestDigest(payload)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.name)
			if _, _, err := verifiedMirrorSnapshot(context.Background(), url, tc.pin, root, uid, client); err == nil {
				t.Fatalf("accepted unverified HTTPS bootstrap: %s", tc.name)
			}
			stages, err := filepath.Glob(filepath.Join(root, ".stl-mirror-preflight.*"))
			if err != nil || len(stages) != 0 {
				t.Fatalf("failed mirror left private copies: %v %v", stages, err)
			}
		})
	}
	mode.Store("ok")
	// HTTPS requires validated TLS. The real production client will not
	// trust the isolated fixture's ephemeral self-signed certificate.
	if _, _, err := verifiedMirrorSnapshot(context.Background(), url, updateTestDigest(payload), root, uid, verifiedUpdateHTTPClient()); err == nil {
		t.Fatal("production TLS client trusted a self-signed test certificate")
	}
}
