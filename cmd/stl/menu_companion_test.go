package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
)

func TestCompanionSpecsMatchPinnedCanonicalInstaller(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for _, kind := range []menuCompanionKind{menuCompanionWSS, menuCompanionQUIC} {
			s, ok := menuPinnedCompanion(kind, arch)
			if !ok || len(s.digest) != 64 || !strings.HasPrefix(s.url, "https://github.com/") ||
				!strings.HasSuffix(s.url, "/"+s.asset) || !strings.Contains(string(canonicalInstaller), s.digest) {
				t.Fatalf("missing pinned source/installer identity for %s/%s: %+v", kind, arch, s)
			}
			switch kind {
			case menuCompanionWSS:
				archivePin := map[string]string{
					"amd64": "9708a99717b5a951453c2ff7c14c25d3418d02ca7fcb96fdb382a8f2083bab5e",
					"arm64": "b86abf73e340ed0c3ff9a77a5458aa27213784920ec65513132b36def45edc94",
				}[arch]
				if s.action != "companion-wss" || s.argument != "--archive" || s.digest != archivePin ||
					s.asset != "wstunnel_11.0.0_linux_"+arch+".tar.gz" {
					t.Fatalf("WSS source drift: %+v", s)
				}
			case menuCompanionQUIC:
				expected := quic.PinnedAMD64SHA256
				if arch == "arm64" {
					expected = quic.PinnedARM64SHA256
				}
				if s.digest != expected || s.action != "companion-quic" ||
					s.argument != "--binary" || s.asset != "hysteria-linux-"+arch {
					t.Fatalf("QUIC source drift: %+v", s)
				}
			}
		}
	}
	if _, ok := menuPinnedCompanion(menuCompanionWSS, "mips"); ok {
		t.Fatal("unsupported architecture accepted")
	}
	if _, ok := menuPinnedCompanion(menuCompanionQUIC, "386"); ok {
		t.Fatal("unsupported QUIC architecture accepted")
	}
	if runtime.GOARCH == "amd64" && wss.PinnedAMD64SHA256 == "" {
		t.Fatal("WSS executable pin missing")
	}
}

// Reproduces R01: a pinned executable with no installer ownership record
// must not be admitted through either Create or Import's shared setup flow.
func TestProductionMenuCompanionRejectsUnrecordedPinnedExecutable(t *testing.T) {
	for _, kind := range []menuCompanionKind{menuCompanionWSS, menuCompanionQUIC} {
		for _, operation := range []string{"create", "import"} {
			t.Run(string(kind)+"/"+operation, func(t *testing.T) {
				spec, ok := menuPinnedCompanion(kind, runtime.GOARCH)
				if !ok {
					t.Skip("unsupported architecture")
				}
				spec.binary = filepath.Join(t.TempDir(), "trusted-executable")
				spec.record = filepath.Join(t.TempDir(), "missing-record")
				if err := os.WriteFile(spec.binary, []byte("fixture for an already pinned executable"), 0755); err != nil {
					t.Fatal(err)
				}
				inspected := 0
				ops := productionMenuCompanionOps(func() error {
					inspected++
					return nil // standalone executable pin is valid
				}, spec)
				input := strings.NewReader("1\nINSTALL\n")
				var out bytes.Buffer
				if menuEnsureCompanion(input, bufio.NewReader(input), &out, spec, ops) {
					t.Fatal("unrecorded executable reused without verifying installer ownership")
				}
				if inspected != 1 || !strings.Contains(out.String(), "will not overwrite") {
					t.Fatalf("identity admission did not fail closed: inspections=%d output=%q", inspected, out.String())
				}
			})
		}
	}
}

func TestCompanionCopyRejectsBadHashAndSize(t *testing.T) {
	data := []byte(strings.Repeat("test-real-contents", 120))
	hash := sha256.Sum256(data)
	good := hex.EncodeToString(hash[:])
	for _, tc := range []struct {
		name, source, hash string
		want               error
	}{
		{"valid", string(data), good, nil},
		{"tampered", string(data), strings.Repeat("0", 64), menuCompanionHashError},
		{"too small", "fake", good, menuCompanionSizeError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "asset")
			err := menuCopyPinnedAsset(strings.NewReader(tc.source), path, tc.hash)
			if !errors.Is(err, tc.want) {
				if tc.want == nil && err == nil {
					return
				}
				t.Fatalf("unexpected pinned copy outcome: got %v want %v", err, tc.want)
			}
			if err == nil {
				info, statErr := os.Stat(path)
				if statErr != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("snapshot not protected: %v %v", info, statErr)
				}
				if err := menuCopyPinnedAsset(strings.NewReader(tc.source), path, good); !errors.Is(err, menuCompanionStagingError) {
					t.Fatalf("O_EXCL denied neither overwrite nor reuse: %v", err)
				}
			}
		})
	}
}

type menuRoundTripper func(*http.Request) (*http.Response, error)

func (f menuRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// A valid HTTPS response can fail after streaming some verified-looking bytes.
// This is a transfer/read failure, not an invalid upstream HTTP status.
type menuInterruptedReader struct{}

func (menuInterruptedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type menuUnwritableStage struct{}

func (menuUnwritableStage) Write([]byte) (int, error) { return 0, io.ErrShortWrite }

func TestPinnedCompanionPayloadDistinguishesReadAndWriteFailures(t *testing.T) {
	body := strings.Repeat("transfer-data", 200)
	sum := sha256.Sum256([]byte(body))
	digest := hex.EncodeToString(sum[:])
	if err := menuCopyPinnedPayload(strings.NewReader(body), menuUnwritableStage{}, digest); !errors.Is(err, menuCompanionStagingError) {
		t.Fatalf("failed staging write misclassified as a remote source failure: %v", err)
	}
	if err := menuCopyPinnedPayload(io.MultiReader(strings.NewReader(body[:1300]), menuInterruptedReader{}), io.Discard, digest); !errors.Is(err, menuCompanionReadError) {
		t.Fatalf("interrupted source reader misclassified as staging failure: %v", err)
	}
}

func TestOnlineCompanionAcquisitionTrustedOriginAndDigest(t *testing.T) {
	body := strings.Repeat("fixed-snapshot-data", 100)
	hash := sha256.Sum256([]byte(body))
	spec, _ := menuPinnedCompanion(menuCompanionQUIC, "amd64")
	spec.digest = hex.EncodeToString(hash[:])
	run := func(status int, content, redirect string, transportErr error) error {
		client := menuCompanionClient()
		client.Transport = menuRoundTripper(func(req *http.Request) (*http.Response, error) {
			if req.URL.Scheme != "https" {
				t.Fatal("non-TLS request")
			}
			if transportErr != nil {
				return nil, transportErr
			}
			headers := make(http.Header)
			if redirect != "" {
				headers.Set("Location", redirect)
			}
			return &http.Response{StatusCode: status, Header: headers,
				Body: io.NopCloser(strings.NewReader(content)), ContentLength: int64(len(content)), Request: req}, nil
		})
		return menuDownloadPinnedCompanionWithClient(context.Background(), spec, filepath.Join(t.TempDir(), "asset"), client)
	}
	if err := run(http.StatusOK, body, "", nil); err != nil {
		t.Fatalf("fixed official HTTPS acquisition failed: %v", err)
	}
	if err := run(http.StatusOK, body+"not-pinned", "", nil); !errors.Is(err, menuCompanionHashError) {
		t.Fatalf("wrong SHA accepted: %v", err)
	}
	if err := run(http.StatusNotFound, body, "", nil); !errors.Is(err, menuCompanionSourceError) {
		t.Fatalf("unavailable release ignored: %v", err)
	}
	if err := run(http.StatusFound, "", "https://evil.example/release", nil); !errors.Is(err, menuCompanionSourceError) {
		t.Fatalf("untrusted redirect followed: %v", err)
	}
	if err := run(0, "", "", fmt.Errorf("network down")); !errors.Is(err, menuCompanionNetworkError) {
		t.Fatalf("network failure ignored: %v", err)
	}
	client := menuCompanionClient()
	client.Transport = menuRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body:          io.NopCloser(io.MultiReader(strings.NewReader(body[:1200]), menuInterruptedReader{})),
			ContentLength: -1, Request: req}, nil
	})
	if err := menuDownloadPinnedCompanionWithClient(context.Background(), spec,
		filepath.Join(t.TempDir(), "partially-downloaded-asset"), client); !errors.Is(err, menuCompanionNetworkError) {
		t.Fatalf("mid-body HTTPS read failure misclassified as upstream rejection: %v", err)
	}
}

func testMenuCompanion(t *testing.T) (menuCompanionSpec, []byte, *bool, menuCompanionOps, *int) {
	t.Helper()
	data := []byte(strings.Repeat("private-hash-verified-test-bytes", 100))
	d := sha256.Sum256(data)
	spec, _ := menuPinnedCompanion(menuCompanionWSS, "amd64")
	spec.digest = hex.EncodeToString(d[:])
	spec.binary = filepath.Join(t.TempDir(), "absent-helper")
	spec.record = filepath.Join(t.TempDir(), "absent-record")
	ready := new(bool)
	installs := new(int)
	ops := menuCompanionOps{
		stageParent: t.TempDir(),
		localFile:   filepath.Join(t.TempDir(), spec.asset),
		inspect: func() error {
			if *ready {
				return nil
			}
			return errors.New("not installed")
		},
		canInstall: func(io.Reader, io.Writer) bool { return true },
		download: func(_ context.Context, spec menuCompanionSpec, path string) error {
			return menuCopyPinnedAsset(bytes.NewReader(data), path, spec.digest)
		},
		copyLocal: func(spec menuCompanionSpec, path, target string) error {
			return menuCopyPinnedAsset(bytes.NewReader(data), target, spec.digest)
		},
		install: func(_ context.Context, stdout, stderr io.Writer, args ...string) error {
			*installs++
			if len(args) != 3 || args[0] != spec.action || args[1] != spec.argument ||
				filepath.Base(args[2]) != spec.asset {
				t.Fatalf("unexpected canonical installer call: %q", args)
			}
			got, e := os.ReadFile(args[2])
			if e != nil || !bytes.Equal(got, data) {
				t.Fatalf("canonical installer received unverified content: %v", e)
			}
			*ready = true
			return nil
		},
	}
	return spec, data, ready, ops, installs
}

func TestMenuCompanionOnlineConsentVerificationAndCancel(t *testing.T) {
	t.Run("online selected and confirmed", func(t *testing.T) {
		s, _, ready, ops, installs := testMenuCompanion(t)
		in := strings.NewReader("1\nINSTALL\n")
		var out bytes.Buffer
		if !menuEnsureCompanion(in, bufio.NewReader(in), &out, s, ops) ||
			!*ready || *installs != 1 || !strings.Contains(out.String(), "Continuing the same Create") ||
			!strings.Contains(out.String(), "SHA-256") {
			t.Fatalf("guided approved install failed: %q", out.String())
		}
		entries, _ := os.ReadDir(ops.stageParent)
		if len(entries) != 0 {
			t.Fatalf("private downloads not cleaned: %+v", entries)
		}
	})
	t.Run("cancel does not download", func(t *testing.T) {
		s, _, ready, ops, installs := testMenuCompanion(t)
		calls := 0
		ops.download = func(context.Context, menuCompanionSpec, string) error {
			calls++
			return nil
		}
		in := strings.NewReader("1\n\n")
		var out bytes.Buffer
		if menuEnsureCompanion(in, bufio.NewReader(in), &out, s, ops) ||
			*ready || *installs != 0 || calls != 0 || !strings.Contains(out.String(), "cancelled") {
			t.Fatalf("cancel performed effects: %q", out.String())
		}
	})
	t.Run("not an installed root TTY", func(t *testing.T) {
		s, _, ready, ops, installs := testMenuCompanion(t)
		ops.canInstall = func(io.Reader, io.Writer) bool { return false }
		in := strings.NewReader("1\nINSTALL\n")
		var out bytes.Buffer
		if menuEnsureCompanion(in, bufio.NewReader(in), &out, s, ops) ||
			*ready || *installs != 0 || !strings.Contains(out.String(), "sudo stl menu") {
			t.Fatalf("root gate bypassed: %q", out.String())
		}
	})
	t.Run("foreign helper never overwritten", func(t *testing.T) {
		s, _, _, ops, installs := testMenuCompanion(t)
		if err := os.WriteFile(s.binary, []byte("not verified"), 0600); err != nil {
			t.Fatal(err)
		}
		in := strings.NewReader("1\nINSTALL\n")
		var out bytes.Buffer
		if menuEnsureCompanion(in, bufio.NewReader(in), &out, s, ops) ||
			*installs != 0 || !strings.Contains(out.String(), "will not overwrite") {
			t.Fatalf("foreign helper adoption: %q", out.String())
		}
	})
}

func TestMenuCompanionOfflineFallbackAndFailedInstallerNoRetry(t *testing.T) {
	s, data, _, ops, installs := testMenuCompanion(t)
	downloads := 0
	ops.download = func(ctx context.Context, spec menuCompanionSpec, target string) error {
		downloads++
		client := menuCompanionClient()
		client.Transport = menuRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
				Body:          io.NopCloser(io.MultiReader(bytes.NewReader(data[:1400]), menuInterruptedReader{})),
				ContentLength: -1, Request: req}, nil
		})
		return menuDownloadPinnedCompanionWithClient(ctx, spec, target, client)
	}
	in := strings.NewReader("1\nINSTALL\n2\nINSTALL\n")
	var out bytes.Buffer
	if !menuEnsureCompanion(in, bufio.NewReader(in), &out, s, ops) ||
		downloads != 1 || *installs != 1 ||
		!strings.Contains(out.String(), "official_download_unreachable") ||
		!strings.Contains(out.String(), "Install local") {
		t.Fatalf("offline fallback not usable: %q", out.String())
	}
	if entries, err := os.ReadDir(ops.stageParent); err != nil || len(entries) != 0 {
		t.Fatalf("interrupted online staging not removed after local recovery: %v / %v", entries, err)
	}
	s, _, _, ops, installs = testMenuCompanion(t)
	ops.install = func(_ context.Context, stdout, stderr io.Writer, args ...string) error {
		*installs++
		_, _ = io.WriteString(stderr, "root installer private-url-secret\n")
		return errors.New("private-data-should-not-leak")
	}
	in = strings.NewReader("1\nINSTALL\n1\nINSTALL\n")
	out.Reset()
	if menuEnsureCompanion(in, bufio.NewReader(in), &out, s, ops) ||
		*installs != 1 || !strings.Contains(out.String(), "root installer private-url-secret") ||
		strings.Contains(out.String(), "private-data-should-not-leak") ||
		!strings.Contains(out.String(), "reconciled before a new attempt") {
		t.Fatalf("failed canonical installer silently retried/leaked: %q", out.String())
	}
}

func TestMenuCompanionLocalSourceCannotChooseArbitraryPath(t *testing.T) {
	s, _ := menuPinnedCompanion(menuCompanionQUIC, "amd64")
	if err := menuCopyLocalCompanion(s, "/tmp/foreign-"+s.asset, filepath.Join(t.TempDir(), "asset")); !errors.Is(err, menuCompanionLocalError) {
		t.Fatalf("arbitrary local source accepted: %v", err)
	}
}

func TestMenuLocalCompanionOwnershipAndDigestFromPrivateDirectory(t *testing.T) {
	spec, _ := menuPinnedCompanion(menuCompanionQUIC, "amd64")
	payload := []byte(strings.Repeat("genuine-offline-transfer-fixture", 125))
	sum := sha256.Sum256(payload)
	spec.digest = hex.EncodeToString(sum[:])
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, spec.asset)
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	target := filepath.Join(t.TempDir(), "snapshot")
	if err := menuCopyLocalCompanionFromDir(spec, source, target, dir, uid); err != nil {
		t.Fatalf("owned local asset wrongly rejected: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("local source was not reproduced in protected verified snapshot", err)
	}
	if err := os.Chmod(source, 0666); err != nil {
		t.Fatal(err)
	}
	if err := menuCopyLocalCompanionFromDir(spec, source, filepath.Join(t.TempDir(), "snapshot"), dir, uid); !errors.Is(err, menuCompanionLocalError) {
		t.Fatalf("world-writable local file admitted: %v", err)
	}
	if err := os.Chmod(source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, source); err != nil {
		t.Fatal(err)
	}
	if err := menuCopyLocalCompanionFromDir(spec, source, filepath.Join(t.TempDir(), "snapshot"), dir, uid); !errors.Is(err, menuCompanionLocalError) {
		t.Fatalf("local source symlink admitted: %v", err)
	}
}

func TestMenuCompanionDownloadSizeLimitBeforeCopy(t *testing.T) {
	spec, _ := menuPinnedCompanion(menuCompanionWSS, "amd64")
	client := menuCompanionClient()
	client.Transport = menuRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(strings.NewReader("not trusted")),
			ContentLength: menuCompanionMaxBytes,
			Request:       req,
		}, nil
	})
	dst := filepath.Join(t.TempDir(), "download")
	if err := menuDownloadPinnedCompanionWithClient(context.Background(), spec, dst, client); !errors.Is(err, menuCompanionSizeError) {
		t.Fatalf("oversized GitHub response accepted: %v", err)
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("size-denied response created a staging file: %v", err)
	}
}

// Optional nonproduction network smoke. Never runs in ordinary CI, never
// installs downloaded executables, and leaves no asset outside t.TempDir.
func TestCompanionLiveOfficialDownloadOptIn(t *testing.T) {
	if os.Getenv("STL_COMPANION_LIVE_DOWNLOAD") != "1" {
		t.Skip("operator-only real official release retrieval")
	}
	for _, kind := range []menuCompanionKind{menuCompanionWSS, menuCompanionQUIC} {
		t.Run(string(kind), func(t *testing.T) {
			spec, ok := menuPinnedCompanion(kind, runtime.GOARCH)
			if !ok {
				t.Skip("no pinned asset for this test architecture")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 95*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), spec.asset)
			if err := menuDownloadPinnedCompanion(ctx, spec, path); err != nil {
				t.Fatalf("real official HTTPS download or pinned digest rejected: %v", err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Size() <= 1024 || info.Mode().Perm() != 0600 {
				t.Fatalf("unverified protected staged asset: %v %v", info, err)
			}
			t.Logf("official %s pinned download PASS: %d bytes", spec.asset, info.Size())
		})
	}
}

func TestMenuCompanionInitialOriginRequiresTrustedHTTPS(t *testing.T) {
	spec, ok := menuPinnedCompanion(menuCompanionWSS, "amd64")
	if !ok {
		t.Fatal("pinned asset unavailable")
	}
	client := menuCompanionClient()
	client.Transport = menuRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid initial URL reached network")
		return nil, nil
	})
	for _, source := range []string{
		"http://github.com/erebe/wstunnel/releases/download/v11.0.0/asset",
		"https://evil.example/asset",
		"https://user:secret@github.com/asset",
		"https://github.com:443/asset",
	} {
		spec.url = source
		if err := menuDownloadPinnedCompanionWithClient(context.Background(), spec, filepath.Join(t.TempDir(), "out"), client); !errors.Is(err, menuCompanionSourceError) {
			t.Fatalf("bad initial URL accepted: %q %v", source, err)
		}
	}
}
