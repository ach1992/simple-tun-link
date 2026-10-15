package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/version"
)

func sampleOfficialRelease(tag string, published time.Time) menuOfficialRelease {
	r := menuOfficialRelease{TagName: tag, Prerelease: true, PublishedAt: published}
	for _, name := range []string{"stl_" + tag + "_linux_amd64", "stl_" + tag + "_linux_arm64",
		"BUILD-MANIFEST.txt", "SHA256SUMS", "LICENSE"} {
		r.Assets = append(r.Assets, struct {
			Name  string `json:"name"`
			Size  int64  `json:"size"`
			State string `json:"state"`
		}{Name: name, Size: 9, State: "uploaded"})
	}
	return r
}

func TestMenuReleaseCatalogueFiltersSortsAndNeverTrustsReleaseNames(t *testing.T) {
	now := time.Date(2026, 10, 15, 5, 0, 0, 0, time.UTC)
	first := sampleOfficialRelease("v0.1.0-rc.3", now.Add(-2*time.Hour))
	other := sampleOfficialRelease("v0.1.0-rc.5", now)
	middle := sampleOfficialRelease("v0.1.0-rc.4", now.Add(-time.Hour))
	duplicate := other
	incomplete := sampleOfficialRelease("v0.1.0-rc.7", now.Add(time.Hour))
	incomplete.Assets = nil
	unsafe := sampleOfficialRelease("v0.1.0-rc.99;rm -rf /", now.Add(2*time.Hour))
	draft := sampleOfficialRelease("v0.1.0-rc.6", now.Add(3*time.Hour))
	draft.Draft = true
	payload, err := json.Marshal([]menuOfficialRelease{first, unsafe, incomplete, middle, draft, other, duplicate})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Error("unexpected release request")
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	got, err := fetchMenuOfficialReleases(context.Background(), server.Client(), server.URL)
	if err != nil || len(got) != 3 || got[0].TagName != other.TagName ||
		got[1].TagName != middle.TagName || got[2].TagName != first.TagName {
		t.Fatalf("release list invalid: %+v, error=%v", got, err)
	}
}

func TestMenuReleaseCatalogueFailsClosedOnTruncatedOrInvalidData(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		status        int
	}{
		{"empty list", "[]", 200},
		{"invalid json", `{"a":"b"}`, 200},
		{"too large", strings.Repeat(" ", menuReleaseBytesLimit+1), 200},
		{"unexpected status", "[]", 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.content)
			}))
			defer server.Close()
			if got, err := fetchMenuOfficialReleases(context.Background(), server.Client(), server.URL); err == nil || len(got) != 0 {
				t.Fatalf("malformed release data accepted: %+v err=%v", got, err)
			}
		})
	}
}

func TestMenuForwardReleaseUpgradeGateRejectsDowngradesAndUnknownVersions(t *testing.T) {
	for _, tc := range []struct {
		current, target string
		allowed         bool
	}{
		{"v0.1.0-rc.4", "v0.1.0-rc.5", true},
		{"v0.1.0-rc.5", "v0.1.0-rc.5", false},
		{"v0.1.0-rc.5", "v0.1.0-rc.4", false},
		{"v0.1.0-rc.5", "v0.1.0-rc.12", true},
		{"v0.1.0-rc.5", "v0.2.0-rc.1", false},
		{"v1.0.0", "v1.0.1", false},
		{"dev-aaaa", "v0.1.0-rc.5", false},
		{"v0.1.0-rc.5", "v0.1.0-rc.5;malicious", false},
	} {
		if actual := menuRCUpgrade(tc.current, tc.target); actual != tc.allowed {
			t.Fatalf("upgrade gate current=%q target=%q got=%t", tc.current, tc.target, actual)
		}
	}
}

func TestMenuUpdateChoiceIsReadOnlyOutsideRealInstalledRootTTY(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	var out, errOut bytes.Buffer
	opts := &runtimeOptions{stateRoot: root, menuReleases: func(context.Context) ([]menuOfficialRelease, error) {
		now := time.Now()
		return []menuOfficialRelease{
			sampleOfficialRelease("v0.1.0-rc.8", now),
			sampleOfficialRelease("v0.1.0-rc.7", now.Add(-time.Hour)),
			sampleOfficialRelease("v0.1.0-rc.6", now.Add(-2*time.Hour)),
		}, nil
	}}
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader("6\n2\n8\n"), &out, &errOut, opts)
	if code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), "v0.1.0-rc.7") ||
		!strings.Contains(out.String(), "No in-place update command is recommended") ||
		strings.Contains(out.String(), "bash -o pipefail") ||
		strings.Contains(out.String(), "Update complete") {
		t.Fatalf("untrusted menu tried to update: code=%d out=%s errors=%s", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("menu changed local State: %v", err)
	}
}

func TestMenuUpdateOfflineFallbackAndRejectedInstallerInput(t *testing.T) {
	var out, errOut bytes.Buffer
	opts := &runtimeOptions{stateRoot: filepath.Join(t.TempDir(), "absent"),
		menuReleases: func(context.Context) ([]menuOfficialRelease, error) {
			return nil, errors.New("secret network diagnostic must not be printed")
		}}
	if code := runWithRuntimeInput([]string{"menu"}, strings.NewReader("6\n0\n8\n"), &out, &errOut, opts); code != 0 ||
		!strings.Contains(out.String(), "Cannot verify the official release list") ||
		strings.Contains(out.String()+errOut.String(), "secret network diagnostic") {
		t.Fatalf("offline fallback was unsafe: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	if err := menuRunCanonicalUpdate(context.Background(), menuOfficialRelease{TagName: "v0.1.0;bad"}, &out, &errOut); err == nil {
		t.Fatal("unsafe tag reached installer")
	}
}

// After privileged update execution, success requires the actual installed
// binary to attest to the selected exact version and an embedded commit.
func TestMenuUpdatedExecutableIdentityVerification(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		ok         bool
	}{
		{"verified", `{"schema_version":1,"version":"v0.1.0-rc.6","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, true},
		{"wrong version", `{"schema_version":1,"version":"v0.1.0-rc.5","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, false},
		{"missing commit", `{"schema_version":1,"version":"v0.1.0-rc.6"}`, false},
		{"untrusted commit", `{"schema_version":1,"version":"v0.1.0-rc.6","commit":"partial"}`, false},
		{"incompatible schema", `{"schema_version":2,"version":"v0.1.0-rc.6","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, false},
		{"garbled", `{"schema_version"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := menuInstalledVersionMatches([]byte(tc.data), "v0.1.0-rc.6"); got != tc.ok {
				t.Fatalf("installed identity verification=%t, want %t", got, tc.ok)
			}
		})
	}
}

func TestMenuRootUpdateRejectsMutableMissingAndAmbiguousReleaseTrust(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"immutable", `{"id":42,"tag_name":"v0.1.0-rc.6","immutable":true}`, true},
		{"false", `{"id":42,"tag_name":"v0.1.0-rc.6","immutable":false}`, false},
		{"missing", `{"id":42,"tag_name":"v0.1.0-rc.6"}`, false},
		{"null", `{"id":42,"tag_name":"v0.1.0-rc.6","immutable":null}`, false},
		{"missing release ID", `{"tag_name":"v0.1.0-rc.6","immutable":true}`, false},
		{"zero release ID", `{"id":0,"tag_name":"v0.1.0-rc.6","immutable":true}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var release menuOfficialRelease
			if err := json.Unmarshal([]byte(tc.raw), &release); err != nil {
				t.Fatal(err)
			}
			if got := menuReleaseImmutable(release); got != tc.want {
				t.Fatalf("release trust %t, want %t", got, tc.want)
			}
			if !tc.want {
				var out, errOut bytes.Buffer
				err := menuRunCanonicalUpdate(context.Background(), release, &out, &errOut)
				if err == nil || !strings.Contains(err.Error(), "confirmed immutable") || out.Len() != 0 || errOut.Len() != 0 {
					t.Fatalf("untrusted metadata passed root-execution guard: %v; %q; %q", err, out.String(), errOut.String())
				}
			}
		})
	}
	var release menuOfficialRelease
	if err := json.Unmarshal([]byte(`{"id":42,"tag_name":"v0.1.0-rc.6","immutable":"true"}`), &release); err == nil {
		t.Fatal("malformed immutable field was accepted")
	}
}

func TestMenuMutablePublishedUpgradeRemainsVisibleButManualOnly(t *testing.T) {
	original := version.Version
	version.Version = "v0.1.0-rc.5"
	t.Cleanup(func() { version.Version = original })
	for _, tc := range []struct {
		name      string
		immutable *bool
	}{
		{"mutable", boolPointer(false)},
		{"missing", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "absent")
			release := sampleOfficialRelease("v0.1.0-rc.99", time.Now())
			release.ID, release.Immutable = 123, tc.immutable
			var out, errOut bytes.Buffer
			opts := &runtimeOptions{stateRoot: root, menuReleases: func(context.Context) ([]menuOfficialRelease, error) {
				return []menuOfficialRelease{release}, nil
			}}
			code := runWithRuntimeInput([]string{"menu"}, strings.NewReader("6\n1\n8\n"), &out, &errOut, opts)
			if code != 0 || errOut.Len() != 0 ||
				!strings.Contains(out.String(), "Automatic root update is disabled") ||
				!strings.Contains(out.String(), "manual only") ||
				!strings.Contains(out.String(), "Do not pipe a mutable-tag download") ||
				strings.Contains(out.String(), "Type UPDATE") ||
				strings.Contains(out.String(), "Update complete") {
				t.Fatalf("mutable release update behavior unsafe: code=%d out=%q err=%q", code, out.String(), errOut.String())
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mutable release changed State: %v", err)
			}
		})
	}
}

func boolPointer(v bool) *bool { return &v }

func TestMenuImmutableReleaseStillNeedsInstalledRootRealTTY(t *testing.T) {
	old := version.Version
	version.Version = "v0.1.0-rc.5"
	t.Cleanup(func() { version.Version = old })
	root := filepath.Join(t.TempDir(), "absent")
	release := sampleOfficialRelease("v0.1.0-rc.6", time.Now())
	release.ID, release.Immutable = 321, boolPointer(true)
	var out, errOut bytes.Buffer
	opts := &runtimeOptions{stateRoot: root, menuReleases: func(context.Context) ([]menuOfficialRelease, error) {
		return []menuOfficialRelease{release}, nil
	}}
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader("6\n1\n8\n"), &out, &errOut, opts)
	if code != 0 || errOut.Len() != 0 ||
		!strings.Contains(out.String(), "Pre-release / immutable") ||
		!strings.Contains(out.String(), "Automatic update requires a real terminal, root") ||
		strings.Contains(out.String(), "Automatic root update is disabled") ||
		strings.Contains(out.String(), "Type UPDATE") || strings.Contains(out.String(), "Update complete") {
		t.Fatalf("immutable release bypassed TTY/root gate: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("noninteractive immutable release changed State: %v", err)
	}
}
