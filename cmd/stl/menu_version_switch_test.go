package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/version"
)

func TestMenuStableDowngradeShowsRealActionAndRootTTYBoundary(t *testing.T) {
	old := version.Version
	version.Version = "v0.1.12"
	t.Cleanup(func() { version.Version = old })
	rel := sampleOfficialRelease("v0.1.9", time.Now())
	rel.ID, rel.Immutable, rel.Prerelease = 721, boolPointer(true), false
	var out, errOut bytes.Buffer
	root := filepath.Join(t.TempDir(), "absent")
	options := &runtimeOptions{stateRoot: root, menuReleases: func(context.Context) ([]menuOfficialRelease, error) {
		return []menuOfficialRelease{rel}, nil
	}}
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader("6\n1\n8\n"), &out, &errOut, options)
	if code != 0 || errOut.Len() != 0 ||
		!strings.Contains(out.String(), "downgrade (requires empty Links)") ||
		!strings.Contains(out.String(), "Automatic update requires a real terminal") ||
		strings.Contains(out.String(), "Type DOWNGRADE") ||
		strings.Contains(out.String(), "Version change complete") {
		t.Fatalf("downgrade not safely handled: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("readonly menu changed state: %v", err)
	}
}

func TestKnownStableDowngradeContractMatrix(t *testing.T) {
	for _, tc := range []struct {
		current, target string
		allowed         bool
	}{
		{"v0.1.12", "v0.1.9", true},
		{"v0.1.12", "v0.1.10", true},
		{"v0.1.12", "v0.1.12", false},
		{"v0.1.9", "v0.1.12", false},
		{"v0.1.12", "v0.1.7", false},
		{"v0.1.12", "v0.2.1", false},
		{"v0.1.12", "v0.1.13", false},
		{"v0.1.12", "v0.1.12-rc.2", false},
		{"dev-abcdef", "v0.1.9", false},
	} {
		if got := menuStablePatchDowngrade(tc.current, tc.target); got != tc.allowed {
			t.Fatalf("%s->%s got %v want %v", tc.current, tc.target, got, tc.allowed)
		}
	}
}

func TestExactOfficialReleaseAdmissionIsNotTrustByName(t *testing.T) {
	valid := sampleOfficialRelease("v0.1.9", time.Now())
	valid.ID, valid.Immutable, valid.Prerelease = 424, boolPointer(true), false
	for _, tc := range []struct {
		name   string
		modify func(*menuOfficialRelease)
		valid  bool
	}{
		{"official complete immutable", func(*menuOfficialRelease) {}, true},
		{"wrong release tag", func(r *menuOfficialRelease) { r.TagName = "v0.1.10" }, false},
		{"incomplete artifacts", func(r *menuOfficialRelease) { r.Assets = nil }, false},
		{"draft", func(r *menuOfficialRelease) { r.Draft = true }, false},
		{"missing published", func(r *menuOfficialRelease) { r.PublishedAt = time.Time{} }, false},
		{"mutable release", func(r *menuOfficialRelease) { r.Immutable = boolPointer(false) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rel := valid
			tc.modify(&rel)
			payload, _ := json.Marshal(rel)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Header.Get("Accept") != "application/vnd.github+json" {
					t.Error("release lookup did not use official media type")
				}
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			got, err := fetchMenuReleaseTagAt(context.Background(), server.Client(), server.URL, "v0.1.9")
			if (err == nil) != tc.valid {
				t.Fatalf("lookup trust=%t error=%v", tc.valid, err)
			}
			if tc.valid && menuReleaseImmutable(got) != (tc.name != "mutable release") {
				t.Fatalf("incorrect immutability: %+v", got)
			}
		})
	}
	if _, err := fetchMenuReleaseTagAt(context.Background(), http.DefaultClient, "http://localhost", "../v0.1.9"); err == nil {
		t.Fatal("invalid tag was queried")
	}
}
