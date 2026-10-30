package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Real official GitHub release responses include verbose notes and full asset
// metadata, even though the operator menu only needs a small subset. A valid
// 15-entry catalogue must not become unavailable merely because published
// release notes have grown beyond the former 256 KiB response budget.
func TestMenuReleaseCatalogueAcceptsValidLargeOfficialResponse(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	releases := make([]map[string]any, 0, 15)
	for i := 0; i < 15; i++ {
		release := sampleOfficialRelease(fmt.Sprintf("v0.1.%d", 14-i),
			now.Add(-time.Duration(i)*time.Hour))
		release.ID = int64(i + 100)
		release.Prerelease = false
		release.Immutable = boolPointer(true)
		raw, err := json.Marshal(release)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatal(err)
		}
		wire["body"] = strings.Repeat("Detailed safe release and offline migration notes. ", 550)
		releases = append(releases, wire)
	}
	payload, err := json.Marshal(releases)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= 256*1024 || len(payload) > 1024*1024 {
		t.Fatalf("realistic release fixture must be 256 KiB to 1 MiB, got %d bytes", len(payload))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Error("menu lost the verified official catalogue request contract")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	got, err := fetchMenuOfficialReleases(context.Background(), server.Client(), server.URL)
	if err != nil || len(got) != 10 {
		t.Fatalf("valid official release catalogue refused: count=%d err=%v", len(got), err)
	}
	if got[0].TagName != "v0.1.14" || got[9].TagName != "v0.1.5" {
		t.Fatalf("latest published releases were not sorted/limited correctly: %q .. %q",
			got[0].TagName, got[9].TagName)
	}
}
