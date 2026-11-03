package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Optional manual network smoke. Normal CI deliberately remains hermetic;
// release source availability and HTTP redirect behavior can change with
// GitHub/CDN and must not turn ordinary unit test runs into network tests.
func TestOptInPinnedCompanionLiveHTTPS(t *testing.T) {
	if os.Getenv("STL_TEST_COMPANION_HTTPS") != "1" {
		t.Skip("set STL_TEST_COMPANION_HTTPS=1 for live source acceptance")
	}
	for _, kind := range []menuCompanionKind{menuCompanionWSS, menuCompanionQUIC} {
		t.Run(string(kind), func(t *testing.T) {
			spec, ok := menuPinnedCompanion(kind, runtime.GOARCH)
			if !ok {
				t.Skip("architecture has no published pinned companion")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), spec.asset)
			if err := menuDownloadPinnedCompanion(ctx, spec, path); err != nil {
				t.Fatalf("published asset failed pinned HTTPS acquisition: %v", err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Size() <= 1024 || info.Mode().Perm() != 0600 {
				t.Fatalf("unsafe downloaded asset: %v / %v", info, err)
			}
		})
	}
}
