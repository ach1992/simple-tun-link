package ipsec

import (
	"context"
	"os"
	"testing"
	"time"
)

// Optional non-privileged positive proof against the current development
// machine's official APT index and an already installed benign package.
// Never installs, stops, configures, or changes any host service.
func TestOfficialArchiveReadOnlySmoke(t *testing.T) {
	if os.Getenv("STL_TEST_OFFICIAL_ARCHIVE") != "1" {
		t.Skip("opt-in read-only distro archive smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	version, err := vendorInstalledVersion(ctx, "iproute2")
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorAttestDistroPackages(ctx, map[string]string{"iproute2": version}); err != nil {
		t.Fatal(err)
	}
}
