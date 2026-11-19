package masquehost

import (
	"os"
	"testing"
)

func TestMASQUEHostCanonicalToolPathIsRegularOnSupportedLinux(t *testing.T) {
	if os.Getenv("CI") == "dont-check" {
		t.Skip("not a supported Linux system")
	}
	info, err := os.Lstat("/usr/bin/ip")
	if err != nil {
		t.Skipf("ip binary not installed in this local environment: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		t.Fatal("canonical iproute2 executable is not a trustworthy regular file")
	}
}
