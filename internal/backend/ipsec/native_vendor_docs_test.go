package ipsec

import (
	"runtime"
	"strings"
	"testing"
)

// Official Ubuntu disposable guest: dpkg --verify returns these entries
// for the files excluded by lean package image policy, despite fully
// installed distro packages. Only unavailable docs, NEVER operational
// executables, libs or config files, may be accepted.
func TestVendorOnlyOmittedDistroDocsStrict(t *testing.T) {
	clean := "missing     /usr/share/man/man5/swanctl.conf.5.gz\n" +
		"missing     /usr/share/man/man8/swanctl.8.gz\n" +
		"missing     /usr/share/doc/libstrongswan/NEWS.Debian.gz\n" +
		"missing     /usr/share/doc/libstrongswan/README.gz\n" +
		"missing     /usr/share/man/man5/strongswan.conf.5.gz\n"
	cases := []struct {
		name, raw string
		absent    bool
		allow     bool
	}{
		{"unchanged package no findings", "", true, true},
		{"lean Ubuntu missing only documentation", clean, true, true},
		{"missing doc is actually present", clean, false, false},
		{"missing operational daemon", "missing     /usr/sbin/charon-systemd\n", true, false},
		{"missing plugin shared library", "missing     /usr/lib/ipsec/plugins/libstrongswan.so\n", true, false},
		{"missing runtime configuration", "missing     /etc/swanctl/swanctl.conf\n", true, false},
		{"changed documentation", "??5??????   /usr/share/doc/libstrongswan/README.gz\n", true, false},
		{"changed vendor config", "??5?????? c /etc/strongswan.conf\n", true, false},
		{"removed colon in missing field", "missing    /usr/share/doc/libstrongswan/README.gz\n", true, false},
		{"unexpected stderr-like field", "missing     /usr/share/doc/file\nWARNING\n", true, false},
		{"truncated receipt", "missing     /usr/share/doc/libstrongswan/README.gz", true, false},
		{"traversal under doc", "missing     /usr/share/doc/../../etc/ipsec.conf\n", true, false},
		{"double slash", "missing     /usr/share/man//man5/example.gz\n", true, false},
		{"space", "missing     /usr/share/doc/file name\n", true, false},
		{"control byte", "missing     /usr/share/doc/file\r\n", true, false},
		{"non ASCII", "missing     /usr/share/doc/\u00e9.gz\n", true, false},
		{"unbounded", strings.Repeat("missing     /usr/share/man/man5/a.gz\n", 150), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vendorOnlyOmittedDistroDocs([]byte(tc.raw), func(path string) bool {
				if !strings.HasPrefix(path, "/usr/share/") {
					t.Fatalf("unexpected optional-doc lookup: %q", path)
				}
				return tc.absent
			})
			if got != tc.allow {
				t.Fatalf("verification report %q: allowed=%t wanted %t", tc.name, got, tc.allow)
			}
		})
	}
	if vendorOnlyOmittedDistroDocs(nil, nil) {
		t.Fatal("missing independent absence checker accepted")
	}
}

func TestVendorDistroConfigOwnerMultiarchAttestation(t *testing.T) {
	for _, owner := range []string{
		"libstrongswan", "libstrongswan:" + runtime.GOARCH,
		"strongswan-swanctl", "strongswan-swanctl:" + runtime.GOARCH,
		"libstrongswan-standard-plugins", "charon-systemd",
	} {
		if !vendorDistroConfigOwner(owner) {
			t.Fatalf("official distro configuration owner rejected: %q", owner)
		}
	}
	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	for _, owner := range []string{
		"", "libstrongswan:unknown", "libstrongswan:" + otherArch,
		"libstrongswan:amd64:foreign", "libstrongswan-extra-plugins",
		"outside-package", "outside-package:" + runtime.GOARCH,
	} {
		if vendorDistroConfigOwner(owner) {
			t.Fatalf("foreign or different architecture owner accepted: %q", owner)
		}
	}
}
