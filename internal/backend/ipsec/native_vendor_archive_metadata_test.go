package ipsec

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type vendorFixtureInfo struct {
	os.FileInfo
	mode os.FileMode
	uid  uint32
}

func (info vendorFixtureInfo) Mode() os.FileMode { return info.mode }
func (info vendorFixtureInfo) IsDir() bool       { return info.mode.IsDir() }
func (info vendorFixtureInfo) Sys() any          { return &syscall.Stat_t{Uid: info.uid} }

type vendorFixturePathEntry struct {
	mode os.FileMode
	uid  uint32
	link string
}

func vendorFixtureRootedPaths() map[string]vendorFixturePathEntry {
	dir := os.ModeDir | 0o755
	return map[string]vendorFixturePathEntry{
		"/":                                {mode: dir},
		"/usr":                             {mode: dir},
		"/usr/lib":                         {mode: dir},
		"/usr/lib/ipsec":                   {mode: dir},
		"/usr/lib/ipsec/plugins":           {mode: dir},
		"/usr/lib/ipsec/plugins/test.so":   {mode: 0o644},
		"/usr/lib/ipsec/plugins/test.so.1": {mode: 0o644},
		"/lib":                             {mode: os.ModeSymlink | 0o777, link: "usr/lib"},
		"/lib/ipsec":                       {mode: dir},
		"/lib/ipsec/plugins":               {mode: dir},
		"/lib/ipsec/plugins/test.so":       {mode: 0o644},
	}
}

func vendorFixtureProbe(entries map[string]vendorFixturePathEntry) vendorDistroPathProbe {
	return vendorDistroPathProbe{
		lstat: func(file string) (os.FileInfo, error) {
			entry, ok := entries[file]
			if !ok {
				return nil, os.ErrNotExist
			}
			return vendorFixtureInfo{mode: entry.mode, uid: entry.uid}, nil
		},
		readlink: func(file string) (string, error) {
			entry, ok := entries[file]
			if !ok || entry.mode&os.ModeSymlink == 0 {
				return "", errors.New("not a symlink")
			}
			return entry.link, nil
		},
	}
}

func TestVendorOfficialRuntimeMetadataRootControlled(t *testing.T) {
	const file = "/usr/lib/ipsec/plugins/test.so"
	dir := os.ModeDir | 0o755
	type mutation func(map[string]vendorFixturePathEntry)
	cases := []struct {
		name   string
		file   string
		kind   byte
		modify mutation
		pass   bool
	}{
		{"root controlled plugin", file, tar.TypeReg, nil, true},
		{"root controlled directory", "/usr/lib/ipsec/plugins", tar.TypeDir, nil, true},
		{"ordinary usrmerge path", "/lib/ipsec/plugins/test.so", tar.TypeReg, nil, true},
		{"root controlled library symlink", file, tar.TypeSymlink, func(m map[string]vendorFixturePathEntry) {
			m[file] = vendorFixturePathEntry{mode: os.ModeSymlink | 0o777, link: "test.so.1"}
		}, true},
		{"world writable plugin despite original signed bytes", file, tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m[file] = vendorFixturePathEntry{mode: 0o666}
		}, false},
		{"group writable plugin", file, tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m[file] = vendorFixturePathEntry{mode: 0o664}
		}, false},
		{"foreign plugin owner", file, tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m[file] = vendorFixturePathEntry{mode: 0o644, uid: 65534}
		}, false},
		{"world writable plugin directory", file, tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m["/usr/lib/ipsec/plugins"] = vendorFixturePathEntry{mode: os.ModeDir | 0o777}
		}, false},
		{"group writable ancestor", file, tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m["/usr/lib"] = vendorFixturePathEntry{mode: os.ModeDir | 0o775}
		}, false},
		{"foreign parent ownership", file, tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m["/usr/lib/ipsec"] = vendorFixturePathEntry{mode: dir, uid: 65534}
		}, false},
		{"unsafe filesystem root", file, tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m["/"] = vendorFixturePathEntry{mode: os.ModeDir | 0o777}
		}, false},
		{"unexpected intermediate symlink", file, tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m["/usr/lib/ipsec"] = vendorFixturePathEntry{mode: os.ModeSymlink | 0o777, link: "../ipsec"}
		}, false},
		{"non-root-owned usrmerge alias", "/lib/ipsec/plugins/test.so", tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m["/lib"] = vendorFixturePathEntry{mode: os.ModeSymlink | 0o777, uid: 65534, link: "usr/lib"}
		}, false},
		{"unapproved usrmerge alias", "/lib/ipsec/plugins/test.so", tar.TypeReg, func(m map[string]vendorFixturePathEntry) {
			m["/lib"] = vendorFixturePathEntry{mode: os.ModeSymlink | 0o777, link: "../usr/lib"}
		}, false},
		{"untrusted signed symlink destination", file, tar.TypeSymlink, func(m map[string]vendorFixturePathEntry) {
			m[file] = vendorFixturePathEntry{mode: os.ModeSymlink | 0o777, link: "test.so.1"}
			m["/usr/lib/ipsec/plugins/test.so.1"] = vendorFixturePathEntry{mode: 0o666}
		}, false},
		{"foreign signed symlink owner", file, tar.TypeSymlink, func(m map[string]vendorFixturePathEntry) {
			m[file] = vendorFixturePathEntry{mode: os.ModeSymlink | 0o777, uid: 65534, link: "test.so.1"}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := vendorFixtureRootedPaths()
			if tc.modify != nil {
				tc.modify(entries)
			}
			err := vendorLiveDistroPathMetadataWithProbe(tc.file, tc.kind, vendorFixtureProbe(entries))
			if (err == nil) != tc.pass {
				t.Fatalf("trusted=%v, wanted=%v; error=%v", err == nil, tc.pass, err)
			}
		})
	}
}

func TestVendorArchiveRejectsInsecureDirectoryEntry(t *testing.T) {
	deb, _ := vendorBuildDisposableDeb(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sawDirectory := false
	err := vendorLiveFilesMatchOfficialArchiveWithPathCheck(ctx, deb,
		func(file string, kind byte) error {
			if kind == tar.TypeDir {
				sawDirectory = true
				return errors.New("unsafe tar directory path")
			}
			return nil
		})
	if !sawDirectory || err == nil {
		t.Fatalf("directory metadata skipped: saw=%v, error=%v", sawDirectory, err)
	}
}

func TestVendorOmittedDocumentationStillNarrow(t *testing.T) {
	for _, tc := range []struct {
		file    string
		allowed bool
	}{
		{"/usr/share/doc", true},
		{"/usr/share/doc/pkg/README", true},
		{"/usr/share/man/man1/sample.1", true},
		{"/usr/share/doc-alternate/README", false},
		{"/usr/lib/ipsec/plugins/sample.so", false},
		{"/etc/strongswan.d/config.conf", false},
	} {
		t.Run(strings.TrimPrefix(tc.file, "/"), func(t *testing.T) {
			if got := vendorOmittableDistroDoc(tc.file); got != tc.allowed {
				t.Fatalf("omission allowed=%v, want %v", got, tc.allowed)
			}
		})
	}
}
