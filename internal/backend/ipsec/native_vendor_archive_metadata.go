package ipsec

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// vendorDistroPathProbe is a narrow observation seam. Production always
// uses lstat/readlink on the actual host. Tests can supply disposable,
// synthetic metadata without changing any privileged host paths.
type vendorDistroPathProbe struct {
	lstat    func(string) (os.FileInfo, error)
	readlink func(string) (string, error)
}

func vendorLiveDistroPathMetadata(path string, kind byte) error {
	return vendorLiveDistroPathMetadataWithProbe(path, kind,
		vendorDistroPathProbe{lstat: os.Lstat, readlink: os.Readlink})
}

// Every runtime file and directory in the authenticated .deb must be rooted
// in a root-owned, non-group/world-writable directory chain. Matching signed
// file bytes alone cannot prevent a local unprivileged user from replacing an
// unsafe plugin after attestation. The ONLY intermediate symlinks accepted
// are the exact, conventional root-owned usrmerge aliases.
func vendorLiveDistroPathMetadataWithProbe(
	file string, kind byte, probe vendorDistroPathProbe,
) error {
	return vendorInspectDistroPath(file, kind, probe, 0)
}

func vendorInspectDistroPath(
	file string, kind byte, probe vendorDistroPathProbe, depth int,
) error {
	if probe.lstat == nil || probe.readlink == nil || depth > 8 ||
		file == "/" || !filepath.IsAbs(file) ||
		filepath.Clean(file) != file || strings.ContainsRune(file, '\\') {
		return errors.New("installed distro path identity invalid")
	}
	parts := strings.Split(strings.TrimPrefix(file, "/"), "/")
	// Verify the filesystem root, too: a non-root-controlled ancestor must
	// never permit later replacement of an otherwise immutable signed file.
	root, err := probe.lstat("/")
	if err != nil || !rootControlledExecutableMetadata(root, true) {
		return errors.New("installed distro filesystem root not trusted")
	}
	cur := ""
	for index, component := range parts {
		if component == "" || component == "." || component == ".." {
			return errors.New("installed distro path component invalid")
		}
		cur += "/" + component
		info, err := probe.lstat(cur)
		if err != nil {
			return errors.New("installed distro path metadata unavailable")
		}
		last := index == len(parts)-1
		if info.Mode()&os.ModeSymlink != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return errors.New("installed distro symlink not root-owned")
			}
			target, err := probe.readlink(cur)
			if err != nil || target == "" || strings.ContainsRune(target, '\\') {
				return errors.New("installed distro symlink target unreadable")
			}
			// A package may include an official signed leaf symlink to a
			// library. The caller has ALREADY matched its link text exactly
			// against the authenticated archive.
			if !last && !vendorApprovedUsrmergeAlias(cur, target) {
				return errors.New("unapproved installed distro intermediate symlink")
			}
			if last && kind != tar.TypeSymlink &&
				!(kind == tar.TypeDir && vendorApprovedUsrmergeAlias(cur, target)) {
				return errors.New("unexpected installed distro leaf symlink")
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(cur), target))
			if filepath.IsAbs(target) {
				resolved = filepath.Clean(target)
			}
			if !filepath.IsAbs(resolved) || resolved == cur {
				return errors.New("installed distro symlink escape or loop")
			}
			// A signed leaf symlink may target another trusted package, but
			// it must not point to a file or directory writable by a local
			// unprivileged actor. Documentation symlink targets may have
			// been intentionally omitted by the distro image.
			if last && kind == tar.TypeSymlink && vendorOmittableDistroDoc(file) {
				continue
			}
			targetInfo, err := probe.lstat(resolved)
			if err != nil {
				return errors.New("installed distro symlink destination missing")
			}
			var targetKind byte
			switch {
			case targetInfo.Mode()&os.ModeSymlink != 0:
				targetKind = tar.TypeSymlink
			case targetInfo.IsDir():
				targetKind = tar.TypeDir
			case targetInfo.Mode().IsRegular():
				targetKind = tar.TypeReg
			default:
				return errors.New("installed distro symlink destination type unsupported")
			}
			if err := vendorInspectDistroPath(resolved, targetKind, probe, depth+1); err != nil {
				return err
			}
			continue
		}
		if !last || kind == tar.TypeDir {
			if !rootControlledExecutableMetadata(info, true) {
				return errors.New("installed distro directory not root-controlled")
			}
			continue
		}
		if kind != tar.TypeReg && kind != tar.TypeRegA ||
			!rootControlledExecutableMetadata(info, false) {
			return errors.New("installed distro runtime file not root-controlled")
		}
	}
	return nil
}

func vendorApprovedUsrmergeAlias(file, target string) bool {
	switch file {
	case "/lib":
		return target == "usr/lib"
	case "/lib64":
		return target == "usr/lib64"
	case "/bin":
		return target == "usr/bin"
	case "/sbin":
		return target == "usr/sbin"
	default:
		return false
	}
}

func vendorOmittableDistroDoc(file string) bool {
	return file == "/usr/share/doc" || file == "/usr/share/man" ||
		strings.HasPrefix(file, "/usr/share/doc/") ||
		strings.HasPrefix(file, "/usr/share/man/")
}
