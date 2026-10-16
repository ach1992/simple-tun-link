package ipsec

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// dpkg ownership and dpkg --verify only attest against locally installed
// metadata, which can itself come from a foreign .deb. For consented STOP,
// cross-check live installed files against a byte-identical official .deb,
// anchored to an independently verified distro-signed InRelease -> Packages
// SHA256 -> package archive SHA256. This is read-only for the local host.
type vendorSignedPackage struct {
	name, version, filename, digest, repo string
	size                                  int64
}

func vendorAttestDistroPackages(ctx context.Context, versions map[string]string) error {
	if ctx == nil || ctx.Err() != nil || len(versions) == 0 {
		return errors.New("official package attestation unavailable")
	}
	releaseID, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return errors.New("host distribution identity unavailable")
	}
	var anchor, origin, keyPkg string
	switch {
	case bytes.Contains(append([]byte("\n"), releaseID...), []byte("\nID=ubuntu\n")):
		anchor, origin, keyPkg = "/usr/share/keyrings/ubuntu-archive-keyring.gpg", "Ubuntu", "ubuntu-keyring"
	case bytes.Contains(append([]byte("\n"), releaseID...), []byte("\nID=debian\n")):
		anchor, origin, keyPkg = "/usr/share/keyrings/debian-archive-keyring.gpg", "Debian", "debian-archive-keyring"
	default:
		return errors.New("unsupported distribution archive")
	}
	// Debian 13 ships the historic .gpg name as a package-owned symlink
	// to the root-controlled .pgp archive. Verify both identities, never
	// follow a keyring alias outside the supported distro keyring directory.
	resolved, err := filepath.EvalSymlinks(anchor)
	if err != nil || !strings.HasPrefix(resolved, "/usr/share/keyrings/") {
		return errors.New("distribution keyring alias unresolved")
	}
	meta, err := os.Lstat(resolved)
	if err != nil || !rootControlledExecutableMetadata(meta, false) {
		return errors.New("distribution signing key not root-controlled")
	}
	owner, e1 := vendorReadOnlyCommand(ctx, "/usr/bin/dpkg-query", "-S", "--", anchor)
	if resolved != anchor {
		alias, e := os.Lstat(anchor)
		actualOwner, ownerErr := vendorReadOnlyCommand(ctx, "/usr/bin/dpkg-query", "-S", "--", resolved)
		if e != nil || alias.Mode()&os.ModeSymlink == 0 || ownerErr != nil || !strings.HasPrefix(string(actualOwner), keyPkg+": ") {
			return errors.New("distribution keyring alias not owned by distro")
		}
	}
	status, e2 := vendorReadOnlyCommand(ctx, "/usr/bin/dpkg-query", "-W", "-f="+"$"+"{Status}", "--", keyPkg)
	if e1 != nil || e2 != nil || !strings.HasPrefix(string(owner), keyPkg+": ") || string(status) != "install ok installed" {
		return errors.New("distribution keyring package not authenticated")
	}
	raw, err := vendorArchiveCommand(ctx, 1<<20, "/usr/bin/apt-get", "indextargets")
	if err != nil {
		return errors.New("APT index mapping unavailable")
	}
	matched := make(map[string]vendorSignedPackage)
	trusted := make(map[string]bool)
	for _, target := range vendorAPTTargets(raw) {
		file, signed, relKey, ok := vendorAPTIndexPath(target)
		if !ok {
			continue
		}
		if !trusted[signed] {
			if vendorVerifySignedRelease(ctx, signed, anchor, origin) != nil {
				continue
			}
			trusted[signed] = true
		}
		expected, size, ok := vendorSignedIndexHash(signed, relKey)
		if !ok {
			continue
		}
		found, err := vendorInspectSignedIndex(ctx, file, expected, size, versions, target["Repo-URI"])
		if err != nil {
			return err
		}
		for pkg, ref := range found {
			if prior, exists := matched[pkg]; exists && (prior.digest != ref.digest || prior.size != ref.size) {
				return errors.New("ambiguous official package identity")
			}
			matched[pkg] = ref
		}
	}
	if len(matched) != len(versions) {
		return errors.New("installed version has no signed official archive")
	}
	for name := range versions {
		if err := vendorCompareOfficialPayload(ctx, matched[name]); err != nil {
			return fmt.Errorf("vendor package %s official provenance differs: %w", name, err)
		}
	}
	return nil
}

func vendorArchiveCommand(ctx context.Context, limit int, name string, args ...string) ([]byte, error) {
	switch name {
	case "/usr/bin/apt-get", "/usr/lib/apt/apt-helper", "/usr/bin/gpgv", "/usr/bin/dpkg-deb":
	default:
		return nil, errors.New("unexpected archive tool")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = nativeSystemdFixedEnvironment()
	stdout, stderr := &privateCapture{max: limit}, &privateCapture{max: 2048}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil || stdout.overflow || stderr.overflow {
		return nil, errors.New("archive attestation command failed")
	}
	// gpgv can emit human-readable successful signature diagnostics on stderr;
	// no output is returned or trusted from that channel.
	if name != "/usr/bin/gpgv" && stderr.output.Len() != 0 {
		return nil, errors.New("archive inspection diagnostics")
	}
	return append([]byte(nil), stdout.output.Bytes()...), nil
}

func vendorAPTTargets(raw []byte) []map[string]string {
	var result []map[string]string
	for _, block := range strings.Split(string(raw), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(block), "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if ok {
				fields[k] = v
			}
		}
		if fields["Target-Of"] == "deb" && fields["Identifier"] == "Packages" {
			result = append(result, fields)
		}
	}
	return result
}

func vendorAPTIndexPath(fields map[string]string) (file, release, key string, ok bool) {
	file, component, arch := fields["Filename"], fields["Component"], fields["Architecture"]
	if component == "" || strings.ContainsAny(component, "./ \t") || arch != runtime.GOARCH ||
		!strings.HasPrefix(file, "/var/lib/apt/lists/") || filepath.Clean(file) != file {
		return
	}
	plain := file
	for _, ext := range []string{".lz4", ".xz", ".gz", ".zst", ".bz2"} {
		if strings.HasSuffix(plain, ext) {
			plain = strings.TrimSuffix(plain, ext)
			break
		}
	}
	suffix := "_" + component + "_binary-" + arch + "_Packages"
	if !strings.HasSuffix(plain, suffix) {
		return
	}
	release = strings.TrimSuffix(plain, suffix) + "_InRelease"
	if _, err := os.Lstat(file); err != nil {
		for _, ext := range []string{".lz4", ".xz", ".gz", ".zst", ".bz2"} {
			if _, err := os.Lstat(plain + ext); err == nil {
				file = plain + ext
				break
			}
		}
	}
	for _, p := range []string{file, release} {
		info, err := os.Lstat(p)
		if err != nil || !rootControlledExecutableMetadata(info, false) {
			return "", "", "", false
		}
	}
	return file, release, component + "/binary-" + arch + "/Packages", true
}

func vendorVerifySignedRelease(ctx context.Context, release, anchor, origin string) error {
	if _, err := vendorArchiveCommand(ctx, 512, "/usr/bin/gpgv", "--quiet", "--keyring", anchor, release); err != nil {
		return err
	}
	raw, err := os.ReadFile(release)
	if err != nil || len(raw) > 4<<20 || !bytes.Contains(raw, []byte("\nOrigin: "+origin+"\n")) {
		return errors.New("foreign or incomplete signed Release")
	}
	return nil
}

func vendorSignedIndexHash(release, key string) (digest string, size int64, ok bool) {
	raw, err := os.ReadFile(release)
	if err != nil || len(raw) > 4<<20 {
		return
	}
	on := false
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "SHA256:" {
			on = true
			continue
		}
		if on && (line == "" || line[0] != ' ') {
			break
		}
		if !on {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != key {
			continue
		}
		n, e := strconv.ParseInt(fields[1], 10, 64)
		if e != nil || n <= 0 || n > 300<<20 || len(fields[0]) != 64 {
			return "", 0, false
		}
		if _, e = hex.DecodeString(fields[0]); e != nil || ok {
			return "", 0, false
		}
		digest, size, ok = fields[0], n, true
	}
	return
}

// Parse the entire decompressed index while hashing it. The digest and exact
// length must match the corresponding entry in the signed InRelease.
func vendorInspectSignedIndex(ctx context.Context, file, digest string, expected int64,
	wanted map[string]string, repo string) (map[string]vendorSignedPackage, error) {
	cmd := exec.CommandContext(ctx, "/usr/lib/apt/apt-helper", "cat-file", file)
	cmd.Env = nativeSystemdFixedEnvironment()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.New("APT index stream unavailable")
	}
	stderr := &privateCapture{max: 1024}
	cmd.Stderr = stderr
	if err = cmd.Start(); err != nil {
		return nil, errors.New("APT index decoder unavailable")
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	limit := &io.LimitedReader{R: out, N: expected + 1}
	hasher := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(limit, hasher))
	scanner.Buffer(make([]byte, 16<<10), 512<<10)
	entries := map[string]vendorSignedPackage{}
	fields := map[string]string{}
	finish := func() error {
		name, version, arch := fields["Package"], fields["Version"], fields["Architecture"]
		if wanted[name] != "" && wanted[name] == version && (arch == runtime.GOARCH || arch == "all") {
			n, e := strconv.ParseInt(fields["Size"], 10, 64)
			sha, file := fields["SHA256"], fields["Filename"]
			if e != nil || n < 100 || n > 40<<20 || len(sha) != 64 || !strings.HasPrefix(file, "pool/") ||
				path.Clean(file) != file || strings.Contains(file, "..") {
				return errors.New("invalid signed package index record")
			}
			if _, e := hex.DecodeString(sha); e != nil {
				return errors.New("bad signed package SHA256")
			}
			ref := vendorSignedPackage{name, version, file, sha, repo, n}
			if old, exists := entries[name]; exists && (old.digest != ref.digest || old.size != ref.size) {
				return errors.New("multiple different official archive identities")
			}
			entries[name] = ref
		}
		fields = map[string]string{}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if e := finish(); e != nil {
				return nil, e
			}
		} else if line[0] != ' ' && line[0] != '\t' {
			k, v, ok := strings.Cut(line, ": ")
			if ok {
				fields[k] = v
			}
		}
	}
	if scanner.Err() != nil || limit.N != 1 {
		return nil, errors.New("APT index incomplete or oversized")
	}
	if err := finish(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil || stderr.output.Len() != 0 {
		return nil, errors.New("APT index decompression failed")
	}
	if !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), digest) {
		return nil, errors.New("package index SHA256 not covered by signed Release")
	}
	return entries, nil
}

func vendorCompareOfficialPayload(ctx context.Context, ref vendorSignedPackage) error {
	uri, err := url.Parse(ref.repo)
	if err != nil || (uri.Scheme != "http" && uri.Scheme != "https") || uri.Host == "" || uri.User != nil ||
		strings.ContainsAny(ref.filename, "\\?#") {
		return errors.New("unsupported official archive transport")
	}
	uri.Path = path.Join(uri.Path, ref.filename)
	uri.RawQuery, uri.Fragment = "", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return errors.New("invalid signed archive location")
	}
	client := &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || r.URL.User != nil || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
			return errors.New("untrusted redirect")
		}
		return nil
	}}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("official archive download unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("official archive HTTP response invalid")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, ref.size+1))
	if err != nil || int64(len(data)) != ref.size {
		return errors.New("signed archive size mismatch")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), ref.digest) {
		return errors.New("signed archive digest mismatch")
	}
	return vendorLiveFilesMatchOfficialArchive(ctx, data)
}

// Check the archive content against the live host, not against modifiable
// installed-package md5 metadata. Never execute archive scripts or change dpkg.
func vendorLiveFilesMatchOfficialArchive(ctx context.Context, deb []byte) error {
	// Fully consume the bounded unpacker output BEFORE inspecting it.
	// Streaming tar.Next() while writing the compressed archive to a child
	// can deadlock on early fail-closed returns with a blocked stdin writer.
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-deb", "--fsys-tarfile", "-")
	cmd.Env = nativeSystemdFixedEnvironment()
	cmd.Stdin = bytes.NewReader(deb)
	stdout, stderr := &privateCapture{max: 128 << 20}, &privateCapture{max: 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil || stdout.overflow || stderr.overflow || stderr.output.Len() != 0 {
		return errors.New("bounded official archive extraction failed")
	}
	tr := tar.NewReader(bytes.NewReader(stdout.output.Bytes()))
	count := 0
	for {
		header, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return errors.New("signed payload truncated")
		}
		name := strings.TrimPrefix(header.Name, "./")
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if name == "" || name == "." {
			continue
		}
		if path.Clean(name) != name || path.IsAbs(name) || strings.HasPrefix(name, "../") ||
			strings.Contains(name, "\\") {
			return errors.New("unexpected package archive pathname")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		count++
		if count > 2500 {
			return errors.New("official package inventory too large")
		}
		live := "/" + name
		info, e := os.Lstat(live)
		if errors.Is(e, os.ErrNotExist) && (strings.HasPrefix(live, "/usr/share/doc/") ||
			strings.HasPrefix(live, "/usr/share/man/")) {
			continue
		}
		if e != nil {
			return errors.New("signed runtime file missing")
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if !info.Mode().IsRegular() || info.Size() != header.Size || header.Size < 0 || header.Size > 80<<20 {
				return errors.New("live file size or type differs from official archive")
			}
			signedHash := sha256.New()
			if _, e = io.Copy(signedHash, tr); e != nil {
				return errors.New("signed file read failed")
			}
			file, e := os.Open(live)
			if e != nil {
				return errors.New("live distro file unreadable")
			}
			liveHash := sha256.New()
			_, e = io.Copy(liveHash, io.LimitReader(file, header.Size+1))
			_ = file.Close()
			if e != nil || !bytes.Equal(signedHash.Sum(nil), liveHash.Sum(nil)) {
				return errors.New("installed file differs from signed distro bytes")
			}
		case tar.TypeSymlink:
			link, e := os.Readlink(live)
			if e != nil || link != header.Linkname {
				return errors.New("installed symlink differs from signed distro archive")
			}
		default:
			return errors.New("unsupported official package member type")
		}
	}
	if count == 0 {
		return errors.New("empty vendor package archive")
	}
	return nil
}
