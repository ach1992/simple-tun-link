// stl-mirror-signer publishes detached Ed25519 authentication for an already
// verified, versioned static STL mirror. The private key never leaves this
// trusted preparing machine and is never served by the mirror.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const purpose = "stl-static-mirror-release/v1"

var (
	tagPattern    = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	hashPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type release struct {
	Purpose         string `json:"purpose"`
	Sequence        uint64 `json:"sequence"`
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	BootstrapSHA256 string `json:"bootstrap_sha256"`
	KeyFingerprint  string `json:"key_fingerprint"`
}

func safeRegular(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("required source is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 ||
		info.Mode().Perm()&0o022 != 0 ||
		private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file owner/permissions/hardlinks untrusted")
	}
	return os.ReadFile(path)
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := safeRegular(path, true)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected private Ed25519 PKCS8 PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("unsupported publisher key type")
	}
	return key, nil
}

func readManifestCommit(raw []byte, tag string) (string, error) {
	lines := strings.Split(string(raw), "\n")
	values := map[string]string{}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "commit" && key != "version" && key != "project" && key != "mode" && key != "source" {
			continue
		}
		if _, exists := values[key]; exists {
			return "", errors.New("duplicate release manifest identity")
		}
		values[key] = value
	}
	if values["project"] != "simple-tun-link" || values["version"] != tag ||
		values["mode"] != "tag" || values["source"] != "https://github.com/ach1992/simple-tun-link" ||
		!commitPattern.MatchString(values["commit"]) {
		return "", errors.New("mirror release manifest identity invalid")
	}
	return values["commit"], nil
}

func signRelease(root, tag, keyPath, trustSums, trustBootstrap string, sequence uint64) (string, error) {
	if !tagPattern.MatchString(tag) || !hashPattern.MatchString(trustSums) ||
		!hashPattern.MatchString(trustBootstrap) || sequence == 0 {
		return "", errors.New("invalid signed release identity, sequence or trusted checksum")
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil || root != real {
		return "", errors.New("mirror root must be an existing canonical directory")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("mirror root is not owner-controlled")
	}
	pk, err := readPrivateKey(keyPath)
	if err != nil {
		return "", err
	}
	bootstrap, err := safeRegular(filepath.Join(root, "install.sh"), false)
	if err != nil {
		return "", err
	}
	sums, err := safeRegular(filepath.Join(root, "releases", tag, "SHA256SUMS"), false)
	if err != nil {
		return "", err
	}
	actualSums := sha256.Sum256(sums)
	if hex.EncodeToString(actualSums[:]) != trustSums {
		return "", errors.New("mirror manifest does not match independently trusted release-wide SHA256")
	}
	manifest, err := safeRegular(filepath.Join(root, "releases", tag, "BUILD-MANIFEST.txt"), false)
	if err != nil {
		return "", err
	}
	// The release commit enters the root-of-trust decision. An attacker who
	// can modify the staging tree after prepare-mirror.sh MUST NOT swap the
	// BUILD-MANIFEST commit while leaving the independently pinned
	// release-wide SHA256SUMS bytes unmodified.
	manifestSum := sha256.Sum256(manifest)
	manifestDigest := hex.EncodeToString(manifestSum[:])
	seenManifest := false
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != "BUILD-MANIFEST.txt" {
			continue
		}
		if seenManifest || fields[0] != manifestDigest {
			return "", errors.New("release commit manifest differs from trusted release-wide checksum")
		}
		seenManifest = true
	}
	if !seenManifest {
		return "", errors.New("trusted release has no authenticated commit manifest")
	}
	commit, err := readManifestCommit(manifest, tag)
	if err != nil {
		return "", err
	}
	pub := pk.Public().(ed25519.PublicKey)
	fp := sha256.Sum256(pub)
	digest := sha256.Sum256(bootstrap)
	if hex.EncodeToString(digest[:]) != trustBootstrap {
		return "", errors.New("mirror bootstrap differs from independently prepared trusted SHA256")
	}
	obj := release{Purpose: purpose, Sequence: sequence, Version: tag, Commit: commit,
		BootstrapSHA256: hex.EncodeToString(digest[:]), KeyFingerprint: hex.EncodeToString(fp[:])}
	raw, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "", err
	}
	raw = append(raw, '\n')
	sig := ed25519.Sign(pk, raw)
	// Fail without overwriting or silently changing a previously published
	// signature. This tool only adds files to a NEW prepared mirror tree.
	jsonPath := filepath.Join(root, "release.json")
	sigPath := filepath.Join(root, "release.sig")
	for _, name := range []string{jsonPath, sigPath} {
		_, statErr := os.Lstat(name)
		if statErr == nil {
			return "", errors.New("signed metadata already exists; prepare a new tree")
		}
		if !os.IsNotExist(statErr) {
			return "", errors.New("metadata destination unavailable")
		}
	}
	if err := writeExclusive(jsonPath, raw); err != nil {
		return "", err
	}
	sigText := []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
	if err := writeExclusive(sigPath, sigText); err != nil {
		_ = os.Remove(jsonPath)
		return "", err
	}
	d, err := os.Open(root)
	if err != nil {
		return "", err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return "", err
	}
	return fmt.Sprintf("KEY_FINGERPRINT=%s\nRELEASE_VERSION=%s\nRELEASE_SEQUENCE=%d\nBOOTSTRAP_SHA256=%s\nCOMMIT=%s",
		obj.KeyFingerprint, tag, sequence, obj.BootstrapSHA256, commit), nil
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// Trusted release metadata MUST be readable by an unprivileged HTTPS
	// web-server account. The publisher's PRIVATE signing key is held
	// separately with strict 0600 permission and is never copied here.
	// Apply the public mode explicitly even when the invoking operator
	// appropriately uses umask 077 for private key material.
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func main() {
	root := flag.String("mirror-dir", "", "new prepared mirror directory")
	tag := flag.String("tag", "", "official immutable Stable tag")
	key := flag.String("private-key", "", "private Ed25519 PKCS8 PEM")
	sums := flag.String("trusted-sums-sha256", "", "independently trusted official SHA256SUMS digest")
	bootstrap := flag.String("trusted-bootstrap-sha256", "", "trusted bootstrap digest from prepare-mirror.sh")
	sequenceText := flag.String("sequence", "", "strictly increasing publication sequence")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	seq, err := strconv.ParseUint(*sequenceText, 10, 64)
	if err != nil || seq == 0 {
		fmt.Fprintln(os.Stderr, "invalid publisher sequence")
		os.Exit(2)
	}
	msg, err := signRelease(*root, *tag, *key, *sums, *bootstrap, seq)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signed mirror publication rejected:", err)
		os.Exit(1)
	}
	fmt.Println(msg)
	fmt.Println("Publish release.json and release.sig only after all versioned release assets and root install.sh are stable.")
	fmt.Println("Distribute the public PEM key fingerprint through an INDEPENDENT trusted channel, never by relying on the mirror.")
}
