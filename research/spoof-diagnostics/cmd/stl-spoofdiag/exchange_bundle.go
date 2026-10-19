package main

// Offline case-evidence envelopes have NO network side effects. They bind
// pre-existing signed Field artifacts to an operator-selected case only when
// the independent node exports its bundle; they are not pre-run permission.
import (
	"archive/zip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	exchangeFormat             = "sdx-evidence-v1"
	exchangeManifestFile       = "SDX-MANIFEST.json"
	exchangeDefaultBase        = "/root/stl-spoofdiag/exchange"
	exchangeMaxEntries         = 50000
	exchangeMaxFile            = 8 << 20
	exchangeMaxTotal     int64 = 1 << 30
)

var (
	exchangeIDPattern     = regexp.MustCompile("^[0-9a-f]{32}$")
	exchangeDigestPattern = regexp.MustCompile("^[0-9a-f]{64}$")
	exchangeBatchPath     = regexp.MustCompile("^batches/batch-[0-9]{5}\\.json$")
	exchangeRunPath       = regexp.MustCompile("^runs/batch-[0-9]{5}/attempt-[0-9]{4}/(challenge|grant|sender|receipt)\\.json$")
)

type exchangeFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type exchangeManifest struct {
	Format         string         `json:"format"`
	CaseID         string         `json:"case_id"`
	Direction      string         `json:"direction"`
	CampaignID     string         `json:"campaign_id"`
	CampaignSHA256 string         `json:"campaign_sha256"`
	Node           string         `json:"node"`
	ExportedUTC    string         `json:"exported_utc"`
	Role           string         `json:"role"`
	Files          []exchangeFile `json:"files"`
}

type signedExchangeManifest struct {
	Manifest           exchangeManifest `json:"manifest"`
	NodeCertificatePEM string           `json:"node_certificate_pem"`
	SignatureHex       string           `json:"signature_hex"`
}

type exchangeBundle struct {
	Manifest     exchangeManifest
	Digest       string
	Identity     string
	SignerSHA256 string
	Source       string
	Files        map[string][]byte
}

func exchangeSlot(direction, role string) (string, string, error) {
	var sender, receiver string
	switch direction {
	case "A_TO_B":
		sender, receiver = "A", "B"
	case "B_TO_A":
		sender, receiver = "B", "A"
	default:
		return "", "", errors.New("unknown case direction")
	}
	switch role {
	case "sender":
		return sender, "send", nil
	case "receiver":
		return receiver, "recv", nil
	default:
		return "", "", errors.New("bundle role must be sender or receiver")
	}
}

func exchangeBundleName(m exchangeManifest) string {
	part := "AB"
	if m.Direction == "B_TO_A" {
		part = "BA"
	}
	_, suffix, _ := exchangeSlot(m.Direction, m.Role)
	return fmt.Sprintf("SDX-%s-%s-%s-%s.zip", m.CaseID, part, m.Node, suffix)
}

func exchangeFileLimit(name string) int64 {
	if name == "campaign.json" {
		return exchangeMaxFile
	}
	return fieldMaxControl
}

func exchangeValidPath(name, role string) bool {
	if name == "campaign.json" || exchangeBatchPath.MatchString(name) {
		return true
	}
	m := exchangeRunPath.FindStringSubmatch(name)
	if m == nil {
		return false
	}
	switch m[1] {
	case "challenge", "grant":
		return true
	case "sender":
		return role == "sender"
	case "receipt":
		return role == "receiver"
	}
	return false
}

func exchangeValidateManifest(m exchangeManifest) error {
	if m.Format != exchangeFormat || !exchangeIDPattern.MatchString(m.CaseID) ||
		!exchangeIDPattern.MatchString(m.CampaignID) {
		return errors.New("unsupported exchange format or malformed case/campaign ID")
	}
	expectedNode, _, err := exchangeSlot(m.Direction, m.Role)
	if err != nil || m.Node != expectedNode {
		return errors.New("exchange node, direction or role mismatch")
	}
	if !exchangeDigestPattern.MatchString(m.CampaignSHA256) {
		return errors.New("invalid campaign digest")
	}
	when, err := time.Parse(time.RFC3339Nano, m.ExportedUTC)
	if err != nil || when.After(time.Now().Add(60*time.Second)) {
		return errors.New("invalid exchange export declaration time")
	}
	if len(m.Files) < 2 || len(m.Files) > exchangeMaxEntries {
		return errors.New("exchange file list is empty or exceeds resource policy")
	}
	var last string
	var total int64
	hasCampaign := false
	for _, f := range m.Files {
		if f.Path <= last || !exchangeValidPath(f.Path, m.Role) ||
			f.Size < 1 || f.Size > exchangeFileLimit(f.Path) ||
			!exchangeDigestPattern.MatchString(f.SHA256) {
			return fmt.Errorf("invalid, duplicate or unsorted exchange entry: %q", f.Path)
		}
		digest, err := hex.DecodeString(f.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("invalid digest for %s", f.Path)
		}
		last = f.Path
		total += f.Size
		if total > exchangeMaxTotal {
			return errors.New("exchange decompression budget exceeded")
		}
		if f.Path == "campaign.json" {
			hasCampaign = true
			if f.SHA256 != m.CampaignSHA256 {
				return errors.New("campaign digest differs from manifest entry")
			}
		}
	}
	if !hasCampaign {
		return errors.New("bundle missing immutable campaign manifest")
	}
	return nil
}

func exchangeSHA(data []byte) string {
	b := sha256.Sum256(data)
	return hex.EncodeToString(b[:])
}

func exchangeReadCampaignFiles(dir, role string) (campaignManifest, map[string][]byte, error) {
	m, err := readCampaign(dir)
	if err != nil {
		return m, nil, err
	}
	files := make(map[string][]byte)
	add := func(rel string) error {
		if !exchangeValidPath(rel, role) {
			return fmt.Errorf("refusing unrecognized exchange path %q", rel)
		}
		data, err := readSmallRegular(filepath.Join(dir, filepath.FromSlash(rel)), exchangeFileLimit(rel))
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	}
	if err := add("campaign.json"); err != nil {
		return m, nil, err
	}
	for _, batch := range m.Batches {
		if err := add(filepath.ToSlash(batch.File)); err != nil {
			return m, nil, err
		}
		latest, _, err := latestCampaignAttempt(dir, batch.Number)
		if err != nil {
			return m, nil, err
		}
		for n := 1; n <= latest; n++ {
			rel := fmt.Sprintf("runs/batch-%05d/attempt-%04d/", batch.Number, n)
			for _, filename := range []string{"challenge.json", "grant.json"} {
				full := filepath.Join(dir, filepath.FromSlash(rel+filename))
				if _, err := os.Lstat(full); err == nil {
					if err := add(rel + filename); err != nil {
						return m, nil, err
					}
				} else if !os.IsNotExist(err) {
					return m, nil, err
				}
			}
			proof := "sender.json"
			if role == "receiver" {
				proof = "receipt.json"
			}
			full := filepath.Join(dir, filepath.FromSlash(rel+proof))
			if _, err := os.Lstat(full); err == nil {
				if err := add(rel + proof); err != nil {
					return m, nil, err
				}
			} else if !os.IsNotExist(err) {
				return m, nil, err
			}
		}
	}
	return m, files, nil
}

func exchangeSignBundle(caseID, dir, role, certPath, keyPath, caPath, out string) (exchangeManifest, error) {
	var empty exchangeManifest
	if !exchangeIDPattern.MatchString(caseID) {
		return empty, errors.New("case-id must be 32 lowercase hex characters")
	}
	m, files, err := exchangeReadCampaignFiles(dir, role)
	if err != nil {
		return empty, err
	}
	node, _, err := exchangeSlot(m.Direction, role)
	if err != nil {
		return empty, err
	}
	usage := x509.ExtKeyUsageClientAuth
	if role == "receiver" {
		usage = x509.ExtKeyUsageServerAuth
	}
	cert, _, err := checkLocalFieldCredential(certPath, keyPath, caPath, node, usage)
	if err != nil {
		return empty, err
	}
	result := exchangeManifest{Format: exchangeFormat, CaseID: caseID, Direction: m.Direction,
		CampaignID: m.CampaignID, Node: node, Role: role,
		CampaignSHA256: exchangeSHA(files["campaign.json"]), ExportedUTC: time.Now().UTC().Format(time.RFC3339Nano)}
	for name, data := range files {
		result.Files = append(result.Files, exchangeFile{Path: name, SHA256: exchangeSHA(data), Size: int64(len(data))})
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	if err := exchangeValidateManifest(result); err != nil {
		return empty, err
	}
	pemText, sig, err := signatureFromCredential(result, cert)
	if err != nil {
		return empty, err
	}
	env := signedExchangeManifest{Manifest: result, NodeCertificatePEM: pemText, SignatureHex: sig}
	if err := exchangeWriteZipNew(out, env, files); err != nil {
		return empty, err
	}
	return result, nil
}

func exchangeWriteZipNew(out string, env signedExchangeManifest, files map[string][]byte) error {
	dir := filepath.Dir(out)
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("exchange output directory must exist and be private (0700)")
	}
	if _, err := os.Lstat(out); err == nil {
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(dir, ".sdx-export-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	put := func(name string, data []byte) error {
		h := &zip.FileHeader{Name: name, Method: zip.Store}
		h.SetMode(0600)
		h.Modified = time.Unix(0, 0).UTC()
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	meta, err := json.Marshal(env)
	if err == nil {
		err = put(exchangeManifestFile, meta)
	}
	if err == nil {
		for _, item := range env.Manifest.Files {
			if err = put(item.Path, files[item.Path]); err != nil {
				break
			}
		}
	}
	if closeErr := zw.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), out); err != nil {
		return err
	}
	if df, err := os.Open(dir); err == nil {
		defer df.Close()
		if err := df.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func exchangeDecodeStrict(data []byte, target any) error {
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing exchange JSON")
	}
	return nil
}

// Open ZIP only for bounded reads. Paths never become filesystem destinations:
// no extraction, code execution or network I/O occurs during verification.
func exchangeOpenBundle(filename, caPath string) (*exchangeBundle, error) {
	st, err := os.Lstat(filename)
	if err != nil || !st.Mode().IsRegular() || st.Size() > exchangeMaxTotal {
		return nil, errors.New("bundle must be a bounded regular file (no symlink)")
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("bundle file changed during open")
	}
	initialHash := sha256.New()
	if _, err := io.Copy(initialHash, io.LimitReader(f, exchangeMaxTotal+1)); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(f, opened.Size())
	if err != nil {
		return nil, err
	}
	if len(zr.File) < 3 || len(zr.File) > exchangeMaxEntries+1 {
		return nil, errors.New("unexpected bundle entry count")
	}
	index := make(map[string]*zip.File, len(zr.File))
	var total int64
	for _, item := range zr.File {
		name := item.Name
		if name == "" || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name ||
			strings.HasPrefix(name, "../") || name == ".." || !item.Mode().IsRegular() ||
			item.UncompressedSize64 == 0 || item.UncompressedSize64 > exchangeMaxFile {
			return nil, fmt.Errorf("unsafe exchange archive entry %q", name)
		}
		// Deliberately cap pathological decompression ratios even when
		// uncompressed file sizes individually fit within policy.
		if item.CompressedSize64 == 0 || item.UncompressedSize64 > 1000*(item.CompressedSize64+1) {
			return nil, fmt.Errorf("unsafe compression ratio for %q", name)
		}
		if _, exists := index[name]; exists {
			return nil, fmt.Errorf("duplicate exchange archive entry %q", name)
		}
		total += int64(item.UncompressedSize64)
		if total > exchangeMaxTotal {
			return nil, errors.New("archive decompression budget exceeded")
		}
		index[name] = item
	}
	manifestZip, ok := index[exchangeManifestFile]
	if !ok || manifestZip.UncompressedSize64 > exchangeMaxFile {
		return nil, errors.New("signed exchange manifest is missing or oversized")
	}
	read := func(z *zip.File, maxSize int64) ([]byte, error) {
		if int64(z.UncompressedSize64) > maxSize {
			return nil, errors.New("declared ZIP entry exceeds policy")
		}
		r, err := z.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		b, err := io.ReadAll(io.LimitReader(r, maxSize+1))
		if err != nil || int64(len(b)) > maxSize || uint64(len(b)) != z.UncompressedSize64 {
			return nil, errors.New("truncated, oversized or invalid compressed content")
		}
		return b, nil
	}
	meta, err := read(manifestZip, exchangeMaxFile)
	if err != nil {
		return nil, err
	}
	var env signedExchangeManifest
	if err := exchangeDecodeStrict(meta, &env); err != nil {
		return nil, err
	}
	if err := exchangeValidateManifest(env.Manifest); err != nil {
		return nil, err
	}
	if len(index) != len(env.Manifest.Files)+1 {
		return nil, errors.New("unexpected or missing ZIP files")
	}
	roots, err := certificateRoots(caPath)
	if err != nil {
		return nil, err
	}
	signedAt, err := time.Parse(time.RFC3339Nano, env.Manifest.ExportedUTC)
	if err != nil {
		return nil, err
	}
	usage := x509.ExtKeyUsageClientAuth
	if env.Manifest.Role == "receiver" {
		usage = x509.ExtKeyUsageServerAuth
	}
	leaf, err := verifyFieldSignature(env.Manifest, env.NodeCertificatePEM,
		env.SignatureHex, roots, env.Manifest.Node, signedAt, usage)
	if err != nil {
		return nil, fmt.Errorf("untrusted signed exchange manifest: %w", err)
	}
	files := make(map[string][]byte, len(env.Manifest.Files))
	for _, item := range env.Manifest.Files {
		z, ok := index[item.Path]
		if !ok || uint64(item.Size) != z.UncompressedSize64 ||
			!exchangeValidPath(item.Path, env.Manifest.Role) {
			return nil, fmt.Errorf("exchange entry absent, wrong role or wrong size: %q", item.Path)
		}
		b, err := read(z, exchangeFileLimit(item.Path))
		if err != nil || exchangeSHA(b) != item.SHA256 {
			return nil, fmt.Errorf("exchange entry fails integrity: %s: %v", item.Path, err)
		}
		files[item.Path] = b
	}
	var campaign campaignManifest
	if err := exchangeDecodeStrict(files["campaign.json"], &campaign); err != nil {
		return nil, err
	}
	if campaign.CampaignID != env.Manifest.CampaignID || campaign.Direction != env.Manifest.Direction ||
		campaign.SchemaVersion != schema ||
		(campaign.Sender != "A" && campaign.Sender != "B") {
		return nil, errors.New("bundle campaign identity mismatch")
	}
	node, _, _ := exchangeSlot(campaign.Direction, env.Manifest.Role)
	if node != env.Manifest.Node {
		return nil, errors.New("bundle signer does not own claimed campaign role")
	}
	// ZIP byte hash is provenance, not a signature; manifest signature and
	// independently signed run proofs are verified separately.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, err
	}
	if !strings.EqualFold(hex.EncodeToString(initialHash.Sum(nil)), hex.EncodeToString(hasher.Sum(nil))) {
		return nil, errors.New("bundle changed while verifying archive entries")
	}
	identity, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return &exchangeBundle{Manifest: env.Manifest, Source: filename,
		Digest: hex.EncodeToString(hasher.Sum(nil)), Identity: exchangeSHA(identity), SignerSHA256: exchangeSHA(leaf.Raw), Files: files}, nil
}

func exchangeCreateBase(base string) error {
	if base == "" || !filepath.IsAbs(base) {
		return errors.New("exchange base must be an absolute path")
	}
	clean := filepath.Clean(base)
	parts := strings.Split(strings.TrimPrefix(clean, "/"), string(filepath.Separator))
	curr := "/"
	for _, part := range parts {
		if part == "" {
			continue
		}
		curr = filepath.Join(curr, part)
		st, err := os.Lstat(curr)
		if os.IsNotExist(err) {
			if err := os.Mkdir(curr, 0700); err != nil {
				return err
			}
			st, err = os.Lstat(curr)
		}
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe exchange ancestor: %q", curr)
		}
	}
	for _, sub := range append([]string{""}, []string{"inbox", "outbox", "reports", "archive", "rejected", "sources"}...) {
		target := filepath.Join(clean, sub)
		if sub != "" {
			if err := os.Mkdir(target, 0700); err != nil && !os.IsExist(err) {
				return err
			}
		}
		st, err := os.Lstat(target)
		if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("exchange directory needs 0700 permissions: %q", target)
		}
	}
	return nil
}

// Importing or exporting archives cannot start network tests or background jobs.
