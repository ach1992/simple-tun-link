package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Imported ZIP archives are data only. Verification and any quarantine copy
// have no path from exchange import to an operational network command.
type exchangeImportResult struct {
	Input       string `json:"input"`
	Status      string `json:"status"`
	CaseID      string `json:"case_id,omitempty"`
	Slot        string `json:"slot,omitempty"`
	ZipSHA256   string `json:"zip_sha256,omitempty"`
	ArchiveFile string `json:"archive_file,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// A staged, bounded read preserves exact bytes for provenance. os.SameFile
// rejects swapped file identities, including a symlink substituted at open.
func exchangeFileDigest(path string) (string, error) {
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > exchangeMaxTotal {
		return "", errors.New("source is not a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(stat, opened) {
		return "", errors.New("source identity changed during open")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, exchangeMaxTotal+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func exchangeCopyArchiveNew(src, destination, expectedDigest string) (string, error) {
	parent := filepath.Dir(destination)
	st, err := os.Lstat(parent)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return "", errors.New("archive/quarantine destination must be a private 0700 directory")
	}
	if prior, err := os.Lstat(destination); err == nil {
		if !prior.Mode().IsRegular() || prior.Mode().Perm()&0077 != 0 {
			return "", errors.New("archive destination already exists and is unsafe")
		}
		digest, err := exchangeFileDigest(destination)
		if err != nil || digest != expectedDigest {
			return "", errors.New("archive target exists with conflicting or unverifiable content")
		}
		return "ALREADY_ARCHIVED_IDENTICAL", nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	stat, err := os.Lstat(src)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > exchangeMaxTotal {
		return "", errors.New("refusing unbounded, symlink or nonregular source")
	}
	source, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(stat, opened) {
		return "", errors.New("archive input changed before copy")
	}
	staged, err := os.CreateTemp(parent, ".sdx-import-*")
	if err != nil {
		return "", err
	}
	defer staged.Close()
	defer os.Remove(staged.Name())
	if err := staged.Chmod(0600); err != nil {
		return "", err
	}
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(staged, h), io.LimitReader(source, exchangeMaxTotal+1))
	if err != nil || written > exchangeMaxTotal || stat.Size() != written || hex.EncodeToString(h.Sum(nil)) != expectedDigest {
		return "", errors.New("source changed or exceeded import budget")
	}
	if err := staged.Sync(); err != nil {
		return "", err
	}
	if err := os.Link(staged.Name(), destination); err != nil {
		if os.IsExist(err) {
			return "", errors.New("another import created this archive; inspect identity before retry")
		}
		return "", err
	}
	if d, err := os.Open(parent); err == nil {
		defer d.Close()
		if err := d.Sync(); err != nil {
			return "", err
		}
	}
	return "ARCHIVED_VERIFIED_COPY", nil
}

func exchangeImport(base, ca string, sources []string, caseID string) ([]exchangeImportResult, error) {
	if ca == "" {
		return nil, errors.New("import requires a public CA trust anchor")
	}
	if caseID != "" && !exchangeIDPattern.MatchString(caseID) {
		return nil, errors.New("invalid optional case ID filter")
	}
	for _, folder := range []string{"archive", "rejected"} {
		st, err := os.Lstat(filepath.Join(base, folder))
		if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("create private exchange directories first with exchange init: %s", folder)
		}
	}
	if _, err := certificateRoots(ca); err != nil {
		return nil, err
	}
	results := make([]exchangeImportResult, 0, len(sources))
	for _, source := range sources {
		r := exchangeImportResult{Input: source}
		bundle, err := exchangeOpenBundle(source, ca)
		if err == nil && caseID != "" && bundle.Manifest.CaseID != caseID {
			r.Status = "IGNORED_DIFFERENT_CASE"
			results = append(results, r)
			continue
		}
		if err == nil {
			err = exchangeValidateBundleContent(bundle, ca)
		}
		if err == nil {
			r.CaseID = bundle.Manifest.CaseID
			r.Slot = exchangeSlotID(bundle.Manifest.Direction, bundle.Manifest.Role)
			r.ZipSHA256 = bundle.Digest
			file := "SDX-" + r.CaseID + "-" + bundle.Manifest.Direction + "-" + bundle.Manifest.Role + "-" + bundle.Digest + ".zip"
			r.ArchiveFile = filepath.Join(base, "archive", file)
			r.Status, err = exchangeCopyArchiveNew(source, r.ArchiveFile, r.ZipSHA256)
			if err != nil {
				return results, fmt.Errorf("cannot safely archive authenticated bundle: %w", err)
			}
		} else {
			r.Reason = err.Error()
			digest, hashErr := exchangeFileDigest(source)
			if hashErr != nil {
				r.Status = "REJECTED_NOT_COPIED_UNSAFE_INPUT"
				results = append(results, r)
				continue
			}
			r.ZipSHA256 = digest
			r.ArchiveFile = filepath.Join(base, "rejected", "SDX-rejected-"+digest+".bin")
			r.Status, err = exchangeCopyArchiveNew(source, r.ArchiveFile, digest)
			if err != nil {
				return results, fmt.Errorf("cannot safely quarantine rejected bundle: %w", err)
			}
			if r.Status == "ARCHIVED_VERIFIED_COPY" {
				r.Status = "REJECTED_QUARANTINED_UNTRUSTED_DATA"
			} else {
				r.Status = "REJECTED_ALREADY_QUARANTINED"
			}
		}
		results = append(results, r)
	}
	return results, nil
}
