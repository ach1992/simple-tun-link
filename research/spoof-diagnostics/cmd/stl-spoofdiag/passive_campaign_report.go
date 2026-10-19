package main

// Offline-only reconciliation of manually collected campaign evidence.
// It opens no sockets and never drives the sender or receiver.

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"
)

const passiveMaxImportedCaptures = 128

type passiveBatchCoverage struct {
	Direction  string `json:"direction"`
	CampaignID string `json:"campaign_id"`
	Batch      int    `json:"batch"`
	Attempts   int    `json:"attempts"`
	Candidates int    `json:"candidates"`
	Planned    int    `json:"planned_samples"`
	Submitted  int    `json:"submitted_syscalls"`
	Observed   int    `json:"verified_observed_samples"`
	NotTested  int    `json:"not_tested_samples"`
	Duplicate  int    `json:"duplicate_signed_observations,omitempty"`
	Ambiguous  int    `json:"ambiguous_signed_observations,omitempty"`
	State      string `json:"state"`
}

type captureSnapshot struct {
	capture passiveCapture
	path    string
	hash    string
}

func sameCaptureScope(a, b passiveCapture) bool {
	return a.Format == b.Format && a.CaptureID == b.CaptureID &&
		a.Observer == b.Observer && a.BindIP == b.BindIP && a.DataPort == b.DataPort &&
		a.WindowSeconds == b.WindowSeconds && a.PacketLimit == b.PacketLimit &&
		a.StartedUTC == b.StartedUTC
}

func passiveSnapshotHistory(a, b passiveCapture) bool {
	if !sameCaptureScope(a, b) {
		return false
	}
	shorter, longer := a.Observations, b.Observations
	if len(longer) < len(shorter) {
		shorter, longer = longer, shorter
	}
	return reflect.DeepEqual(shorter, longer[:len(shorter)])
}

func validatedCapturePaths(dir, ca string, manifest campaignManifest) ([]string, []passiveInputFile, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, errors.New("capture input directory must exist and be private (0700)")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) > passiveMaxImportedCaptures {
		return nil, nil, errors.New("too many passive receiver captures")
	}
	seen := map[string]captureSnapshot{}
	hashes := map[string]bool{}
	digests := []passiveInputFile{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".json" {
			return nil, nil, fmt.Errorf("unexpected non-regular passive evidence file: %s", entry.Name())
		}
		path := filepath.Join(dir, entry.Name())
		capture, err := readAndVerifyPassive(path, ca, manifest.Receiver)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid signed observation %s: %w", entry.Name(), err)
		}
		if capture.BindIP != manifest.DestinationIP || capture.DataPort != manifest.DataPort {
			return nil, nil, errors.New("receiver observation endpoint differs from campaign")
		}
		data, err := readSmallRegular(path, passiveMaxFile)
		if err != nil {
			return nil, nil, err
		}
		hash := digestBytes(data)
		if !hashes[hash] {
			digests = append(digests, passiveInputFile{Slot: manifest.Direction, Kind: "signed_passive_receiver_capture", SHA256: hash})
			hashes[hash] = true
		}
		prior, exists := seen[capture.CaptureID]
		if !exists {
			seen[capture.CaptureID] = captureSnapshot{capture: capture, path: path, hash: hash}
			continue
		}
		if prior.hash == hash {
			continue
		}
		if !passiveSnapshotHistory(prior.capture, capture) {
			return nil, nil, errors.New("conflicting snapshots of a signed receiver capture")
		}
		oldUTC, e1 := time.Parse(time.RFC3339Nano, prior.capture.UpdatedUTC)
		newUTC, e2 := time.Parse(time.RFC3339Nano, capture.UpdatedUTC)
		if e1 != nil || e2 != nil {
			return nil, nil, errors.New("invalid signed capture timestamps")
		}
		if len(capture.Observations) > len(prior.capture.Observations) {
			if newUTC.Before(oldUTC) {
				return nil, nil, errors.New("longer capture snapshot has earlier timestamp")
			}
			seen[capture.CaptureID] = captureSnapshot{capture: capture, path: path, hash: hash}
		} else if len(capture.Observations) < len(prior.capture.Observations) {
			if oldUTC.Before(newUTC) {
				return nil, nil, errors.New("shorter capture snapshot has later timestamp")
			}
		} else if newUTC.After(oldUTC) {
			seen[capture.CaptureID] = captureSnapshot{capture: capture, path: path, hash: hash}
		}
	}
	paths := make([]string, 0, len(seen))
	for _, record := range seen {
		paths = append(paths, record.path)
	}
	sort.Strings(paths)
	sort.Slice(digests, func(i, j int) bool { return digests[i].SHA256 < digests[j].SHA256 })
	return paths, digests, nil
}

// The SDF2 Run-ID bytes here are only an UNTRUSTED search hint. Every
// selected observation is later checked against the exact signed plan and
// sender public key; index membership alone is never evidence of arrival.
func indexedCaptureRunPaths(paths []string, ca, observer string) (map[string][]string, error) {
	byRun := map[string][]string{}
	for _, path := range paths {
		capture, err := readAndVerifyPassive(path, ca, observer)
		if err != nil {
			return nil, err
		}
		forRun := map[string]bool{}
		for _, record := range capture.Observations {
			frame, err := base64.StdEncoding.DecodeString(record.PacketBase64)
			if err != nil || len(frame) < 20 {
				return nil, errors.New("invalid signed capture frame")
			}
			runID := hex.EncodeToString(frame[4:20])
			if !forRun[runID] {
				byRun[runID] = append(byRun[runID], path)
				forRun[runID] = true
			}
		}
	}
	for _, group := range byRun {
		sort.Strings(group)
	}
	return byRun, nil
}
