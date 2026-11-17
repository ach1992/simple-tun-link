package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestSignedMirrorReceiptRejectsConcurrentPinnedVersionAndCommitChange(t *testing.T) {
	// The external pinned updater has exclusive maintenance ownership; once
	// it publishes 0.1.27 the stale signed 0.1.26 consent must not persist a
	// sequence, even when its previously authenticated signature is valid.
	meta := mirrorSignedRelease{Sequence: 6, Version: "v0.1.26", Commit: strings.Repeat("b", 40)}
	state := mirrorPublisherTrust{Sequence: 5, LastVersion: "v0.1.25"}
	installed := signedInstalledIdentity{SchemaVersion: jsonSchemaVersion, Version: "v0.1.25", Commit: strings.Repeat("a", 40)}
	var maintenance sync.Mutex
	acquire := func(context.Context) (func() error, error) {
		maintenance.Lock()
		return func() error { maintenance.Unlock(); return nil }, nil
	}
	maintenance.Lock()
	// Actor B holds the maintenance lock and completes an authorized pinned
	// update after Actor A authenticated its older signed candidate.
	installed.Version, installed.Commit = "v0.1.27", strings.Repeat("c", 40)
	maintenance.Unlock()
	writes := 0
	read := func() (signedInstalledIdentity, error) { return installed, nil }
	write := func(mirrorPublisherTrust) error { writes++; return nil }
	if err := commitSignedMirrorReceipt(meta, state, acquire, read, write); err == nil || writes != 0 {
		t.Fatalf("publisher receipt advanced after another pinned Update: err=%v writes=%d", err, writes)
	}
	if state.Sequence != 5 || state.LastVersion != "v0.1.25" {
		t.Fatal("failed receipt mutated the previous publisher trust state")
	}
	// Same version but source commit differs: tag alone never authorizes a
	// publisher receipt after a competing repack/recovery attempt.
	installed.Version, installed.Commit = meta.Version, strings.Repeat("d", 40)
	if err := commitSignedMirrorReceipt(meta, state, acquire, read, write); err == nil || writes != 0 {
		t.Fatalf("wrong installed commit advanced publisher receipt: %v", err)
	}
}

func TestSignedMirrorInterruptedUpdateRecoveryUsesLockedInstalledIdentity(t *testing.T) {
	// This is the already-installed *exact* signed version after an interrupted
	// receipt write. No installer callback exists in this recovery path.
	meta := mirrorSignedRelease{Sequence: 9, Version: "v0.1.26", Commit: strings.Repeat("b", 40)}
	state := mirrorPublisherTrust{Sequence: 8, LastVersion: "v0.1.25"}
	installed := signedInstalledIdentity{SchemaVersion: jsonSchemaVersion, Version: meta.Version, Commit: meta.Commit}
	var maintenance sync.Mutex
	underLock := false
	locker := func(context.Context) (func() error, error) {
		maintenance.Lock()
		underLock = true
		return func() error { underLock = false; maintenance.Unlock(); return nil }, nil
	}
	reads, writes := 0, 0
	var persisted mirrorPublisherTrust
	err := commitSignedMirrorReceipt(meta, state, locker,
		func() (signedInstalledIdentity, error) {
			reads++
			if !underLock {
				return signedInstalledIdentity{}, errors.New("read outside canonical lock")
			}
			return installed, nil
		},
		func(next mirrorPublisherTrust) error {
			writes++
			if !underLock {
				return errors.New("receipt persisted outside canonical lock")
			}
			persisted = next
			return nil
		})
	if err != nil || reads != 1 || writes != 1 || persisted.Sequence != meta.Sequence ||
		persisted.LastVersion != meta.Version || underLock {
		t.Fatalf("interrupted matching-install recovery not atomic: err=%v reads=%d writes=%d next=%+v locked=%t",
			err, reads, writes, persisted, underLock)
	}
	// Cannot claim a completed receipt if the maintenance lock cannot be
	// acquired, or a post-update installed-identity read becomes unverified.
	writes = 0
	if err := commitSignedMirrorReceipt(meta, state, func(context.Context) (func() error, error) {
		return nil, errors.New("another update owns canonical lock")
	}, func() (signedInstalledIdentity, error) {
		t.Fatal("read without maintenance lock")
		return installed, nil
	},
		func(mirrorPublisherTrust) error { writes++; return nil }); err == nil || writes != 0 {
		t.Fatalf("unavailable canonical lock advanced receipt: %v", err)
	}
	if err := commitSignedMirrorReceipt(meta, state, locker,
		func() (signedInstalledIdentity, error) {
			return signedInstalledIdentity{}, errors.New("unknown installed state")
		},
		func(mirrorPublisherTrust) error { writes++; return nil }); err == nil || writes != 0 {
		t.Fatalf("failed installed identity verification advanced receipt: %v", err)
	}
}

func TestSignedMirrorLiveIdentityRequiresSingleValidInstalledVersion(t *testing.T) {
	commit := strings.Repeat("a", 40)
	ok := fmt.Sprintf(`{"schema_version":1,"version":"v0.1.25","commit":"%s","date":"2026-11-17T00:00:00Z"}`, commit)
	id, err := readSignedInstalledIdentityWithRunner(func() ([]byte, error) { return []byte(ok), nil })
	if err != nil || id.Version != "v0.1.25" || id.Commit != commit {
		t.Fatalf("valid installed Stable not verified: %+v, %v", id, err)
	}
	for _, tc := range []struct{ name, raw string }{
		{"dev build", strings.Replace(ok, "v0.1.25", "dev-123456789abc", 1)},
		{"different schema", strings.Replace(ok, `"schema_version":1`, `"schema_version":2`, 1)},
		{"missing commit", strings.Replace(ok, commit, "", 1)},
		{"extra JSON object", ok + "{}"},
		{"unknown field", strings.TrimSuffix(ok, "}") + `,"injected":"unsafe"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readSignedInstalledIdentityWithRunner(func() ([]byte, error) { return []byte(tc.raw), nil }); err == nil {
				t.Fatal("untrusted installed binary identity accepted")
			}
		})
	}
}
