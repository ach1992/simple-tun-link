package ipsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func nativeUnitPublicationFixture(t *testing.T) (root, unit, receipt string, owner uint32) {
	t.Helper()
	root = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(root, nativeUnitFixturePath),
		filepath.Join(root, "var/lib/simple-tun-link/ipsec", nativeUnitOriginName),
		uint32(os.Geteuid())
}

func TestNativeUnitPublicationNoClobberDurableOrigin(t *testing.T) {
	root, unit, receipt, owner := nativeUnitPublicationFixture(t)
	if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginMissing {
		t.Fatalf("before publication: %s", got)
	}
	if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); err != nil {
		t.Fatal(err)
	}
	if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginVerified {
		t.Fatalf("published origin not observable after reopen: %s", got)
	}
	if got := inspectNativeServiceUnitAt(root, owner, nil); got != NativeServiceUnitExact {
		t.Fatalf("existing byte reader diverged: %s", got)
	}
	info, err := os.Lstat(unit)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("published unit identity: %v %+v", err, info)
	}
	data, err := os.ReadFile(unit)
	if err != nil || !bytes.Equal(data, NativeExclusiveServiceUnitV1()) {
		t.Fatalf("published unit bytes: %v", err)
	}
	receiptInfo, err := os.Stat(receipt)
	if err != nil || receiptInfo.Mode().Perm() != 0o600 {
		t.Fatalf("receipt must remain private: %v", err)
	}
	if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("replay adopted published unit: %v", err)
	}
	if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginVerified {
		t.Fatalf("replay changed trusted record: %s", got)
	}
	for _, dir := range []string{filepath.Dir(unit), filepath.Dir(receipt)} {
		items, err := os.ReadDir(dir)
		if err != nil || len(items) != 1 {
			t.Fatalf("unexpected staging debris in %q: %d %v", dir, len(items), err)
		}
	}
}

func TestNativeUnitPublicationNeverAdoptsForeignState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		create func(*testing.T, string)
	}{
		{"byte-identical foreign unit", func(t *testing.T, p string) {
			if err := os.WriteFile(p, NativeExclusiveServiceUnitV1(), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"modified foreign unit", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("[Service]\nExecStart=/bin/false\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink foreign unit", func(t *testing.T, p string) {
			if err := os.Symlink("external.service", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory foreign unit", func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, unit, receipt, owner := nativeUnitPublicationFixture(t)
			tc.create(t, unit)
			before, err := os.Lstat(unit)
			if err != nil {
				t.Fatal(err)
			}
			if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
				t.Fatalf("foreign canonical adopted: %v", err)
			}
			after, err := os.Lstat(unit)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("replaced foreign unit")
			}
			if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
				t.Fatalf("foreign file granted provenance: %s", got)
			}
			if _, err := os.Lstat(receipt); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected receipt on preexisting conflict: %v", err)
			}
		})
	}
}

// Regression for R1: fsync(unit stage fd) does not durably name that inode.
// The stage directory must be synced before the afterStage interruption seam
// and before a receipt is even attempted. The fixture can prove syscall
// ordering and fail-closed errors, NOT simulate an actual power-loss reboot.
func TestNativeUnitPublicationPreReceiptDirectorySyncGate(t *testing.T) {
	t.Run("successful directory sync precedes pre-receipt crash hook", func(t *testing.T) {
		root, unit, receipt, owner := nativeUnitPublicationFixture(t)
		synced, calledAfter := false, false
		err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{
			stageDirSync: func(fd int) error {
				if err := unix.Fsync(fd); err != nil {
					return err
				}
				synced = true
				return nil
			},
			afterStage: func() error {
				calledAfter = true
				if !synced {
					t.Fatal("reached pre-receipt interruption seam before fsync of unit directory")
				}
				return errors.New("simulate interruption after durable directory sync")
			},
		})
		if !errors.Is(err, errNativePublicationUnknown) || !synced || !calledAfter {
			t.Fatalf("unexpected pre-receipt sync/interruption state: err=%v synced=%t hook=%t", err, synced, calledAfter)
		}
		if _, err := os.Lstat(filepath.Join(filepath.Dir(unit), nativeUnitStageName)); err != nil {
			t.Fatalf("synced stage not observable in current filesystem: %v", err)
		}
		if _, err := os.Lstat(unit); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canonical unit created before receipt: %v", err)
		}
		if _, err := os.Lstat(receipt); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("receipt created before interruption point: %v", err)
		}
		if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
			t.Fatalf("stage-only state must block vacancy: %s", got)
		}
	})

	t.Run("failed directory sync is fail-closed and does not claim persistence", func(t *testing.T) {
		root, unit, receipt, owner := nativeUnitPublicationFixture(t)
		afterStageCalled := false
		afterReceiptCalled := false
		syncAttempted := false
		err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{
			stageDirSync: func(fd int) error {
				if fd < 0 {
					t.Fatal("invalid directory fd")
				}
				syncAttempted = true
				return errors.New("injected unit-stage directory fsync error")
			},
			afterStage: func() error {
				afterStageCalled = true
				return nil
			},
			afterReceipt: func() error {
				afterReceiptCalled = true
				return nil
			},
		})
		if !errors.Is(err, errNativePublicationUnknown) || !syncAttempted ||
			afterStageCalled || afterReceiptCalled {
			t.Fatalf("fsync failure passed receipt boundary: err=%v sync=%t stage=%t receipt=%t",
				err, syncAttempted, afterStageCalled, afterReceiptCalled)
		}
		if _, err := os.Lstat(receipt); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("receipt published despite failed stage directory sync: %v", err)
		}
		if _, err := os.Lstat(unit); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canonical unit published despite failed stage directory sync: %v", err)
		}
		// The staged name is visible on this still-running filesystem, but
		// a reboot is NOT modeled: after fsync failure its durability is unknown.
		if _, err := os.Lstat(filepath.Join(filepath.Dir(unit), nativeUnitStageName)); err != nil {
			t.Fatalf("unknown failure should not blindly delete staged data: %v", err)
		}
		if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
			t.Fatalf("ambiguous stage was automatically retried/adopted: %v", err)
		}
	})

	t.Run("receipt is never attempted before stage directory sync", func(t *testing.T) {
		root, _, _, owner := nativeUnitPublicationFixture(t)
		synced, reachedReceipt := false, false
		err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{
			stageDirSync: func(fd int) error {
				if err := unix.Fsync(fd); err != nil {
					return err
				}
				synced = true
				return nil
			},
			afterReceipt: func() error {
				reachedReceipt = true
				if !synced {
					t.Fatal("receipt committed before durable stage directory entry")
				}
				return errors.New("stop after receipt")
			},
		})
		if !errors.Is(err, errNativePublicationPending) || !synced || !reachedReceipt {
			t.Fatalf("unexpected ordered receipt failure: err=%v stageSync=%t receipt=%t",
				err, synced, reachedReceipt)
		}
	})
}

func TestNativeUnitPublicationDetectsPreReceiptCrashAndPendingArtifacts(t *testing.T) {
	t.Run("crash after stage before receipt", func(t *testing.T) {
		root, unit, receipt, owner := nativeUnitPublicationFixture(t)
		err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{afterStage: func() error {
			return errors.New("interrupt before receipt")
		}})
		if !errors.Is(err, errNativePublicationUnknown) {
			t.Fatalf("pre-receipt interruption: %v", err)
		}
		if _, err := os.Lstat(unit); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canonical unit unexpectedly created: %v", err)
		}
		if _, err := os.Lstat(receipt); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("receipt unexpectedly published: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(filepath.Dir(unit), nativeUnitStageName)); err != nil {
			t.Fatalf("prepared stage must be retained for operator reconciliation: %v", err)
		}
		if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
			t.Fatalf("prepared-only stage interpreted as vacancy: %s", got)
		}
		if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
			t.Fatalf("blind retry adopted or ignored staged file: %v", err)
		}
	})
	for _, name := range []string{nativeUnitStageName, nativeUnitReceiptStageName} {
		t.Run(name, func(t *testing.T) {
			root, unit, receipt, owner := nativeUnitPublicationFixture(t)
			if err := os.MkdirAll(filepath.Dir(receipt), 0o700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Dir(unit)
			if name == nativeUnitReceiptStageName {
				dir = filepath.Dir(receipt)
			}
			foreignStage := filepath.Join(dir, name)
			if err := os.WriteFile(foreignStage, []byte("foreign prepared stage"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
				t.Fatalf("staged-only foreign artifact granted vacancy: %s", got)
			}
			if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
				t.Fatalf("foreign staged name overwritten: %v", err)
			}
			bytes, err := os.ReadFile(foreignStage)
			if err != nil || string(bytes) != "foreign prepared stage" {
				t.Fatalf("foreign staged object altered: %v", err)
			}
		})
	}
}

func TestNativeUnitPublicationRaceAndInterruptionNeverAutoRecovers(t *testing.T) {
	t.Run("canonical raced by foreign actor", func(t *testing.T) {
		root, unit, _, owner := nativeUnitPublicationFixture(t)
		foreign := []byte("[Unit]\nDescription=FOREIGN; NEVER REPLACE\n")
		err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{beforeCanonical: func() error {
			if err := os.WriteFile(unit, foreign, 0o600); err != nil {
				t.Fatal(err)
			}
			return nil
		}})
		if !errors.Is(err, errNativePublicationPending) {
			t.Fatalf("foreign create not detected: %v", err)
		}
		got, readErr := os.ReadFile(unit)
		if readErr != nil || !bytes.Equal(got, foreign) {
			t.Fatal("foreign unit overwritten")
		}
		if state := inspectNativeUnitOriginAt(root, owner); state != NativeOriginConflict {
			t.Fatalf("foreign unit adopted: %s", state)
		}
	})
	t.Run("receipt committed before canonical", func(t *testing.T) {
		root, unit, receipt, owner := nativeUnitPublicationFixture(t)
		err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{afterReceipt: func() error {
			return errors.New("interrupted")
		}})
		if !errors.Is(err, errNativePublicationPending) {
			t.Fatalf("receipt interruption must be pending: %v", err)
		}
		if _, err := os.Stat(receipt); err != nil {
			t.Fatalf("receipt was not prepared: %v", err)
		}
		if _, err := os.Lstat(unit); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unit appeared before rename: %v", err)
		}
		if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
			t.Fatalf("interrupted receipt not blocked: %s", got)
		}
		if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
			t.Fatalf("interrupted transaction automatically restarted: %v", err)
		}
	})
	t.Run("post rename uncertainty retains inode and receipt", func(t *testing.T) {
		root, unit, _, owner := nativeUnitPublicationFixture(t)
		err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{afterCanonical: func() error {
			return errors.New("interrupted")
		}})
		if !errors.Is(err, errNativePublicationPending) {
			t.Fatalf("post-rename uncertainty hidden: %v", err)
		}
		if _, err := os.Stat(unit); err != nil {
			t.Fatalf("published inode lost: %v", err)
		}
		if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginVerified {
			t.Fatalf("completed bytes/receipt cannot be read after restart: %s", got)
		}
		if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
			t.Fatalf("adopted ambiguous post-rename state: %v", err)
		}
	})
}

func TestNativeUnitPublicationReceiptRacesArePendingAndNeverExposeCanonical(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, string)
	}{
		{"receipt rewritten in place", func(t *testing.T, receipt string) {
			if err := os.WriteFile(receipt, []byte("independent writer changed publication receipt"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt replaced as new inode", func(t *testing.T, receipt string) {
			if err := os.Remove(receipt); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(receipt, []byte("independent writer replaced origin"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, unit, receipt, owner := nativeUnitPublicationFixture(t)
			err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{afterReceipt: func() error {
				tc.edit(t, receipt)
				return nil
			}})
			if !errors.Is(err, errNativePublicationPending) {
				t.Fatalf("changed receipt did not block canonical rename: %v", err)
			}
			if _, err := os.Lstat(unit); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("canonical exposed despite tampered receipt: %v", err)
			}
			if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
				t.Fatalf("tampered receipt read as valid: %s", got)
			}
		})
	}
}

func TestNativeUnitOriginRejectsTamperingAndReceiptForgery(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, unit, receipt string)
	}{
		{"unit same-size rewrite", func(t *testing.T, p, _ string) {
			data := bytes.Replace(NativeExclusiveServiceUnitV1(), []byte("UMask=0077"), []byte("UMask=0000"), 1)
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unit replaced same content with different inode", func(t *testing.T, p, _ string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, NativeExclusiveServiceUnitV1(), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unit mode becomes public", func(t *testing.T, p, _ string) {
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"unit xattr missing", func(t *testing.T, p, _ string) {
			if err := unix.Removexattr(p, nativeUnitOriginXattr); err != nil {
				t.Fatal(err)
			}
		}},
		{"unit hardlinked elsewhere", func(t *testing.T, p, _ string) {
			if err := os.Link(p, p+".foreign"); err != nil {
				t.Fatal(err)
			}
		}},
		{"unit replaced by symlink", func(t *testing.T, p, _ string) {
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".old", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt missing", func(t *testing.T, _, r string) {
			if err := os.Remove(r); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt malformed/unknown field", func(t *testing.T, _, r string) {
			if err := os.WriteFile(r, []byte(`{"schema_version":1,"nonce":"00000000000000000000000000000000","device":1,"inode":1,"unit_sha256":"x","evil":"PSK_DO_NOT_PRINT"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt data changed", func(t *testing.T, _, r string) {
			data, err := os.ReadFile(r)
			if err != nil {
				t.Fatal(err)
			}
			var receipt nativeUnitOriginReceipt
			if err := json.Unmarshal(data, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt.UnitSHA256 = strings.Repeat("0", sha256.Size*2)
			wire, _ := json.Marshal(receipt)
			if err := os.WriteFile(r, append(wire, 10), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt writable by others", func(t *testing.T, _, r string) {
			if err := os.Chmod(r, 0o666); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, unit, receipt, owner := nativeUnitPublicationFixture(t)
			if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); err != nil {
				t.Fatal(err)
			}
			tc.edit(t, unit, receipt)
			if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
				t.Fatalf("modified origin still verified: %s", got)
			}
		})
	}
}

func TestNativeUnitOriginFailClosedOnUnsafePathsAndBadIdentity(t *testing.T) {
	root, _, _, owner := nativeUnitPublicationFixture(t)
	if got := inspectNativeUnitOriginAt("relative-path", owner); got != NativeOriginUnverified {
		t.Fatalf("relative root accepted: %s", got)
	}
	if err := publishNativeUnitAt("relative-path", owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationUnknown) {
		t.Fatalf("relative root publication accepted: %v", err)
	}
	if got := inspectNativeUnitOriginAt(root, owner+1); got != NativeOriginConflict {
		t.Fatalf("wrong root owner accepted: %s", got)
	}
	if err := publishNativeUnitAt(root, owner+1, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("wrong owner publication accepted: %v", err)
	}
	t.Run("missing systemd ancestor and state", func(t *testing.T) {
		empty := t.TempDir()
		if got := inspectNativeUnitOriginAt(empty, owner); got != NativeOriginMissing {
			t.Fatalf("both missing: %s", got)
		}
	})
	t.Run("symlinked systemd parent", func(t *testing.T) {
		root, _, _, owner := nativeUnitPublicationFixture(t)
		if err := os.Rename(filepath.Join(root, "etc/systemd"), filepath.Join(root, "etc/systemd.old")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("systemd.old", filepath.Join(root, "etc/systemd")); err != nil {
			t.Fatal(err)
		}
		if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
			t.Fatalf("symlink parent accepted: %v", err)
		}
		if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
			t.Fatalf("symlink parent origin accepted: %s", got)
		}
	})
	t.Run("unsafe writable ancestor", func(t *testing.T) {
		root, _, _, owner := nativeUnitPublicationFixture(t)
		if err := os.Chmod(filepath.Join(root, "etc/systemd"), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
			t.Fatalf("writable parent accepted: %v", err)
		}
		if got := inspectNativeUnitOriginAt(root, owner); got != NativeOriginConflict {
			t.Fatalf("writable parent observed as safe: %s", got)
		}
	})
	t.Run("origin state survives other config receipt", func(t *testing.T) {
		root, _, _, owner := nativeUnitPublicationFixture(t)
		if err := publishNativeConfigAt(root, owner, nativePublishHooks{}); err != nil {
			t.Fatal(err)
		}
		if err := publishNativeUnitAt(root, owner, nativeUnitPublishHooks{}); err != nil {
			t.Fatal(err)
		}
		if inspectNativeOriginAt(root, owner) != NativeOriginVerified ||
			inspectNativeUnitOriginAt(root, owner) != NativeOriginVerified {
			t.Fatal("native config and unit provenance interfere")
		}
	})
}

func TestConcurrentNativeUnitPublishersCannotBothClaimCanonical(t *testing.T) {
	root, _, _, owner := nativeUnitPublicationFixture(t)
	const workers = 6
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- publishNativeUnitAt(root, owner, nativeUnitPublishHooks{})
		}()
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, errNativePublicationConflict) && !errors.Is(err, errNativePublicationPending) &&
			!errors.Is(err, errNativePublicationUnknown) {
			t.Fatalf("unexpected racing publisher result: %v", err)
		}
	}
	if success > 1 {
		t.Fatalf("two publishers claimed the same unit: %d", success)
	}
	// Since a prepared receipt can intentionally block another writer, the
	// canonical file may be absent or complete, but never foreign-adopted.
	state := inspectNativeUnitOriginAt(root, owner)
	if state == NativeOriginUnverified {
		t.Fatal("race left an unclassified origin")
	}
}
