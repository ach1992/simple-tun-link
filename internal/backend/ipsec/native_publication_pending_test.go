package ipsec

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeConfigPendingStagesFailClosedBeforeReceipt(t *testing.T) {
	for _, tc := range []struct {
		name             string
		hooks            func(string) nativePublishHooks
		wantConfigStage  bool
		wantReceiptStage bool
	}{
		{"durable config stage interrupted", func(string) nativePublishHooks {
			return nativePublishHooks{afterStage: func() error { return errors.New("simulated interruption") }}
		}, true, false},
		{"stage directory fsync unknown", func(string) nativePublishHooks {
			return nativePublishHooks{stageDirSync: func(int) error { return errors.New("simulated fsync failure") },
				afterStage: func() error { panic("must not proceed after stage fsync failure") }}
		}, true, false},
		{"receipt stage precommit interrupted", func(path string) nativePublishHooks {
			return nativePublishHooks{afterStage: func() error {
				return os.WriteFile(filepath.Join(filepath.Dir(path), nativeConfigReceiptStage),
					[]byte("incomplete retained receipt"), 0o600)
			}}
		}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, path, uid := nativePublicationFixture(t)
			err := publishNativeConfigAt(root, uid, tc.hooks(path))
			if err == nil {
				t.Fatal("pre-receipt interruption returned success")
			}
			for _, pair := range []struct {
				name   string
				exists bool
			}{
				{nativeConfigStageName, tc.wantConfigStage},
				{nativeConfigReceiptStage, tc.wantReceiptStage},
			} {
				_, e := os.Lstat(filepath.Join(filepath.Dir(path), pair.name))
				if (e == nil) != pair.exists {
					t.Fatalf("pending stage evidence lost or unexpected: %s %v", pair.name, e)
				}
			}
			if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("canonical config was published despite pre-receipt failure: %v", e)
			}
			if got := inspectNativeOriginAt(root, uid); got == NativeOriginMissing || got == NativeOriginVerified {
				t.Fatalf("pending private source misclassified as fresh/admitted: %s", got)
			}
			if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
				t.Fatalf("failed first transaction was retried or adopted: %v", err)
			}
		})
	}
}

func TestNativeConfigInspectorRejectsForeignPendingStageEvenWhenCanonicalPairAbsent(t *testing.T) {
	for _, stage := range []string{nativeConfigStageName, nativeConfigReceiptStage} {
		t.Run(stage, func(t *testing.T) {
			root, path, uid := nativePublicationFixture(t)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/tmp/untrusted-native", filepath.Join(filepath.Dir(path), stage)); err != nil {
				t.Fatal(err)
			}
			if got := inspectNativeOriginAt(root, uid); got != NativeOriginConflict {
				t.Fatalf("unsafe symlink pending stage incorrectly accepted: %s", got)
			}
			if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
				t.Fatalf("foreign pending stage adopted or overwritten: %v", err)
			}
		})
	}
}
