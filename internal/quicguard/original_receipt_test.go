package quicguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"golang.org/x/sys/unix"
)

func receiptFixture(t *testing.T) originReceipt {
	t.Helper()
	guard, err := linux.NewQUICWGIngressPlan(fixtureID, 51820, fixtureNonce)
	if err != nil {
		t.Fatal(err)
	}
	return originReceipt{SchemaVersion: 1, LinkID: fixtureID,
		Nonce: fixtureNonce, ListenPort: 51820, Table: guard.TableName(),
		KernelBootID: testBootID, NetworkNS: testNetNS,
		Handles: linux.WGIngressLiveHandles{Table: 1, Chain: 2, Rule: 3}}
}

func newReceiptTestDir(t *testing.T) (string, int, originReceipt) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	dir, err := openOriginReceiptDir(root, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(dir) })
	return root, dir, receiptFixture(t)
}

func TestOriginalReceiptExclusiveCreationDurableReadbackAndNoAdoption(t *testing.T) {
	root, dir, receipt := newReceiptTestDir(t)
	if err := ensureOriginReceiptVacant(dir, receipt.LinkID); err != nil {
		t.Fatal(err)
	}
	if _, err := readOriginReceiptFD(dir, receipt.LinkID, receipt.Nonce, receipt.ListenPort); err == nil {
		t.Fatal("missing original CREATE receipt was accepted")
	}
	if err := persistOriginReceiptFD(root, dir, receipt, fixtureID, fixtureNonce, 51820); err != nil {
		t.Fatal(err)
	}
	got, err := readOriginReceiptFD(dir, receipt.LinkID, receipt.Nonce, receipt.ListenPort)
	if err != nil || got != receipt {
		t.Fatalf("verified durable original lost: %+v %v", got, err)
	}
	if err := ensureOriginReceiptVacant(dir, receipt.LinkID); err == nil {
		t.Fatal("existing receipt was adopted as fresh original")
	}
	if err := persistOriginReceiptFD(root, dir, receipt, fixtureID, fixtureNonce, 51820); err == nil {
		t.Fatal("same-byte original overwrite/adoption was accepted")
	}
	name := filepath.Join(root, "credentials", originReceiptDir, originReceiptName(receipt.LinkID))
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("receipt must be a regular private durable file: %v %+v", err, info)
	}
	anotherDir, err := openOriginReceiptDir(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(anotherDir)
	if again, err := readOriginReceiptFD(anotherDir, receipt.LinkID, receipt.Nonce, receipt.ListenPort); err != nil || again != receipt {
		t.Fatalf("fresh directory read could not recover exact original: %v %+v", err, again)
	}
}

func TestOriginalReceiptRejectsMalformedOrReplacedPrivateFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  func(t *testing.T, filename string)
	}{
		{"duplicate JSON field", func(t *testing.T, p string) {
			t.Helper()
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b = bytes.Replace(b, []byte(`"schema_version":1,`), []byte(`"schema_version":1,"schema_version":1,`), 1)
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown JSON field", func(t *testing.T, p string) {
			t.Helper()
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b = bytes.Replace(b, []byte(`"schema_version":1,`), []byte(`"schema_version":1,"foreign":true,`), 1)
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode widened", func(t *testing.T, p string) {
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, p string) {
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".old", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlinked", func(t *testing.T, p string) {
			if err := os.Link(p, p+".second"); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated", func(t *testing.T, p string) {
			if err := os.Truncate(p, 12); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, dir, receipt := newReceiptTestDir(t)
			if err := persistOriginReceiptFD(root, dir, receipt, fixtureID, fixtureNonce, 51820); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(root, "credentials", originReceiptDir, originReceiptName(receipt.LinkID))
			tc.bad(t, filename)
			if _, err := readOriginReceiptFD(dir, receipt.LinkID, receipt.Nonce, receipt.ListenPort); err == nil {
				t.Fatal("unsafe receipt accepted as a trusted creation record")
			}
		})
	}
}

func TestOriginalReceiptRejectsInventedHostObjectIdentity(t *testing.T) {
	original := receiptFixture(t)
	for _, change := range []struct {
		name string
		fn   func(*originReceipt)
	}{
		{"empty handle", func(r *originReceipt) { r.Handles.Rule = 0 }},
		{"wrong nonce", func(r *originReceipt) { r.Nonce = strings.Repeat("f", 32) }},
		{"wrong port", func(r *originReceipt) { r.ListenPort = 80 }},
		{"wrong table", func(r *originReceipt) { r.Table = "foreign" }},
		{"invalid boot", func(r *originReceipt) { r.KernelBootID = "unverified" }},
		{"wrong scope", func(r *originReceipt) { r.NetworkNS = "net:[0]" }},
		{"future schema", func(r *originReceipt) { r.SchemaVersion = 2 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			root, dir, record := newReceiptTestDir(t)
			change.fn(&record)
			if err := persistOriginReceiptFD(root, dir, record, fixtureID, fixtureNonce, 51820); err == nil {
				t.Fatal("invalid original receipt persisted")
			}
			if err := ensureOriginReceiptVacant(dir, original.LinkID); err != nil {
				t.Fatalf("invalid receipt unexpectedly created a file: %v", err)
			}
		})
	}
}

func TestOriginalReceiptFixedThreadPostEffectWitnessAndQuarantine(t *testing.T) {
	newLive := func() (liveGuardReader, func(context.Context, string) error) {
		f, _ := guardFixture(t)
		r := liveGuardReader{f}
		return r, func(_ context.Context, batch string) error {
			if !strings.HasPrefix(batch, "create table inet ") {
				t.Fatal("not exact nft CREATE")
			}
			r.present = true
			return nil
		}
	}
	for _, tc := range []struct {
		name          string
		boot          func() (string, error)
		after         func(originReceipt) error
		wantDispatch  int
		wantRecord    int
		wantUncertain bool
	}{
		{"success", func() (string, error) { return testBootID, nil }, func(originReceipt) error { return nil }, 1, 1, false},
		{"untrusted boot before effect", func() (string, error) { return "untrusted", nil }, func(originReceipt) error { return nil }, 0, 0, false},
		{"receipt publication failure", func() (string, error) { return testBootID, nil }, func(originReceipt) error { return errors.New("SENSITIVE_FOREIGN_WRITER_ERROR") }, 1, 1, true},
		{"boot changes after effect", func() (string, error) { return testBootID, nil }, func(originReceipt) error { return nil }, 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, apply := newLive()
			dispatched := 0
			recorded := 0
			bootReads := 0
			boot := func() (string, error) {
				bootReads++
				if tc.name == "boot changes after effect" && bootReads > 1 {
					return "abcdef01-2345-6789-abcd-ef0123456789", nil
				}
				return tc.boot()
			}
			err := publishOriginalWithReceipt(context.Background(), r, fixtureID, fixtureNonce, testWG(),
				func(c context.Context, b string) error { dispatched++; return apply(c, b) },
				func() (string, error) { return testNetNS, nil }, boot,
				func(got originReceipt) error {
					recorded++
					if got.Handles.Table != 1 || got.ListenPort != 51820 || got.Nonce != fixtureNonce ||
						got.KernelBootID != testBootID || got.NetworkNS != testNetNS {
						t.Fatalf("wrong host witness: %+v", got)
					}
					return tc.after(got)
				})
			wantRecorded := tc.wantRecord
			if tc.name == "boot changes after effect" {
				wantRecorded = 0
			}
			if dispatched != tc.wantDispatch || recorded != wantRecorded {
				t.Fatalf("inappropriate side effect/record: %d/%d err %v", dispatched, recorded, err)
			}
			if tc.name == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if tc.wantUncertain || tc.name == "boot changes after effect" {
				if !errors.Is(err, errEffectUncertain) || strings.Contains(err.Error(), "SENSITIVE_FOREIGN") {
					t.Fatalf("post-effect uncertainty incorrectly handled: %v", err)
				}
			} else if err == nil {
				t.Fatal("untrusted host source did not prevent effect")
			}
			for _, call := range r.calls {
				if strings.Contains(call, "delete") || strings.Contains(call, "flush") {
					t.Fatalf("unsafe cleanup or adoption during failure: %q", call)
				}
			}
		})
	}
}

func TestOriginalReceiptCanonicalJSONRoundTrip(t *testing.T) {
	rec := receiptFixture(t)
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var round originReceipt
	if err := json.Unmarshal(raw, &round); err != nil || round != rec {
		t.Fatalf("original receipt fields lost: %+v %v", round, err)
	}
}
