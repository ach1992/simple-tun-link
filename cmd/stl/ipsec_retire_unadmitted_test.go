package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ipsec "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestRetireIPsecWithoutNativeAdmission(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	keys, err := ipsec.NewPSKStore(root)
	if err != nil {
		t.Fatal(err)
	}
	id := domain.LinkID("lnk_11111111111111111111111111111111")
	sibling := domain.LinkID("lnk_22222222222222222222222222222222")
	secret := bytes.Repeat([]byte{0x41}, 32)
	if err := keys.PutNew(id, secret); err != nil {
		t.Fatal(err)
	}
	if err := keys.PutNew(sibling, bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(secret)
	store := state.NewFileStore(root)
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.IPsecRemovalReceipts = append(s.IPsecRemovalReceipts, state.IPsecRemovalReceipt{LinkID: id, PSKSHA256: hex.EncodeToString(hash[:])})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	opts := &runtimeOptions{stateRoot: root} // no IPsec backend or admitted daemon
	for i := 0; i < 2; i++ {
		var out, errs bytes.Buffer
		status := runWithRuntime([]string{"link", "retire-ipsec", string(id), "--confirm", string(id), "--json"}, &out, &errs, opts)
		var result ipsecRetireResult
		if status != 0 || errs.Len() != 0 || json.Unmarshal(out.Bytes(), &result) != nil || !result.Retired || result.SchemaVersion != 1 {
			t.Fatalf("attempt %d: exit=%d reply=%s stderr=%s", i, status, out.String(), errs.String())
		}
	}
	if _, err := os.Stat(filepath.Join(root, "credentials", string(id)+".ipsecpsk")); !os.IsNotExist(err) {
		t.Fatal("retired key retained")
	}
	if _, err := keys.Load(sibling); err != nil {
		t.Fatal("sibling modified", err)
	}
	snap, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := snap.FindIPsecRemovalReceipt(id)
	if !ok || !receipt.Retired {
		t.Fatal("receipt uncommitted")
	}
}
