package state

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
)

func managedQUICStateFixture(t *testing.T) (QUICCrashOperation, LinkRecord) {
	t.Helper()
	op := quicCrashFixture(t)
	op.WireGuard.PeerPort = op.Plan.Local.RemoteWGUDPPort
	link := domain.Link{ID: op.Plan.Local.LinkID, DisplayName: "managed-quic", Backend: domain.BackendWireGuardQUIC, Encapsulation: domain.EncapUDP,
		Underlay: domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: op.Plan.Physical.Addr()}, Addresses: op.Addresses, WireGuard: op.WireGuard,
		QUIC: domain.QUICOptions{Role: "dial", UDPPort: op.Plan.Physical.Port(), ForwardUDPPort: op.Plan.Local.LocalHelperUDPPort, TLSServerName: op.Plan.TLSName}}
	op.Managed = &QUICManagedOperation{Version: 1, Intent: link, Operation: "ensure"}
	op.Resources = normalizeClaims(op.Resources)
	g := QUICGeneration{Version: 1, OriginNonce: op.Nonce, MaterialNonce: op.Nonce, KernelBootID: "01234567-89ab-4cde-8fab-0123456789ab", KernelBootSource: hostidentity.VerifiedHostBootSourceV1, NetworkNS: "net:[42]", WGIfIndex: 101,
		GuardTableHandle: 1, GuardChainHandle: 2, GuardRuleHandle: 3,
		Files:          QUICFileIdentity{Certificate: op.CertificateSHA256, TLSKey: strings.Repeat("f", 64), TrustCA: op.TrustCASHA256, Authorization: op.AuthorizationSHA256, HelperConfig: op.HelperConfigSHA256, DirectoryDevice: 1, DirectoryInode: 5, ReceiptDevice: 1, ReceiptInode: 6},
		ExecutablePath: op.ExecutablePath, ExecutableSHA256: op.ExecutableSHA256, ExecutableDevice: op.ExecutableDevice, ExecutableInode: op.ExecutableInode}
	if err := op.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(link); err != nil {
		t.Fatal(err)
	}
	return op, LinkRecord{Desired: link, OwnedResources: op.Resources, QUICGeneration: g}
}

func TestManagedQUICJournalOnlyAllowsExactAtomicOwnerCompletion(t *testing.T) {
	ctx := context.Background()
	op, record := managedQUICStateFixture(t)
	store := NewFileStore(t.TempDir())
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICCrashOperations = append(s.QUICCrashOperations, op); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Snapshot){
		func(s *Snapshot) { s.DeleteQUICManagedOperation(record.Desired.ID) },
		func(s *Snapshot) { s.QUICCrashOperations[0].Managed.Operation = "remove" },
		func(s *Snapshot) {
			r := record
			r.QUICGeneration.OriginNonce = strings.Repeat("b", 32)
			s.Upsert(r)
			s.DeleteQUICManagedOperation(r.Desired.ID)
		},
		func(s *Snapshot) {
			r := record
			r.QUICGeneration.Files.HelperConfig = strings.Repeat("c", 64)
			s.Upsert(r)
			s.DeleteQUICManagedOperation(r.Desired.ID)
		},
	} {
		before, _ := store.Load(ctx)
		if err := store.Update(ctx, func(s *Snapshot) error { change(s); return nil }); err == nil {
			t.Fatal("unproved managed journal transition accepted")
		}
		after, _ := store.Load(ctx)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("denied journal mutation changed protected State")
		}
	}
	if err := store.Update(ctx, func(s *Snapshot) error { s.Upsert(record); s.DeleteQUICManagedOperation(record.Desired.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewFileStore(store.RootDir()).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := loaded.Find(record.Desired.ID)
	if !ok || got.QUICGeneration != record.QUICGeneration || len(loaded.QUICCrashOperations) != 0 {
		t.Fatal("exact managed commit was not atomic")
	}
}

func TestManagedQUICRemoveRequiresAtomicExactTerminationReceipt(t *testing.T) {
	ctx := context.Background()
	op, record := managedQUICStateFixture(t)
	store := NewFileStore(t.TempDir())
	op.Nonce = strings.Repeat("b", 32)
	op.Managed = &QUICManagedOperation{Version: 1, Intent: record.Desired, Operation: "remove", HadCommittedLink: true, OriginalGeneration: record.QUICGeneration}
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.Upsert(record)
		s.QUICCrashOperations = append(s.QUICCrashOperations, op)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	remove := func(s *Snapshot) { s.Delete(record.Desired.ID); s.DeleteQUICManagedOperation(record.Desired.ID) }
	if err := store.Update(ctx, func(s *Snapshot) error { remove(s); return nil }); err == nil {
		t.Fatal("managed Remove cleared without termination receipt")
	}
	if err := store.Update(ctx, func(s *Snapshot) error {
		remove(s)
		s.RemovalReceipts = append(s.RemovalReceipts, RemovalReceipt{LinkID: record.Desired.ID, Backend: domain.BackendWireGuardQUIC, LocalPublicKey: record.Desired.WireGuard.LocalPublicKey, QUICLink: record.Desired, QUICGeneration: record.QUICGeneration, QUICOriginalTermination: QUICOriginalExactIfIndexDeleted})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := store.Load(ctx)
	if err != nil || len(s.Links) != 0 || len(s.QUICCrashOperations) != 0 || len(s.RemovalReceipts) != 1 {
		t.Fatalf("atomic QUIC retirement receipt missing: %v", err)
	}
}

func TestStateV4QUICJournalMigratesWithoutManagedAuthority(t *testing.T) {
	ctx := context.Background()
	old := quicCrashFixture(t)
	root := t.TempDir()
	raw, err := json.Marshal(Snapshot{SchemaVersion: 4, Links: []LinkRecord{}, QUICCrashOperations: []QUICCrashOperation{old}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	store := NewFileStore(root)
	s, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != 5 || len(s.QUICCrashOperations) != 1 || s.QUICCrashOperations[0].Managed != nil {
		t.Fatal("v4 source journal was promoted")
	}
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICCrashOperations = nil; return nil }); err == nil {
		t.Fatal("legacy source journal was consumed")
	}
	managed, _ := managedQUICStateFixture(t)
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICCrashOperations[0] = managed; return nil }); err == nil {
		t.Fatal("existing source journal was converted to managed authority")
	}
	if err := store.Update(ctx, func(*Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	published, err := store.Load(ctx)
	if err != nil || published.QUICCrashOperations[0].Managed != nil {
		t.Fatal("legacy migration lost quarantine")
	}
}

func TestStateV4RejectsManagedQUICGrafts(t *testing.T) {
	op, record := managedQUICStateFixture(t)
	for _, snapshot := range []Snapshot{
		{SchemaVersion: 4, Links: []LinkRecord{record}},
		{SchemaVersion: 4, Links: []LinkRecord{}, QUICCrashOperations: []QUICCrashOperation{op}},
	} {
		root := t.TempDir()
		raw, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileStore(root).Load(context.Background()); err == nil {
			t.Fatal("v4 graft gained managed QUIC authority")
		}
	}
	// The public managed model uses the remote reciprocal WG port. The old
	// source-only envelope keeps its distinct forwarding-port interpretation.
	if op.WireGuard.PeerPort != op.Plan.Local.RemoteWGUDPPort || op.Plan.Local.Role != composition.Dial {
		t.Fatal("invalid managed port fixture")
	}
}
