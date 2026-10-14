package state

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func mtuStateTestDocument(t *testing.T, version int, key, value, location string) []byte {
	t.Helper()
	link := testLink(t, domain.LinkID("lnk_22222222222222222222222222222222"),
		"10.80.40.0/31", "10.80.40.1/31")
	encodedLink, err := json.Marshal(link)
	if err != nil {
		t.Fatal(err)
	}
	var desired map[string]json.RawMessage
	if err := json.Unmarshal(encodedLink, &desired); err != nil {
		t.Fatal(err)
	}
	if key != "" {
		desired[key] = json.RawMessage(value)
	}
	document := map[string]any{
		"schema_version": version,
		"links":          []any{map[string]any{"desired": desired}},
	}
	switch location {
	case "committed":
	case "pending":
		document["links"] = []any{}
		document["pending_senders"] = []any{map[string]any{"link": desired}}
	case "nested_journal":
		document["links"] = []any{}
		document["ipsec_vici_operations"] = []any{
			map[string]any{"intent": map[string]any{"link": desired}},
		}
	default:
		t.Fatalf("unsupported test location %q", location)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPreMTUStateV1V2RejectNewFieldRegardlessOfValueOrCasing(t *testing.T) {
	modes := []struct {
		name, key, raw string
	}{
		{"manual", "mtu", `{"mode":"manual","bytes":1300}`},
		{"auto", "mtu", `{"mode":"auto"}`},
		{"explicit_unmanaged", "mtu", `{"mode":"unmanaged"}`},
		{"empty_object", "mtu", `{}`},
		{"null_value", "mtu", "null"},
		{"uppercase_key", "MTU", `{"mode":"auto"}`},
		{"mixed_case_key", "mTu", `{"mode":"manual","bytes":1300}`},
	}
	for _, version := range []int{legacySchemaVersion, preMTUSchemaVersion} {
		for _, tc := range modes {
			t.Run(fmt.Sprintf("v%d/%s", version, tc.name), func(t *testing.T) {
				root := t.TempDir()
				raw := mtuStateTestDocument(t, version, tc.key, tc.raw, "committed")
				if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0o600); err != nil {
					t.Fatal(err)
				}
				_, err := NewFileStore(root).Load(context.Background())
				if err == nil || !strings.Contains(err.Error(), "cannot contain MTU policy") {
					t.Fatalf("pre-MTU state accepted a new field, or failed for the wrong reason: %v", err)
				}
			})
		}
	}
}

func TestPreMTUStateV2RejectsMTUInsideUncommittedIntentsAndJournals(t *testing.T) {
	for _, location := range []string{"pending", "nested_journal"} {
		t.Run(location, func(t *testing.T) {
			root := t.TempDir()
			raw := mtuStateTestDocument(t, preMTUSchemaVersion, "mtu",
				`{"mode":"auto"}`, location)
			if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := NewFileStore(root).Load(context.Background())
			if err == nil || !strings.Contains(err.Error(), "cannot contain MTU policy") {
				t.Fatalf("nested pre-MTU state field was admitted: %v", err)
			}
		})
	}
}

func TestGenuinePreMTUStateMigratesWithoutManagedWrites(t *testing.T) {
	for _, version := range []int{legacySchemaVersion, preMTUSchemaVersion} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			root := t.TempDir()
			raw := mtuStateTestDocument(t, version, "", "", "committed")
			if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			store := NewFileStore(root)
			loaded, err := store.Load(context.Background())
			if err != nil || loaded.SchemaVersion != SchemaVersion ||
				len(loaded.Links) != 1 || loaded.Links[0].Desired.MTU != (domain.MTUPolicy{}) {
				t.Fatalf("pre-MTU state failed safe in-memory migration: %+v, %v", loaded, err)
			}
			if err := store.Update(context.Background(), func(*Snapshot) error { return nil }); err != nil {
				t.Fatal(err)
			}
			persisted, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(persisted, []byte(`"schema_version": 3`)) ||
				bytes.Contains(persisted, []byte(`"mtu"`)) {
				t.Fatalf("migrated state gained a managed MTU or was not published as v3")
			}
		})
	}
}

func TestCurrentStateV3RoundTripsManagedAndUnmanagedPolicies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy domain.MTUPolicy
	}{
		{"auto", domain.MTUPolicy{Mode: domain.MTUAuto}},
		{"manual", domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1300}},
		{"explicit_unmanaged", domain.MTUPolicy{Mode: domain.MTUUnmanagedExplicit}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			store := NewFileStore(root)
			link := testLink(t, domain.LinkID("lnk_33333333333333333333333333333333"),
				"10.80.42.0/31", "10.80.42.1/31")
			link.MTU = tc.policy
			if err := store.Update(context.Background(), func(s *Snapshot) error {
				s.Upsert(LinkRecord{Desired: link})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Load(context.Background())
			if err != nil || loaded.SchemaVersion != SchemaVersion ||
				len(loaded.Links) != 1 || loaded.Links[0].Desired.MTU != tc.policy {
				t.Fatalf("v3 policy did not round-trip: %+v, %v", loaded, err)
			}
		})
	}
}

func TestCurrentStateV3RejectsUnknownNestedMTUFields(t *testing.T) {
	root := t.TempDir()
	raw := mtuStateTestDocument(t, SchemaVersion, "mtu",
		`{"mode":"manual","bytes":1300,"unexpected":true}`, "committed")
	if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewFileStore(root).Load(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown nested MTU field was accepted: %v", err)
	}
}
