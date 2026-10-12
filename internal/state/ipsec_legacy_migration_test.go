package state

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacySchemaRejectsAllLifecycleFields(t *testing.T) {
	id := "lnk_11111111111111111111111111111111"
	payloads := map[string]any{
		"pending_senders":          []any{map[string]any{}},
		"pending_ipsec":            []any{map[string]any{}},
		"ipsec_vici_operations":    []any{map[string]any{"nonce": "x"}},
		"ipsec_reapply_operations": []any{map[string]any{"nonce": "x"}},
		"ipsec_remove_operations":  []any{map[string]any{"nonce": "x"}},
		"ipsec_xfrm_operations":    []any{map[string]any{"nonce": "x"}},
		"ipsec_removal_receipts":   []any{map[string]any{"link_id": id}},
		"removal_receipts":         []any{map[string]any{"link_id": id}},
	}
	for field, record := range payloads {
		t.Run(field, func(t *testing.T) {
			root := t.TempDir()
			encoded, err := json.Marshal(map[string]any{"schema_version": 1, "links": []any{}, field: record})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "state.json"), encoded, 0600); err != nil {
				t.Fatal(err)
			}
			_, err = NewFileStore(root).Load(context.Background())
			if err == nil || !strings.Contains(err.Error(), "legacy state") {
				t.Fatalf("schema v1 illegally admitted %s: %v", field, err)
			}
		})
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "state.json"), []byte(`{"schema_version":1,"links":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	snap, err := NewFileStore(root).Load(context.Background())
	if err != nil || snap.SchemaVersion != SchemaVersion {
		t.Fatalf("historical v1 not migrated: %+v %v", snap, err)
	}
}
