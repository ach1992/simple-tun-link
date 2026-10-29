package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// WGIngressGuardReader is implemented by the existing WSS and QUIC ingress
// plans. This read-only inspector provides a shared, complete absence/strict
// presence decision; table names, comments and matching bytes alone do not
// establish original creation ownership.
type WGIngressGuardReader interface {
	TableName() string
	VerifyNFTJSON([]byte) error
}

// InspectWGIngressGuard never uses an unsuccessful exact-table lookup as
// evidence of absence. It requires a complete nft table census before a
// strict full-object readback. The caller still owns the original journal,
// exclusive create and resource-lock requirements.
func InspectWGIngressGuard(ctx context.Context, runner BoundedRunner, guard WGIngressGuardReader) (bool, error) {
	if ctx == nil || runner == nil || guard == nil || guard.TableName() == "" {
		return false, fmt.Errorf("complete WG ingress inspection inputs required")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	out, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 8 << 20, Stderr: 64 << 10}, "nft", "-j", "list", "tables")
	if err != nil || ctx.Err() != nil || len(out.Stdout) > 8<<20 || len(out.Stderr) != 0 {
		return false, fmt.Errorf("nft table inventory unavailable or incomplete")
	}
	if err := ValidateWSSWGJSONMembers(out.Stdout); err != nil {
		return false, fmt.Errorf("ambiguous nft table inventory")
	}
	var inventory struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil || inventory.Nftables == nil {
		return false, fmt.Errorf("incomplete nft table inventory")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false, fmt.Errorf("nft table inventory has trailing content")
	}
	found, metadata := false, 0
	seen := make(map[string]bool)
	for _, entry := range inventory.Nftables {
		if len(entry) != 1 {
			return false, fmt.Errorf("ambiguous nft table inventory entry")
		}
		for kind, raw := range entry {
			switch kind {
			case "metainfo":
				var meta struct {
					Version           string `json:"version"`
					ReleaseName       string `json:"release_name"`
					JSONSchemaVersion int    `json:"json_schema_version"`
				}
				if strictWGIngressJSON(raw, &meta) != nil || meta.Version == "" || meta.JSONSchemaVersion != 1 || metadata != 0 {
					return false, fmt.Errorf("unsupported nft table inventory metadata")
				}
				metadata++
			case "table":
				var row struct {
					Family string `json:"family"`
					Name   string `json:"name"`
					Handle uint64 `json:"handle,omitempty"`
				}
				if strictWGIngressJSON(raw, &row) != nil || row.Name == "" || !wgIngressTableFamily(row.Family) {
					return false, fmt.Errorf("invalid nft table inventory row")
				}
				key := row.Family + "\x00" + row.Name
				if seen[key] {
					return false, fmt.Errorf("duplicate nft table identity")
				}
				seen[key] = true
				if row.Name == guard.TableName() && row.Family == "inet" {
					found = true
				}
			default:
				return false, fmt.Errorf("unsupported nft table inventory object")
			}
		}
	}
	if metadata != 1 || ctx.Err() != nil {
		return false, fmt.Errorf("incomplete nft table inventory metadata or observation")
	}
	if !found {
		return false, nil
	}
	table, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 1 << 20, Stderr: 64 << 10},
		"nft", "-j", "list", "table", "inet", guard.TableName())
	if err != nil || ctx.Err() != nil || len(table.Stdout) > 1<<20 || len(table.Stderr) != 0 {
		return false, fmt.Errorf("WG ingress table readback unavailable or incomplete")
	}
	if err := guard.VerifyNFTJSON(table.Stdout); err != nil {
		return false, fmt.Errorf("foreign or malformed WG ingress table")
	}
	return true, nil
}

func strictWGIngressJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON member")
	}
	return nil
}

func wgIngressTableFamily(family string) bool {
	switch family {
	case "inet", "ip", "ip6", "arp", "bridge", "netdev":
		return true
	}
	return false
}
