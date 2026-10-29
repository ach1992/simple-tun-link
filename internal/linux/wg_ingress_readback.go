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

// WGIngressLiveHandles identifies one verified live nft table, chain and rule
// in a single observed namespace. Handles may be recycled on replacement and
// are never durable original ownership or removal authority by themselves.
type WGIngressLiveHandles struct {
	Table uint64
	Chain uint64
	Rule  uint64
}

// InspectWGIngressGuard never uses an unsuccessful exact-table lookup as
// evidence of absence. It requires a complete nft table census before a
// strict full-object readback. The caller still owns the original journal,
// exclusive create and resource-lock requirements. Its existing WSS and QUIC
// boolean-only contract intentionally does not require handle readback.
func InspectWGIngressGuard(ctx context.Context, runner BoundedRunner, guard WGIngressGuardReader) (bool, error) {
	present, _, err := inspectWGIngressGuard(ctx, runner, guard, false)
	return present, err
}

// ReadWGIngressGuardHandles uses the identical strict WSS/QUIC read-only guard
// validation plus positive kernel object handles and consistency between
// the table census and exact table readback. Absence or equal-looking bytes
// are NEVER proof that STL originally created the resource; this function
// does not mutate, adopt, release, re-create or grant retirement permission.
func ReadWGIngressGuardHandles(ctx context.Context, runner BoundedRunner, guard WGIngressGuardReader) (bool, WGIngressLiveHandles, error) {
	return inspectWGIngressGuard(ctx, runner, guard, true)
}

func inspectWGIngressGuard(ctx context.Context, runner BoundedRunner, guard WGIngressGuardReader, requireHandles bool) (bool, WGIngressLiveHandles, error) {
	if ctx == nil || runner == nil || guard == nil || guard.TableName() == "" {
		return false, WGIngressLiveHandles{}, fmt.Errorf("complete WG ingress inspection inputs required")
	}
	if err := ctx.Err(); err != nil {
		return false, WGIngressLiveHandles{}, err
	}
	out, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 8 << 20, Stderr: 64 << 10}, "nft", "-j", "list", "tables")
	if err != nil || ctx.Err() != nil || len(out.Stdout) > 8<<20 || len(out.Stderr) != 0 {
		return false, WGIngressLiveHandles{}, fmt.Errorf("nft table inventory unavailable or incomplete")
	}
	if err := ValidateWSSWGJSONMembers(out.Stdout); err != nil {
		return false, WGIngressLiveHandles{}, fmt.Errorf("ambiguous nft table inventory")
	}
	var inventory struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil || inventory.Nftables == nil {
		return false, WGIngressLiveHandles{}, fmt.Errorf("incomplete nft table inventory")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false, WGIngressLiveHandles{}, fmt.Errorf("nft table inventory has trailing content")
	}
	found, metadata := false, 0
	var inventoryHandle uint64
	seen := make(map[string]bool)
	for _, entry := range inventory.Nftables {
		if len(entry) != 1 {
			return false, WGIngressLiveHandles{}, fmt.Errorf("ambiguous nft table inventory entry")
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
					return false, WGIngressLiveHandles{}, fmt.Errorf("unsupported nft table inventory metadata")
				}
				metadata++
			case "table":
				var row struct {
					Family string `json:"family"`
					Name   string `json:"name"`
					Handle uint64 `json:"handle,omitempty"`
				}
				if strictWGIngressJSON(raw, &row) != nil || row.Name == "" || !wgIngressTableFamily(row.Family) {
					return false, WGIngressLiveHandles{}, fmt.Errorf("invalid nft table inventory row")
				}
				key := row.Family + "\x00" + row.Name
				if seen[key] {
					return false, WGIngressLiveHandles{}, fmt.Errorf("duplicate nft table identity")
				}
				seen[key] = true
				if row.Name == guard.TableName() && row.Family == "inet" {
					found = true
					inventoryHandle = row.Handle
					if requireHandles && row.Handle == 0 {
						return false, WGIngressLiveHandles{}, fmt.Errorf("nft guard table census handle unavailable")
					}
				}
			default:
				return false, WGIngressLiveHandles{}, fmt.Errorf("unsupported nft table inventory object")
			}
		}
	}
	if metadata != 1 || ctx.Err() != nil {
		return false, WGIngressLiveHandles{}, fmt.Errorf("incomplete nft table inventory metadata or observation")
	}
	if !found {
		return false, WGIngressLiveHandles{}, nil
	}
	table, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 1 << 20, Stderr: 64 << 10},
		"nft", "-j", "list", "table", "inet", guard.TableName())
	if err != nil || ctx.Err() != nil || len(table.Stdout) > 1<<20 || len(table.Stderr) != 0 {
		return false, WGIngressLiveHandles{}, fmt.Errorf("WG ingress table readback unavailable or incomplete")
	}
	if err := guard.VerifyNFTJSON(table.Stdout); err != nil {
		return false, WGIngressLiveHandles{}, fmt.Errorf("foreign or malformed WG ingress table")
	}
	if !requireHandles {
		return true, WGIngressLiveHandles{}, nil
	}
	handles, err := parseVerifiedWGIngressHandles(table.Stdout)
	if err != nil || handles.Table != inventoryHandle {
		return false, WGIngressLiveHandles{}, fmt.Errorf("WG ingress nft table object identity changed during observation")
	}
	return true, handles, nil
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

// parseVerifiedWGIngressHandles runs only after the original strict guard
// verifier accepted the complete table/chain/rule shape and member syntax.
// Dynamic nft handles here are nonsecret, but must not be trusted without
// the prior exact journal-derived guard verification and full table census.
func parseVerifiedWGIngressHandles(raw []byte) (WGIngressLiveHandles, error) {
	var dump wssNFTDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return WGIngressLiveHandles{}, fmt.Errorf("WG ingress handle inventory invalid")
	}
	var handles WGIngressLiveHandles
	tableCount, chainCount, ruleCount := 0, 0, 0
	for _, entry := range dump.Nftables {
		for kind, value := range entry {
			switch kind {
			case "table":
				var v wssNFTTable
				if decodeWSSNFTObject(value, &v) != nil {
					return WGIngressLiveHandles{}, fmt.Errorf("WG ingress table handle invalid")
				}
				handles.Table = v.Handle
				tableCount++
			case "chain":
				var v wssNFTChain
				if decodeWSSNFTObject(value, &v) != nil {
					return WGIngressLiveHandles{}, fmt.Errorf("WG ingress chain handle invalid")
				}
				handles.Chain = v.Handle
				chainCount++
			case "rule":
				var v wssNFTRule
				if decodeWSSNFTObject(value, &v) != nil {
					return WGIngressLiveHandles{}, fmt.Errorf("WG ingress rule handle invalid")
				}
				handles.Rule = v.Handle
				ruleCount++
			}
		}
	}
	if tableCount != 1 || chainCount != 1 || ruleCount != 1 ||
		handles.Table == 0 || handles.Chain == 0 || handles.Rule == 0 {
		return WGIngressLiveHandles{}, fmt.Errorf("WG ingress live handles incomplete or ambiguous")
	}
	return handles, nil
}
