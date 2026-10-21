package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// WSSWGFirewallEvidence is a point-in-time, read-only host firewall inventory
// for the NON-RUNNABLE WSS/WireGuard ingress design. The future caller must
// obtain successful, bounded readbacks of:
//   - nft -j list ruleset
//   - iptables -V and ip6tables -V
//   - iptables-legacy-save and ip6tables-legacy-save (without -c)
//
// A nil legacy snapshot means collection failed or was not attempted; a
// non-nil empty byte slice means the command succeeded with empty stdout.
// Never log these inventories: foreign rules may contain private data.
type WSSWGFirewallEvidence struct {
	NFTRuleset   []byte
	IPTablesV4   string
	IPTablesV6   string
	LegacySaveV4 []byte
	LegacySaveV6 []byte
}

// CheckWSSWGFirewallCoexistence rejects known and unknown host firewall
// interference with the proposed *new* per-Link WG ingress guard. A nil
// error means only that the supplied snapshots exhibit no classified
// conflict. It does NOT grant activation, prove effective packet isolation,
// certify snapshot freshness, reserve ports, or establish table ownership.
// A future Engine caller must coordinate resource locks, a durable journal,
// actual host capabilities, exclusive apply, readback, drift, compensation
// and independent Owner security/host-effects approval.
func (p WSSWGIngressPlan) CheckWSSWGFirewallCoexistence(e WSSWGFirewallEvidence) error {
	if err := p.CheckWSSWGNFTCoexistence(e.NFTRuleset); err != nil {
		return err
	}
	for _, entry := range []struct {
		family  string
		version string
		legacy  []byte
	}{
		{"IPv4", e.IPTablesV4, e.LegacySaveV4},
		{"IPv6", e.IPTablesV6, e.LegacySaveV6},
	} {
		// The active frontend version does NOT exclude dormant legacy hooks.
		// Inspect both families' legacy rules in addition to the nft dump.
		version := strings.TrimSpace(entry.version)
		prefix := "iptables v1."
		if entry.family == "IPv6" {
			prefix = "ip6tables v1."
		}
		if len(strings.Fields(version)) != 3 || strings.ContainsAny(version, "\r\n") ||
			!strings.HasPrefix(version, prefix) || !strings.HasSuffix(version, " (nf_tables)") {
			return fmt.Errorf("WSS WG %s iptables backend is unknown or not nf_tables", entry.family)
		}
		if err := inspectWSSWGLegacySave(entry.legacy); err != nil {
			return fmt.Errorf("WSS WG %s legacy iptables coexistence is unverified: %w", entry.family, err)
		}
	}
	return nil
}

func inspectWSSWGLegacySave(saved []byte) error {
	if saved == nil {
		return fmt.Errorf("successful legacy readback was not supplied")
	}
	// The command's successful exit is required independently. An empty
	// successful snapshot is legitimate when no legacy tables are loaded.
	inTable := false
	for _, raw := range strings.Split(string(saved), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "*") && !inTable:
			name := strings.TrimPrefix(line, "*")
			if name == "" || strings.ContainsAny(name, " \t\r*") {
				return fmt.Errorf("malformed legacy table header")
			}
			inTable = true
		case line == "COMMIT" && inTable:
			inTable = false
		case strings.HasPrefix(line, ":") && inTable:
			// Accept only completely empty, permissive built-in chains.
			// Non-ACCEPT policy or -A/-N rules may affect the future guard.
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[1] != "ACCEPT" ||
				!strings.HasPrefix(fields[2], "[") || !strings.HasSuffix(fields[2], "]") {
				return fmt.Errorf("legacy firewall contains a nontrivial chain or policy")
			}
			for _, c := range fields[0][1:] {
				if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
					return fmt.Errorf("malformed legacy chain name")
				}
			}
			if len(fields[0]) == 1 {
				return fmt.Errorf("empty legacy chain name")
			}
			counts := strings.Split(strings.Trim(fields[2], "[]"), ":")
			if len(counts) != 2 {
				return fmt.Errorf("malformed legacy chain counters")
			}
			for _, count := range counts {
				if _, err := strconv.ParseUint(count, 10, 64); err != nil {
					return fmt.Errorf("malformed legacy chain counter")
				}
			}
		default:
			return fmt.Errorf("legacy firewall contains rules or unrecognized policy")
		}
	}
	if inTable {
		return fmt.Errorf("legacy firewall snapshot is incomplete")
	}
	return nil
}

// ProbeWSSWGFirewallCoexistence performs only fixed, bounded, read-only
// firewall queries. It does not acquire locks, run nft transactions, create
// rules, or authorize applying a guard. The Engine must later re-check the
// host under its own admission locks and durable intent before any effects.
// The trusted caller must use a trusted execution PATH/binary provenance.
func (p WSSWGIngressPlan) ProbeWSSWGFirewallCoexistence(ctx context.Context, runner BoundedRunner) error {
	if err := p.validate(); err != nil {
		return err
	}
	if runner == nil {
		return fmt.Errorf("WSS WG host firewall probe requires a bounded runner")
	}
	read := func(stage, executable string, cap int, args ...string) ([]byte, error) {
		result, err := runner.RunBounded(ctx, CaptureLimits{Stdout: cap, Stderr: 64 << 10}, executable, args...)
		if err != nil {
			// Never include raw stdout/stderr: firewall comments may contain
			// foreign application credentials or private host metadata.
			return nil, fmt.Errorf("WSS WG %s readback failed: %w", stage, err)
		}
		if len(bytes.TrimSpace(result.Stderr)) != 0 {
			return nil, fmt.Errorf("WSS WG %s readback reported unexpected stderr", stage)
		}
		return result.Stdout, nil
	}
	var e WSSWGFirewallEvidence
	var err error
	if e.NFTRuleset, err = read("nft", "nft", 8<<20, "-j", "list", "ruleset"); err != nil {
		return err
	}
	if version, versionErr := read("iptables version", "iptables", 512, "-V"); versionErr != nil {
		return versionErr
	} else {
		e.IPTablesV4 = string(version)
	}
	if version, versionErr := read("ip6tables version", "ip6tables", 512, "-V"); versionErr != nil {
		return versionErr
	} else {
		e.IPTablesV6 = string(version)
	}
	if e.LegacySaveV4, err = read("IPv4 legacy", "iptables-legacy-save", 2<<20); err != nil {
		return err
	}
	if e.LegacySaveV6, err = read("IPv6 legacy", "ip6tables-legacy-save", 2<<20); err != nil {
		return err
	}
	// Normalize a verified successful empty stdout to distinguish it
	// from a missing/failed legacy snapshot in the pure verifier.
	e.LegacySaveV4 = append([]byte{}, e.LegacySaveV4...)
	e.LegacySaveV6 = append([]byte{}, e.LegacySaveV6...)
	return p.CheckWSSWGFirewallCoexistence(e)
}

type wssWGHostChain struct {
	Family string          `json:"family"`
	Table  string          `json:"table"`
	Name   string          `json:"name"`
	Hook   string          `json:"hook"`
	Prio   json.RawMessage `json:"prio"`
	Policy string          `json:"policy"`
}

type wssWGHostRule struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Expr   []json.RawMessage `json:"expr"`
}

func wssWGChainKey(family, table, name string) string {
	return family + "\x00" + table + "\x00" + name
}

// CheckWSSWGNFTCoexistence evaluates a full "nft -j list ruleset"
// snapshot, not the existing per-table readback checked by VerifyNFTJSON.
// Rejecting a chain is deliberately conservative: it needs an explicit
// compatibility review, not a global flush, override or foreign adoption.
// Common later-priority INPUT ACCEPT rules cannot bypass the earlier DROP.
func (p WSSWGIngressPlan) CheckWSSWGNFTCoexistence(raw []byte) error {
	if err := p.validate(); err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > 8<<20 {
		return fmt.Errorf("WSS WG nft ruleset snapshot absent or exceeds bounded inspection size")
	}
	var dump wssNFTDump
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&dump); err != nil || dump.Nftables == nil {
		return fmt.Errorf("WSS WG nft ruleset JSON is invalid")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("WSS WG nft ruleset has trailing data")
	}
	tables := map[string]bool{}
	chains := map[string]wssWGHostChain{}
	ruleCount := map[string]int{}
	for _, item := range dump.Nftables {
		if len(item) != 1 {
			return fmt.Errorf("WSS WG nft ruleset entry has unexpected shape")
		}
		for kind, data := range item {
			switch kind {
			case "metainfo":
				if !json.Valid(data) {
					return fmt.Errorf("WSS WG nft metadata is invalid")
				}
			case "table":
				var t struct {
					Family string `json:"family"`
					Name   string `json:"name"`
				}
				if json.Unmarshal(data, &t) != nil || t.Family == "" || t.Name == "" {
					return fmt.Errorf("WSS WG nft table is invalid")
				}
				if t.Family == "inet" && t.Name == p.tableName() {
					return fmt.Errorf("WSS WG ingress table name already exists; never adopt by name")
				}
				key := wssWGChainKey(t.Family, t.Name, "")
				if tables[key] {
					return fmt.Errorf("WSS WG nft table identity is duplicated")
				}
				tables[key] = true
			case "chain":
				var c wssWGHostChain
				if json.Unmarshal(data, &c) != nil ||
					c.Family == "" || c.Table == "" || c.Name == "" {
					return fmt.Errorf("WSS WG nft chain is invalid")
				}
				key := wssWGChainKey(c.Family, c.Table, c.Name)
				if _, exists := chains[key]; exists {
					return fmt.Errorf("WSS WG nft chain identity is duplicated")
				}
				chains[key] = c
			case "rule":
				var r wssWGHostRule
				if json.Unmarshal(data, &r) != nil ||
					r.Family == "" || r.Table == "" || r.Chain == "" || len(r.Expr) == 0 {
					return fmt.Errorf("WSS WG nft rule is invalid")
				}
				ruleCount[wssWGChainKey(r.Family, r.Table, r.Chain)]++
			case "set", "element", "map", "counter", "quota", "limit", "ct helper", "ct timeout", "ct expectation", "secmark":
				// Only rules referenced from hazardous hooks can affect input.
				if !json.Valid(data) {
					return fmt.Errorf("WSS WG nft auxiliary object is invalid")
				}
			default:
				// Flowtables and unrecognized object types need separate
				// traffic-path analysis before a runtime admission decision.
				return fmt.Errorf("WSS WG nft ruleset has unsupported object kind")
			}
		}
	}
	for key, c := range chains {
		if !tables[wssWGChainKey(c.Family, c.Table, "")] {
			return fmt.Errorf("WSS WG nft chain has no containing table")
		}
		if c.Hook == "" {
			if len(c.Prio) != 0 || c.Policy != "" {
				return fmt.Errorf("WSS WG nft unhooked chain has conflicting base-chain properties")
			}
			continue
		}
		switch c.Hook {
		case "ingress", "prerouting", "input", "output", "forward", "postrouting":
		default:
			return fmt.Errorf("WSS WG nft has unknown hooked chain")
		}
		if len(c.Prio) == 0 {
			return fmt.Errorf("WSS WG nft base-chain priority cannot be inspected")
		}
		var priority int
		if json.Unmarshal(c.Prio, &priority) != nil {
			return fmt.Errorf("WSS WG nft base-chain priority is unsupported")
		}
		if c.Policy != "accept" && c.Policy != "drop" {
			return fmt.Errorf("WSS WG nft base-chain policy is unsupported")
		}
		// Any rule at ingress/prerouting may transform the path before
		// input. Earlier-or-equal priority input chains are opaque too.
		// A later input ACCEPT cannot cancel an earlier DROP.
		earlier := c.Hook == "ingress" || c.Hook == "prerouting" ||
			(c.Hook == "input" && priority <= wssWGIngressPriority)
		if earlier && (c.Policy != "accept" || ruleCount[key] != 0) {
			return fmt.Errorf("WSS WG nft contains an active foreign pre-guard hook")
		}
	}
	for key := range ruleCount {
		if _, ok := chains[key]; !ok {
			return fmt.Errorf("WSS WG nft rule refers to an unknown chain")
		}
	}
	return nil
}
