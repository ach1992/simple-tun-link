package linux

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const wssWGIngressPriority = -250

// WSSWGIngressPlan renders the exact nft ingress guard used by the
// unreleased, STL-managed WSS+kernel-WireGuard candidate. It is a pure
// plan and does not independently execute host effects. The canonical
// Engine invokes the scoped host executor only after resource/ownership
// admission and durable WSS pre-effect intent, with crash quarantine.
// A kernel WG listener binds more than loopback even when its configured
// peer endpoint is 127.0.0.1. Table names and comments alone are never
// ownership proofs; uncertain host effects must remain quarantined.
type WSSWGIngressPlan struct {
	LinkID        domain.LinkID
	ListenPort    uint16
	OriginalNonce string
}

func NewWSSWGIngressPlan(id domain.LinkID, listenPort uint16) (WSSWGIngressPlan, error) {
	p := WSSWGIngressPlan{LinkID: id, ListenPort: listenPort}
	if err := p.validate(); err != nil {
		return WSSWGIngressPlan{}, err
	}
	return p, nil
}

func (p WSSWGIngressPlan) validate() error {
	if err := p.LinkID.Validate(); err != nil {
		return fmt.Errorf("WSS WireGuard ingress Link identity: %w", err)
	}
	if p.ListenPort == 0 {
		return fmt.Errorf("WSS WireGuard ingress requires a nonzero kernel UDP listen port")
	}
	if p.OriginalNonce != "" {
		raw, err := hex.DecodeString(p.OriginalNonce)
		if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != p.OriginalNonce {
			return fmt.Errorf("invalid WSS original nft guard identity")
		}
	}
	return nil
}

// TableName identifies a reserved, per-Link nft object. It is not
// permission to adopt or delete a table with a matching name.
func (p WSSWGIngressPlan) TableName() string { return p.tableName() }

func (p WSSWGIngressPlan) tableName() string {
	hash := sha256.Sum256([]byte(p.LinkID))
	return fmt.Sprintf("stlwss_%x", hash[:8])
}

func (p WSSWGIngressPlan) ruleComment() string {
	tag := "stl:" + string(p.LinkID) + ":wg-udp-guard:" + strconv.Itoa(int(p.ListenPort))
	if p.OriginalNonce != "" {
		tag += ":tx:" + p.OriginalNonce
	}
	return tag
}

// NFTBatch returns the exact single nftables transaction for an *absent*
// per-Link table. Exclusive nft "create" operations must fail atomically
// if a foreign table/chain already exists (even after an absence preflight).
// It never executes anything. An existing table must NOT be adopted, flushed,
// replaced or deleted by matching its name or marker.
//
// An inet/input chain at priority -250 gives a UDP DROP on non-loopback
// interfaces, regardless of an earlier ACCEPT in the standard INPUT filter
// chain. The nonmatching chain policy remains ACCEPT so unrelated traffic
// continues to encounter its ordinary host policy. This does not prove
// compatibility with every foreign nft/prerouting/bridge ruleset, nor protect
// against later rule changes or other network namespaces.
func (p WSSWGIngressPlan) NFTBatch() (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	table := p.tableName()
	return fmt.Sprintf(
		"create table inet %s\n"+
			"create chain inet %s ingress { type filter hook input priority %d; policy accept; }\n"+
			"add rule inet %s ingress iifname != \"lo\" udp dport %d counter drop comment \"%s\"\n",
		table, table, wssWGIngressPriority, table, p.ListenPort, p.ruleComment(),
	), nil
}

type wssNFTDump struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type wssNFTTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle uint64 `json:"handle"`
}

type wssNFTChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle uint64 `json:"handle"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
}

type wssNFTRule struct {
	Family  string                       `json:"family"`
	Table   string                       `json:"table"`
	Chain   string                       `json:"chain"`
	Handle  uint64                       `json:"handle"`
	Comment string                       `json:"comment"`
	Expr    []map[string]json.RawMessage `json:"expr"`
}

func decodeWSSNFTObject(data json.RawMessage, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON data")
	}
	return nil
}

func wssJSONEqual(actual json.RawMessage, expected string) bool {
	var left, right any
	if json.Unmarshal(actual, &left) != nil || json.Unmarshal([]byte(expected), &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

// VerifyNFTJSON checks the exact contents of an nft -j list table inet
// <per-Link-table> response, ignoring only dynamic handles/counter values
// and one nft metadata object. It is read-only evidence about one table,
// NOT proof of original ownership, physical packet isolation, or the absence
// of higher-priority foreign hooks. On any ambiguity it rejects the result.
func (p WSSWGIngressPlan) VerifyNFTJSON(raw []byte) error {
	if err := p.validate(); err != nil {
		return err
	}
	var dump wssNFTDump
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&dump); err != nil {
		return fmt.Errorf("WSS ingress nftables JSON is invalid: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("WSS ingress nftables output has unexpected trailing data")
	}
	table, chain, rule, metadata := 0, 0, 0, 0
	for _, item := range dump.Nftables {
		if len(item) != 1 {
			return fmt.Errorf("WSS ingress nftables entry has unexpected shape")
		}
		for kind, rawObject := range item {
			switch kind {
			case "metainfo":
				metadata++
				if metadata != 1 {
					return fmt.Errorf("WSS ingress nftables metadata is duplicated")
				}
			case "table":
				table++
				var t wssNFTTable
				if err := decodeWSSNFTObject(rawObject, &t); err != nil ||
					t.Family != "inet" || t.Name != p.tableName() || t.Handle == 0 {
					return fmt.Errorf("WSS ingress table identity differs from the planned table")
				}
			case "chain":
				chain++
				var c wssNFTChain
				if err := decodeWSSNFTObject(rawObject, &c); err != nil ||
					c.Family != "inet" || c.Table != p.tableName() ||
					c.Name != "ingress" || c.Handle == 0 ||
					c.Type != "filter" || c.Hook != "input" ||
					c.Prio != wssWGIngressPriority || c.Policy != "accept" {
					return fmt.Errorf("WSS ingress chain does not match the planned hook and policy")
				}
			case "rule":
				rule++
				var r wssNFTRule
				if err := decodeWSSNFTObject(rawObject, &r); err != nil ||
					r.Family != "inet" || r.Table != p.tableName() ||
					r.Chain != "ingress" || r.Handle == 0 ||
					r.Comment != p.ruleComment() || len(r.Expr) != 4 {
					return fmt.Errorf("WSS ingress rule identity or expression count differs from the plan")
				}
				if len(r.Expr[0]) != 1 ||
					!wssJSONEqual(r.Expr[0]["match"], `{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"lo"}`) ||
					len(r.Expr[1]) != 1 ||
					!wssJSONEqual(r.Expr[1]["match"], fmt.Sprintf(`{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":%d}`, p.ListenPort)) ||
					len(r.Expr[2]) != 1 || len(r.Expr[3]) != 1 {
					return fmt.Errorf("WSS ingress matching conditions were altered")
				}
				var counter struct {
					Packets *uint64 `json:"packets"`
					Bytes   *uint64 `json:"bytes"`
				}
				if err := decodeWSSNFTObject(r.Expr[2]["counter"], &counter); err != nil ||
					counter.Packets == nil || counter.Bytes == nil {
					return fmt.Errorf("WSS ingress counter is invalid")
				}
				drop, ok := r.Expr[3]["drop"]
				if !ok || string(drop) != "null" {
					return fmt.Errorf("WSS ingress is not an unconditional UDP drop")
				}
			default:
				return fmt.Errorf("WSS ingress nftables contains an unexpected %s object", kind)
			}
		}
	}
	if table != 1 || chain != 1 || rule != 1 {
		return fmt.Errorf("WSS ingress must contain exactly one table, hook and drop rule")
	}
	return nil
}
