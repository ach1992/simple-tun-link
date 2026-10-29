package linux

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// QUICWGIngressPlan is a source-only, transport-isolated kernel WireGuard
// UDP guard. It reuses the exact WSS nft renderer and readback verifier,
// with a QUIC-specific table and an immutable journal-nonce-bound marker.
// None of these methods execute nftables or establish original ownership.
type QUICWGIngressPlan struct {
	LinkID        domain.LinkID
	ListenPort    uint16
	OriginalNonce string
}

func NewQUICWGIngressPlan(id domain.LinkID, port uint16, nonce string) (QUICWGIngressPlan, error) {
	p := QUICWGIngressPlan{LinkID: id, ListenPort: port, OriginalNonce: nonce}
	if err := p.spec().validate(); err != nil {
		return QUICWGIngressPlan{}, err
	}
	return p, nil
}

func (p QUICWGIngressPlan) spec() wgIngressSpec {
	return wgIngressSpec{
		linkID: p.LinkID, listenPort: p.ListenPort,
		originalNonce: p.OriginalNonce, carrier: "quic",
	}
}
func (p QUICWGIngressPlan) TableName() string              { return p.spec().tableName() }
func (p QUICWGIngressPlan) NFTBatch() (string, error)      { return p.spec().NFTBatch() }
func (p QUICWGIngressPlan) VerifyNFTJSON(raw []byte) error { return p.spec().VerifyNFTJSON(raw) }

// QUICWGOwnerTag identifies an original QUIC kernel-WG generation, never a
// WSS generation with the same Link ID/nonce. The positive original creation
// and exact ifindex still need separate kernel readback; a marker alone is
// never permission to adopt, rename, remove or recover an interface.
func QUICWGOwnerTag(id domain.LinkID, nonce string) (string, error) {
	if id.Validate() != nil {
		return "", fmt.Errorf("invalid QUIC kernel WG Link identity")
	}
	raw, err := hex.DecodeString(nonce)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != nonce {
		return "", fmt.Errorf("invalid QUIC kernel WG journal nonce")
	}
	return "stl:quic:" + string(id) + ":tx:" + nonce, nil
}

func ParseQUICWGOwnerTag(tag string) (domain.LinkID, string, bool) {
	if !strings.HasPrefix(tag, "stl:quic:") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(tag, "stl:quic:"), ":tx:")
	if len(parts) != 2 {
		return "", "", false
	}
	id := domain.LinkID(parts[0])
	want, err := QUICWGOwnerTag(id, parts[1])
	if err != nil || tag != want {
		return "", "", false
	}
	return id, parts[1], true
}

// QUICWGStagingName is generated from the complete immutable journal intent
// *before* any exclusive RTM_NEWLINK; an interrupted creation retains a
// nonce-derived original name instead of an anonymous new WireGuard device.
// The 70-bit value is distinct from the WSS staging namespace and is not,
// alone, proof of original kernel ownership or deletion authority.
func QUICWGStagingName(id domain.LinkID, nonce string) (string, error) {
	if _, err := QUICWGOwnerTag(id, nonce); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(string(id) + ":quic:" + nonce))
	part := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
	return "q" + part[:14], nil
}

// CreateQUICWireGuardStaged reuses the tested exclusive WSS kernel creator,
// but only after validating the *different* QUIC temporary name namespace.
// No caller may invoke it without the canonical Engine's pre-effect journal,
// held Link/resource locks and separate reviewed host-effect ownership gate.
func CreateQUICWireGuardStaged(ctx context.Context, name string) error {
	if !validWireGuardStagingName(name, 'q') {
		return fmt.Errorf("invalid exact QUIC temporary kernel identity")
	}
	return createWireGuardStaged(ctx, name)
}

// QUICWGHostOrigin binds the same Engine-generated nonce to the kernel
// original marker, exclusive pre-alias creation name and ingress guard.
// A successful plan is pure identity data, not proof of a created resource.
type QUICWGHostOrigin struct {
	OwnerTag    string
	StagingName string
	Guard       QUICWGIngressPlan
}

func PlanQUICWGHostOrigin(id domain.LinkID, nonce string, localWGUDPPort uint16) (QUICWGHostOrigin, error) {
	guard, err := NewQUICWGIngressPlan(id, localWGUDPPort, nonce)
	if err != nil {
		return QUICWGHostOrigin{}, err
	}
	tag, err := QUICWGOwnerTag(id, nonce)
	if err != nil {
		return QUICWGHostOrigin{}, err
	}
	name, err := QUICWGStagingName(id, nonce)
	if err != nil {
		return QUICWGHostOrigin{}, err
	}
	return QUICWGHostOrigin{OwnerTag: tag, StagingName: name, Guard: guard}, nil
}
