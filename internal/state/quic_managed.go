package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
)

// QUICFileIdentity is the immutable protected material of a committed Link.
// Certificate and Authorization use the existing QUIC verifier's semantic
// digests; TLSKey hashes the private file. The protected generation receipt
// independently binds the original directory and all exact file inodes.
type QUICFileIdentity struct {
	Certificate     string `json:"certificate_sha256"`
	TLSKey          string `json:"tls_key_sha256"`
	TrustCA         string `json:"trust_ca_sha256"`
	Authorization   string `json:"authorization_sha256"`
	HelperConfig    string `json:"helper_config_sha256"`
	DirectoryDevice uint64 `json:"directory_device"`
	DirectoryInode  uint64 `json:"directory_inode"`
	ReceiptDevice   uint64 `json:"receipt_device"`
	ReceiptInode    uint64 `json:"receipt_inode"`
}

func (f QUICFileIdentity) Validate() error {
	for _, digest := range []string{f.Certificate, f.TLSKey, f.TrustCA, f.Authorization, f.HelperConfig} {
		if !validIPsecPendingDigest(digest) {
			return fmt.Errorf("invalid managed QUIC material identity")
		}
	}
	if f.DirectoryDevice == 0 || f.DirectoryInode == 0 || f.ReceiptDevice == 0 || f.ReceiptInode == 0 {
		return fmt.Errorf("managed QUIC original material receipt identity missing")
	}
	return nil
}

// QUICGeneration is issued only by a fresh, fully verified managed Engine
// transaction. It is never reconstructed from a source-only birth receipt.
// It combines protected creation provenance with exact current host checks
// under the documented trusted-root boundary; it does not prove an unseen
// history against an administrator capable of forging host objects.
type QUICGeneration struct {
	Version          int              `json:"version"`
	OriginNonce      string           `json:"origin_nonce"`
	MaterialNonce    string           `json:"material_nonce"`
	KernelBootID     string           `json:"kernel_boot_id"`
	KernelBootSource string           `json:"kernel_boot_source"`
	NetworkNS        string           `json:"network_namespace"`
	WGIfIndex        int              `json:"wg_ifindex"`
	GuardTableHandle uint64           `json:"guard_table_handle"`
	GuardChainHandle uint64           `json:"guard_chain_handle"`
	GuardRuleHandle  uint64           `json:"guard_rule_handle"`
	Files            QUICFileIdentity `json:"files"`
	ExecutablePath   string           `json:"executable_path"`
	ExecutableSHA256 string           `json:"executable_sha256"`
	ExecutableDevice uint64           `json:"executable_device"`
	ExecutableInode  uint64           `json:"executable_inode"`
}

func validQUICNonce(s string) bool {
	v, err := hex.DecodeString(s)
	return err == nil && len(v) == 16 && hex.EncodeToString(v) == s
}

func (g QUICGeneration) Validate(link domain.Link) error {
	if link.Backend != domain.BackendWireGuardQUIC || link.Validate() != nil || g.Version != 1 ||
		!validQUICNonce(g.OriginNonce) || !validQUICNonce(g.MaterialNonce) ||
		!hostidentity.ValidBootID(g.KernelBootID) || g.KernelBootSource != hostidentity.VerifiedHostBootSourceV1 ||
		g.WGIfIndex <= 0 || g.GuardTableHandle == 0 || g.GuardChainHandle == 0 || g.GuardRuleHandle == 0 {
		return fmt.Errorf("invalid committed QUIC original generation")
	}
	ns := strings.TrimSuffix(strings.TrimPrefix(g.NetworkNS, "net:["), "]")
	if n, err := strconv.ParseUint(ns, 10, 64); err != nil || n == 0 || strconv.FormatUint(n, 10) != ns || g.NetworkNS != "net:["+ns+"]" {
		return fmt.Errorf("invalid committed QUIC network namespace")
	}
	if g.ExecutablePath != "/usr/local/libexec/stl/hysteria" || filepath.Clean(g.ExecutablePath) != g.ExecutablePath ||
		!validIPsecPendingDigest(g.ExecutableSHA256) || g.ExecutableDevice == 0 || g.ExecutableInode == 0 {
		return fmt.Errorf("invalid committed QUIC executable identity")
	}
	return g.Files.Validate()
}

// Managed is absent on every historical source-only QUIC operation. Only
// fresh Version 1 operations participate in canonical committed lifecycle.
// This intent is immutable until its exact atomic commit/removal transition.
type QUICManagedOperation struct {
	Version int `json:"version"`
	// The attempt's trusted kernel generation is recorded BEFORE any effect.
	// OriginalGeneration may be older during restore and cannot replace this.
	KernelBootID       string         `json:"kernel_boot_id"`
	KernelBootSource   string         `json:"kernel_boot_source"`
	Intent             domain.Link    `json:"intent"`
	Operation          string         `json:"operation"`
	HadCommittedLink   bool           `json:"had_committed_link"`
	OriginalGeneration QUICGeneration `json:"original_generation,omitzero"`
}

func (op QUICCrashOperation) ValidateManaged() error {
	m := op.Managed
	if op.ExecutablePath != "/usr/local/libexec/stl/hysteria" {
		return fmt.Errorf("managed QUIC requires the canonical approved executable path")
	}
	if m == nil || m.Version != 1 || !hostidentity.ValidBootID(m.KernelBootID) || m.KernelBootSource != hostidentity.VerifiedHostBootSourceV1 || m.Intent.Backend != domain.BackendWireGuardQUIC || m.Intent.Validate() != nil ||
		(m.Operation != "ensure" && m.Operation != "remove") {
		return fmt.Errorf("invalid managed QUIC operation")
	}
	host, err := composition.QUICHostPlanForLink(m.Intent)
	if err != nil || host != op.Plan || m.Intent.Addresses != op.Addresses || m.Intent.WireGuard != op.WireGuard {
		return fmt.Errorf("managed QUIC public identity differs from journal")
	}
	if m.HadCommittedLink {
		if err := m.OriginalGeneration.Validate(m.Intent); err != nil {
			return err
		}
		if !op.MatchesGenerationMaterial(m.OriginalGeneration) {
			return fmt.Errorf("managed QUIC original material changed")
		}
	} else if m.OriginalGeneration != (QUICGeneration{}) || m.Operation != "ensure" {
		return fmt.Errorf("managed QUIC operation lacks original committed owner")
	}
	return nil
}

func (op QUICCrashOperation) MatchesGenerationMaterial(g QUICGeneration) bool {
	return op.CertificateSHA256 == g.Files.Certificate && op.TrustCASHA256 == g.Files.TrustCA &&
		op.AuthorizationSHA256 == g.Files.Authorization && op.HelperConfigSHA256 == g.Files.HelperConfig &&
		op.ExecutablePath == g.ExecutablePath && op.ExecutableSHA256 == g.ExecutableSHA256 &&
		op.ExecutableDevice == g.ExecutableDevice && op.ExecutableInode == g.ExecutableInode
}

func (s *Snapshot) DeleteQUICManagedOperation(id domain.LinkID) bool {
	for i, op := range s.QUICCrashOperations {
		if op.Plan.Local.LinkID == id && op.Managed != nil {
			s.QUICCrashOperations = append(s.QUICCrashOperations[:i], s.QUICCrashOperations[i+1:]...)
			return true
		}
	}
	return false
}

func validQUICManagedCompletion(op QUICCrashOperation, s Snapshot) bool {
	if op.ValidateManaged() != nil {
		return false
	}
	m := op.Managed
	if m.Operation == "ensure" {
		if !m.HadCommittedLink {
			if receipt, ok := s.FindQUICAbandonmentReceipt(m.Intent.ID); ok {
				return receipt.Validate() == nil && reflect.DeepEqual(receipt.Operation, op)
			}
		}
		r, ok := s.Find(m.Intent.ID)
		if !ok || r.Desired != m.Intent || !slices.Equal(r.OwnedResources, op.Resources) ||
			r.QUICGeneration.Validate(r.Desired) != nil || !op.MatchesGenerationMaterial(r.QUICGeneration) {
			return false
		}
		origin, material := op.Nonce, op.Nonce
		if m.HadCommittedLink {
			origin, material = m.OriginalGeneration.OriginNonce, m.OriginalGeneration.MaterialNonce
		}
		return r.QUICGeneration.OriginNonce == origin && r.QUICGeneration.MaterialNonce == material
	}
	if _, present := s.Find(m.Intent.ID); present {
		return false
	}
	r, ok := s.FindRemovalReceipt(m.Intent.ID)
	return ok && r.Backend == domain.BackendWireGuardQUIC && r.QUICLink == m.Intent &&
		r.QUICGeneration == m.OriginalGeneration && ValidQUICOriginalTerminationProof(r.QUICOriginalTermination)
}

const (
	QUICOriginalExactIfIndexDeleted     = "original-ifindex-deleted-v1"
	QUICOriginalKernelGenerationExtinct = "trusted-kernel-generation-extinct-v1"
)

func ValidQUICOriginalTerminationProof(proof string) bool {
	return proof == QUICOriginalExactIfIndexDeleted || proof == QUICOriginalKernelGenerationExtinct
}

func rejectLegacyQUICManagedFields(raw []byte) error {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	var contains func(any) bool
	contains = func(v any) bool {
		switch item := v.(type) {
		case map[string]any:
			for key, child := range item {
				switch strings.ToLower(key) {
				case "quic", "quic_generation", "quic_link", "quic_original_termination", "quic_abandonment_receipts", "managed":
					return true
				}
				if contains(child) {
					return true
				}
			}
		case []any:
			for _, child := range item {
				if contains(child) {
					return true
				}
			}
		}
		return false
	}
	if contains(document) {
		return fmt.Errorf("legacy State cannot grant managed QUIC authority")
	}
	return nil
}
