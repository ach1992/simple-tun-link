package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type quicRetirementHost interface {
	VerifyRetirementHostAbsent(context.Context, domain.Link, state.QUICGeneration) error
}

type quicCredentialRetirement struct {
	root string
	host quicRetirementHost
	keys *wgbackend.KeyStore
}

// Engine alone calls this adapter under canonical locks, after exact durable
// Remove and original-termination proof. Matching names are never deletion
// authority. A partially retired generation keeps its receipt for retry.
func (r quicCredentialRetirement) RetireAfterRemove(ctx context.Context, link domain.Link, generation state.QUICGeneration) error {
	if r.host == nil || r.keys == nil || generation.Validate(link) != nil {
		return fmt.Errorf("QUIC retirement authority unavailable")
	}
	if err := r.host.VerifyRetirementHostAbsent(ctx, link, generation); err != nil {
		return fmt.Errorf("QUIC resources remain live or unverified")
	}
	plan, err := quicPlanForLink(link)
	if err != nil {
		return err
	}
	expected := quic.HelperConfigIdentity{ConfigSHA256: generation.Files.HelperConfig,
		Credentials: quic.CredentialIdentity{CertificateSHA256: generation.Files.Certificate,
			TrustCASHA256: generation.Files.TrustCA, AuthorizationSHA256: generation.Files.Authorization},
		Executable: pinnedexec.Identity{SHA256: generation.ExecutableSHA256, Device: generation.ExecutableDevice, Inode: generation.ExecutableInode}}
	identity := quic.MaterialIdentity{CertificateSHA256: generation.Files.Certificate, TLSKeySHA256: generation.Files.TLSKey,
		TrustCASHA256: generation.Files.TrustCA, AuthorizationSHA256: generation.Files.Authorization,
		HelperConfigSHA256: generation.Files.HelperConfig, DirectoryDevice: generation.Files.DirectoryDevice,
		DirectoryInode: generation.Files.DirectoryInode, ReceiptDevice: generation.Files.ReceiptDevice, ReceiptInode: generation.Files.ReceiptInode}
	if err := quic.RetireOwnedGeneration(ctx, r.root, plan, generation.MaterialNonce, expected, identity); err != nil {
		return err
	}
	_, err = r.keys.RetireExact(link.ID, link.WireGuard.LocalPublicKey)
	return err
}

// Reappearing material is untrusted. Historical retirement permits a read-only
// absence check and never grants authority to delete a replacement identity.
func (r quicCredentialRetirement) VerifyAbsent(ctx context.Context, link domain.Link, generation state.QUICGeneration) error {
	if r.host == nil || r.keys == nil || generation.Validate(link) != nil {
		return fmt.Errorf("QUIC retirement authority unavailable")
	}
	if err := r.host.VerifyRetirementHostAbsent(ctx, link, generation); err != nil {
		return fmt.Errorf("retired QUIC host resources reappeared or are unverified")
	}
	absent, err := quic.GenerationAbsent(r.root, link.ID)
	if err != nil || !absent {
		return fmt.Errorf("retired QUIC protected material reappeared or is unverified")
	}
	_, err = r.keys.LocalPublicIdentity(link.ID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("retired QUIC WireGuard identity reappeared or is unverified")
}

func linkQUICRetireCommand(args []string, out, errOut io.Writer, options *runtimeOptions) int {
	isJSON := len(args) == 4 && args[3] == "--json"
	if !((len(args) == 3 || isJSON) && args[1] == "--confirm" && args[0] == args[2]) {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "quic_retire", "usage: stl link retire-quic <link-id> --confirm <link-id> [--json]")
	}
	id := domain.LinkID(args[0])
	if id.Validate() != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "quic_retire", "invalid QUIC Link ID")
	}
	var err error
	if options == nil {
		options, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, isJSON, stlerr.CodeState, "quic_retire", "runtime unavailable")
		}
	}
	engine, err := buildRuntimeEngine(*options)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState, "quic_retire", "Engine unavailable")
	}
	ctx, cancel := quicCtx()
	defer cancel()
	if err := engine.RetireQUICCredential(ctx, id); err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeOf(err), "quic_retire", "QUIC credential retirement unconfirmed; preserve the removal receipt and protected files until exact host absence is verified")
	}
	if isJSON {
		if json.NewEncoder(out).Encode(struct {
			SchemaVersion int           `json:"schema_version"`
			LinkID        domain.LinkID `json:"link_id"`
			Retired       bool          `json:"retired"`
		}{1, id, true}) != nil {
			return 1
		}
	} else {
		fmt.Fprintf(out, "QUIC TLS, authorization and WireGuard credentials for Link %s confirmed retired after durable original-termination and host/State absence checks.\n", id)
	}
	return 0
}
