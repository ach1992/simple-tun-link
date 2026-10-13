package app

import (
	"context"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// RecoverWireGuardSenderHandoff moves only the exact durable sender's original
// SENSITIVE handoff. It never creates a key, reserves a Link, or touches the
// network. The caller supplies a no-clobber file publication callback.
func (e *Engine) RecoverWireGuardSenderHandoff(ctx context.Context, link domain.Link, digest string,
	keys SenderKeyStore, publish func() error) error {
	if keys == nil || link.Backend != domain.BackendWireGuard || link.Encapsulation != domain.EncapUDP {
		return stlerr.New(stlerr.CodeInvalid, "recover_handoff", string(link.ID), "", "invalid WireGuard sender identity")
	}
	return e.recoverPendingSenderHandoff(ctx, link, digest, func() error {
		public, err := keys.LocalPublicIdentity(link.ID)
		if err != nil || public != link.WireGuard.LocalPublicKey {
			return stlerr.New(stlerr.CodeConflict, "recover_handoff", string(link.ID), "",
				"protected WireGuard sender credential is missing, unsafe or not identity-bound")
		}
		return nil
	}, publish)
}

// RecoverIPsecSenderHandoff requires the exact protected PSK and preexisting
// public sender intent. A recipient-origin pending transaction has NO authority
// to recover or publish a sender's SENSITIVE URL.
func (e *Engine) RecoverIPsecSenderHandoff(ctx context.Context, link domain.Link, digest string,
	secret []byte, keys IPsecCredentialStore, publish func() error) error {
	if keys == nil || link.Backend != domain.BackendIPsec ||
		(link.Encapsulation != domain.EncapESP && link.Encapsulation != domain.EncapNATT) {
		return stlerr.New(stlerr.CodeInvalid, "recover_handoff", string(link.ID), "", "invalid IPsec sender identity")
	}
	key, err := ipsec.ParsePSK(secret)
	if err != nil {
		return stlerr.New(stlerr.CodeInvalid, "recover_handoff", string(link.ID), "", "invalid protected IPsec sender credential")
	}
	key.Zeroize()
	return e.recoverPendingSenderHandoff(ctx, link, digest, func() error {
		if err := keys.RequireExistingExact(link.ID, secret); err != nil {
			return stlerr.New(stlerr.CodeConflict, "recover_handoff", string(link.ID), "",
				"protected IPsec sender PSK is missing, unsafe or different")
		}
		return nil
	}, publish)
}

func (e *Engine) recoverPendingSenderHandoff(ctx context.Context, link domain.Link, digest string,
	verifyCredential, publish func() error) error {
	const op = "recover_handoff"
	if e == nil || ctx == nil || verifyCredential == nil || publish == nil ||
		link.Validate() != nil || !validSenderDigest(digest) {
		return stlerr.New(stlerr.CodeInvalid, op, string(link.ID), "", "invalid exact sender handoff recovery")
	}
	release, err := e.acquireMaintenance(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, op, string(link.ID), "", "sender recovery maintenance lock unavailable")
	}
	defer release()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(link.ID)})
	if err != nil {
		return stlerr.New(stlerr.CodeState, op, string(link.ID), "", "sender recovery Link lock unavailable")
	}
	defer linkRelease()
	snap, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, op, string(link.ID), "", "cannot verify original sender recovery state")
	}
	if _, committed := snap.Find(link.ID); committed {
		return stlerr.New(stlerr.CodeConflict, op, string(link.ID), "", "sender Link already committed; no pending recovery authority")
	}
	if _, removed := snap.FindRemovalReceipt(link.ID); removed {
		return stlerr.New(stlerr.CodeConflict, op, string(link.ID), "", "sender identity was already removed")
	}
	switch link.Backend {
	case domain.BackendWireGuard:
		pending, ok := snap.FindPendingSender(link.ID)
		if !ok || pending.Link != link || pending.HandoffSHA256 != digest {
			return stlerr.New(stlerr.CodeConflict, op, string(link.ID), "", "no exact WireGuard sender pending recovery intent")
		}
	case domain.BackendIPsec:
		pending, ok := snap.FindPendingIPsec(link.ID)
		if !ok || pending.Origin != "sender" || pending.Link != link || pending.HandoffSHA256 != digest {
			return stlerr.New(stlerr.CodeConflict, op, string(link.ID), "", "no exact IPsec sender pending recovery intent")
		}
	default:
		return stlerr.New(stlerr.CodeUnsupported, op, string(link.ID), "", "unsupported sender backend")
	}
	if err := verifyCredential(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return stlerr.New(stlerr.CodeState, op, string(link.ID), "", "sender recovery interrupted before publication")
	}
	// No user-controlled error strings reach CLI/JSON: filenames, private URL
	// bytes, or low-level filesystem causes must remain outside these surfaces.
	if err := publish(); err != nil {
		return stlerr.New(stlerr.CodeState, op, string(link.ID), "",
			"private handoff recovery failed or has uncertain durability; inspect both paths without rekeying")
	}
	return nil
}
