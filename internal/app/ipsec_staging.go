package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// IPsecCredentialStore is the narrowly scoped protected PSK publication seam.
// It must use no-replace, private per-Link files. The canonical Engine owns
// synchronization and the public intent; raw keys never enter state.json.
type IPsecCredentialStore interface {
	PutNew(domain.LinkID, []byte) error
	RequireExistingExact(domain.LinkID, []byte) error
}

// StageIPsecSender persists a 256-bit PSK and complete public sender Link
// intent under canonical maintenance/Link/resource locks BEFORE exposing a
// deliberately SENSITIVE Quick Link through publish. No VICI/XFRM or backend
// mutation occurs. On uncertain publication or an error, preserve the key
// and intent for exact-replay recovery; never silently create a replacement.
func (e *Engine) StageIPsecSender(ctx context.Context, offer pairing.Offer, keys IPsecCredentialStore, publish func(string) error) error {
	if publish == nil {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_stage_sender", "", "ipsec", "SENSITIVE handoff destination is required")
	}
	desired, secret, encoded, err := checkedIPsecQuickOffer(offer, false)
	if err != nil {
		return err
	}
	defer clear(secret)
	digest := sha256.Sum256([]byte(encoded))
	return e.stageIPsec(ctx, desired, secret, "sender", hex.EncodeToString(digest[:]), keys,
		func() error { return publish(encoded) })
}

// StageIPsecRecipient protects an explicitly reviewed Quick Link's shared
// PSK and exact inverted recipient public Link as a local pending intent.
// The raw URL and its SHA256 confirmation are checked before any persistence.
// Existing v2 Quick Links remain previewable, but only a strict 32-byte PSK
// is eligible for staging; noncanonical legacy lengths are never rekeyed.
func (e *Engine) StageIPsecRecipient(ctx context.Context, rawURL string, confirmedSHA256 string, keys IPsecCredentialStore) error {
	// Bound untrusted input before even hashing it, then bind the exact raw
	// bytes shown in preview (not a re-encoded Offer).
	if len(rawURL) == 0 || len(rawURL) > pairing.MaxLinkBytes {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_stage_recipient", "", "ipsec", "SENSITIVE Quick Link exceeds supported size")
	}
	if !validSenderDigest(confirmedSHA256) {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_stage_recipient", "", "ipsec", "invalid reviewed Quick Link confirmation")
	}
	sum := sha256.Sum256([]byte(rawURL))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(confirmedSHA256)) != 1 {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_stage_recipient", "", "ipsec", "SENSITIVE Quick Link does not match the reviewed preview")
	}
	offer, err := pairing.DecodeSetupLink(rawURL)
	if err != nil {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_stage_recipient", "", "ipsec", "invalid or unsupported IPsec Quick Link")
	}
	defer offer.ClearRecipientCredential()
	desired, secret, _, err := checkedIPsecQuickOffer(offer, true)
	if err != nil {
		return err
	}
	defer clear(secret)
	return e.stageIPsec(ctx, desired, secret, "recipient", "", keys, nil)
}

func checkedIPsecQuickOffer(offer pairing.Offer, recipient bool) (domain.Link, []byte, string, error) {
	preview := offer.Preview()
	if preview.SchemaVersion != pairing.SchemaVersion || preview.Mode != pairing.ModeQuick ||
		preview.Link.Backend != domain.BackendIPsec || !preview.Sensitive ||
		preview.Credential != pairing.CredentialIPsecPSK {
		return domain.Link{}, nil, "", stlerr.New(stlerr.CodeUnsupported, "ipsec_stage", "", "ipsec", "only a strict IPsec Quick Link can be staged")
	}
	var encoded string
	if !recipient {
		var err error
		encoded, err = offer.EncodeSetupLink()
		if err != nil {
			return domain.Link{}, nil, "", stlerr.New(stlerr.CodeInvalid, "ipsec_stage", "", "ipsec", "invalid SENSITIVE IPsec pairing intent")
		}
	}
	secret := offer.RecipientCredential()
	key, err := ipsec.ParsePSK(secret)
	key.Zeroize()
	if err != nil {
		clear(secret)
		return domain.Link{}, nil, "", stlerr.New(stlerr.CodeUnsupported, "ipsec_stage", "", "ipsec", "legacy IPsec PSK size is preview-only; require a new 256-bit key via an explicit operator-approved flow")
	}
	// Preview is recipient-oriented even when rendered by the sender.
	// Never derive the sender's durable local identity from Preview.Link.
	desired := offer.Link()
	if recipient {
		desired = offer.ReceiverLink()
	}
	if _, err := ipsec.NewProfile(desired); err != nil {
		clear(secret)
		return domain.Link{}, nil, "", stlerr.New(stlerr.CodeInvalid, "ipsec_stage", "", "ipsec", "invalid IPsec endpoint identity")
	}
	return desired, secret, encoded, nil
}

func (e *Engine) stageIPsec(ctx context.Context, desired domain.Link, secret []byte, origin, digest string, keys IPsecCredentialStore, publish func() error) error {
	if e == nil || ctx == nil || keys == nil {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_stage", "", "ipsec", "Engine and protected key store are required")
	}
	profile, err := ipsec.NewProfile(desired)
	if err != nil {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_stage", "", "ipsec", "noncanonical IPsec identity")
	}
	claims, err := validatedClaims(profile.ResourceClaims())
	if err != nil {
		return stlerr.Wrap(stlerr.CodeInvalid, "ipsec_stage", string(desired.ID), "ipsec", "invalid protected resource reservation", err)
	}
	releaseMaintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "maintenance gate unavailable")
	}
	defer releaseMaintenance()
	releaseLink, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(desired.ID)})
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "Link ownership lock unavailable")
	}
	defer releaseLink()
	resourceLocks, err := resourceLockClaims(claims)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "invalid resource locks")
	}
	releaseResources, err := e.locks.Acquire(ctx, resourceLocks)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "resource ownership locks unavailable")
	}
	defer releaseResources()

	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "cannot verify canonical state")
	}
	if _, exists := snapshot.Find(desired.ID); exists {
		return stlerr.New(stlerr.CodeConflict, "ipsec_stage", string(desired.ID), "ipsec", "Link identity already committed")
	}
	if _, exists := snapshot.FindPendingSender(desired.ID); exists {
		return stlerr.New(stlerr.CodeConflict, "ipsec_stage", string(desired.ID), "ipsec", "WireGuard sender reserves Link identity")
	}
	if _, exists := snapshot.FindRemovalReceipt(desired.ID); exists {
		return stlerr.New(stlerr.CodeConflict, "ipsec_stage", string(desired.ID), "ipsec", "credential retirement receipt reserves Link identity")
	}
	if err := rejectResourceConflicts(snapshot, desired.ID, claims); err != nil {
		return err
	}

	expected := state.PendingIPsec{Link: desired, Origin: origin, HandoffSHA256: digest}
	pending, exists := snapshot.FindPendingIPsec(desired.ID)
	if exists {
		if pending != expected {
			return stlerr.New(stlerr.CodeConflict, "ipsec_stage", string(desired.ID), "ipsec", "staged IPsec Link or handoff identity differs; explicit reconciliation is required")
		}
		// A durable pending intent requires the SAME EXISTING protected key.
		// Replay must never recreate missing material or adopt a new PSK.
		if err := keys.RequireExistingExact(desired.ID, secret); err != nil {
			return stlerr.New(stlerr.CodeConflict, "ipsec_stage", string(desired.ID), "ipsec", "staged protected PSK missing, unsafe or different")
		}
	} else {
		// No public intent: even an equal orphan key is NOT adoption authority.
		// PutNew must fail on any existing credential and preserve it.
		if err := keys.PutNew(desired.ID, secret); err != nil {
			return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "protected PSK already exists or could not be published; reconcile orphan before retry")
		}
		if err := ctx.Err(); err != nil {
			return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "protected PSK staged but interrupted before public intent")
		}
		err := e.store.Update(ctx, func(s *state.Snapshot) error {
			if _, committed := s.Find(desired.ID); committed {
				return fmt.Errorf("Link committed during credential staging")
			}
			if _, pending := s.FindPendingSender(desired.ID); pending {
				return fmt.Errorf("WireGuard sender acquired Link identity")
			}
			if _, pending := s.FindPendingIPsec(desired.ID); pending {
				return fmt.Errorf("IPsec identity already staged")
			}
			if _, receipt := s.FindRemovalReceipt(desired.ID); receipt {
				return fmt.Errorf("removal receipt overlaps IPsec intent")
			}
			if err := rejectResourceConflicts(*s, desired.ID, claims); err != nil {
				return err
			}
			s.PendingIPsec = append(s.PendingIPsec, expected)
			return nil
		})
		if err != nil {
			// Publication can have occurred before fsync failure; never remove
			// the protected key or disclose a URL after uncertainty.
			return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "PSK persisted but public intent durability uncertain; reconcile exact staged state")
		}
	}
	if err := ctx.Err(); err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "IPsec credential intent staged but operation interrupted")
	}
	if publish != nil {
		// Callback errors may contain URL/PSK; never wrap or format them.
		if err := publish(); err != nil {
			return stlerr.New(stlerr.CodeState, "ipsec_stage", string(desired.ID), "ipsec", "SENSITIVE handoff publication failed or is uncertain; inspect destination and retry exact offer")
		}
	}
	return nil
}
