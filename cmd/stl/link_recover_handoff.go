package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"golang.org/x/sys/unix"
)

type handoffRecoveryResult struct {
	SchemaVersion int            `json:"schema_version"`
	Operation     string         `json:"operation"`
	LinkID        domain.LinkID  `json:"link_id"`
	Backend       domain.Backend `json:"backend"`
	HandoffFile   string         `json:"handoff_file"`
	Recovered     bool           `json:"recovered"`
}

// A hard crash during the atomic no-clobber handoff writer may leave a
// fully synced 0600 staging file instead of the requested final name.
// Only explicitly named, regular, owner-private, singly-linked STL temporary
// files can be recovered. The original URL never enters argv or normal JSON.
func withVerifiedHandoffTemporary(source, output string, operation func(raw string, publish func() error) error) error {
	if operation == nil || !filepath.IsAbs(source) || filepath.Clean(source) != source ||
		!filepath.IsAbs(output) || filepath.Clean(output) != output ||
		filepath.Dir(source) != filepath.Dir(output) || source == output {
		return fmt.Errorf("invalid recovery paths; both must be in the same private directory")
	}
	temporary := filepath.Base(source)
	if !strings.HasPrefix(temporary, ".stl-handoff-") || !strings.HasSuffix(temporary, ".tmp") {
		return fmt.Errorf("source is not a recognized STL crash temporary")
	}
	nonce := strings.TrimSuffix(strings.TrimPrefix(temporary, ".stl-handoff-"), ".tmp")
	if len(nonce) != 32 {
		return fmt.Errorf("invalid STL temporary identity")
	}
	decoded, err := hex.DecodeString(nonce)
	if err != nil || hex.EncodeToString(decoded) != nonce {
		return fmt.Errorf("invalid STL temporary identity")
	}
	target := filepath.Base(output)
	if target == "." || target == ".." || target == "" || strings.HasPrefix(target, ".stl-handoff-") {
		return fmt.Errorf("invalid private handoff destination")
	}
	dir, err := openPrivateHandoffParent(filepath.Dir(source))
	if err != nil {
		return fmt.Errorf("cannot inspect protected handoff parent")
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, temporary, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot open exact protected STL temporary")
	}
	file := os.NewFile(uintptr(fd), "stl-protected-crash-temporary")
	defer file.Close()
	var initial unix.Stat_t
	if err := unix.Fstat(fd, &initial); err != nil || !validHandoffTempFile(initial) {
		return fmt.Errorf("STL temporary is not an owner-private regular unlinked-safe file")
	}
	// readSetupLink enforces the canonical 24KiB protocol bound and accepts
	// only the writer's optional final newline. It never prints the URL.
	raw, err := readSetupLink(file)
	if err != nil {
		return fmt.Errorf("protected temporary is incomplete or malformed")
	}
	return operation(raw, func() error {
		// The Engine retains its maintenance and exact Link lock for this
		// final no-clobber move. Reject a replaced/modified path before rename.
		var current unix.Stat_t
		if err := unix.Fstatat(dir, temporary, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			!validHandoffTempFile(current) || current.Ino != initial.Ino ||
			current.Dev != initial.Dev || current.Size != initial.Size {
			return fmt.Errorf("protected temporary changed during recovery")
		}
		// The original writer may have died before fsync(file). Complete its
		// data durability before exposing a recovered URL under the final name.
		// Detect in-place writes between the initial identity read and the
		// canonical Engine-locked publication, including same-size rewrites.
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("cannot revalidate protected temporary")
		}
		fresh, err := readSetupLink(file)
		if err != nil || fresh != raw {
			return fmt.Errorf("protected temporary content changed during recovery")
		}
		if err := unix.Fsync(fd); err != nil {
			return fmt.Errorf("cannot make original protected temporary durable")
		}
		if err := unix.Renameat2(dir, temporary, dir, target, unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("no-clobber temporary publication refused or failed")
		}
		if err := unix.Fsync(dir); err != nil {
			return fmt.Errorf("handoff renamed but directory durability is uncertain")
		}
		return nil
	})
}

func validHandoffTempFile(s unix.Stat_t) bool {
	return s.Uid == uint32(os.Geteuid()) && s.Mode&unix.S_IFMT == unix.S_IFREG &&
		s.Mode&0o777 == 0o600 && s.Nlink == 1 &&
		s.Size > 0 && s.Size <= pairing.MaxLinkBytes+2
}

func linkRecoverHandoffCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	const op = "link_recover_handoff"
	isJSON := slices.Contains(args, "--json")
	if !((len(args) == 7 || (len(args) == 8 && args[7] == "--json")) &&
		args[0] == "recover-handoff" && args[1] == "--source" &&
		args[3] == "--output" && args[5] == "--confirm") {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, op,
			"usage: stl link recover-handoff --source <STL-private-temp> --output <private-file> --confirm <link-id> [--json]")
	}
	id := domain.LinkID(args[6])
	if err := id.Validate(); err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, op,
			"invalid exact Link ID confirmation")
	}
	root := state.DefaultRoot
	if opts != nil {
		root = opts.stateRoot
	}
	// No backend probing/activation is necessary: this is a private-file
	// recovery action only. The canonical Engine still owns locks and state.
	engine, err := buildRuntimeEngine(runtimeOptions{stateRoot: root})
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState, op,
			"cannot load protected sender recovery runtime")
	}
	var kind domain.Backend
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = withVerifiedHandoffTemporary(args[2], args[4], func(raw string, publish func() error) error {
		offer, decodeErr := pairing.DecodeSetupLink(raw)
		if decodeErr != nil {
			return stlerr.New(stlerr.CodeInvalid, op, string(id), "", "malformed SENSITIVE crash temporary")
		}
		defer offer.ClearRecipientCredential()
		link := offer.Link()
		if link.ID != id || offer.Preview().Mode != pairing.ModeQuick || !offer.IsSensitive() {
			return stlerr.New(stlerr.CodeConflict, op, string(id), "", "temporary is not the confirmed sender's Quick Link")
		}
		kind = link.Backend
		digest := setupLinkConfirmation(raw)
		switch link.Backend {
		case domain.BackendWireGuard:
			if offer.Preview().SchemaVersion != pairing.WireGuardSchemaVersion ||
				offer.CredentialKind() != pairing.CredentialWireGuardPrivateKey {
				return stlerr.New(stlerr.CodeUnsupported, op, string(id), "", "unsupported WireGuard recovery schema")
			}
			keys, keyErr := wgbackend.NewKeyStore(root)
			if keyErr != nil {
				return stlerr.New(stlerr.CodeState, op, string(id), "", "protected WireGuard store unavailable")
			}
			return engine.RecoverWireGuardSenderHandoff(ctx, link, digest, keys, publish)
		case domain.BackendIPsec:
			if !importableIPsecOffer(offer) {
				return stlerr.New(stlerr.CodeUnsupported, op, string(id), "", "unsupported IPsec recovery schema or PSK")
			}
			keys, keyErr := ipsecbackend.NewPSKStore(root)
			if keyErr != nil {
				return stlerr.New(stlerr.CodeState, op, string(id), "", "protected IPsec store unavailable")
			}
			secret := offer.RecipientCredential()
			defer clear(secret)
			return engine.RecoverIPsecSenderHandoff(ctx, link, digest, secret, keys, publish)
		default:
			return stlerr.New(stlerr.CodeUnsupported, op, string(id), "", "unsupported backend for protected handoff recovery")
		}
	})
	if err != nil {
		// No raw filesystem, JSON, setup URL, or key-store errors in public
		// output. Only stable, redacted action and reason categories.
		code := stlerr.CodeOf(err)
		if code == stlerr.CodeInternal {
			code = stlerr.CodeState
		}
		var result *app.Result
		if id.Validate() == nil {
			result = &app.Result{LinkID: id}
		}
		return lifecycleFailure(out, errOut, isJSON, code, op, result,
			"handoff recovery unconfirmed: retain the original temporary and protected key; inspect exact pending sender state and both destination paths, then retry only from the original identity")
	}
	if isJSON {
		if err := json.NewEncoder(out).Encode(handoffRecoveryResult{SchemaVersion: jsonSchemaVersion,
			Operation: op, LinkID: id, Backend: kind, HandoffFile: args[4], Recovered: true}); err != nil {
			fmt.Fprintln(errOut, "SENSITIVE handoff may be recovered, but output is uncertain; inspect the private destination")
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "Recovered exact original SENSITIVE %s sender handoff for Link %s into the private destination.\n", kind, id)
	fmt.Fprintln(out, "Verify original peer delivery, then use the existing confirmed WireGuard Resume or staged IPsec Activate flow. No peer handshake, traffic, or host networking was changed.")
	return 0
}
