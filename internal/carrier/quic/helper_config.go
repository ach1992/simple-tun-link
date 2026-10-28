package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"golang.org/x/sys/unix"
)

// HelperConfigIdentity is public-only readback evidence for an exact local
// helper config, its checked credentials and the approved executable inode.
// It is NOT an Engine commit, process-lifetime pin or authority to spawn.
type HelperConfigIdentity struct {
	ConfigSHA256 string
	Credentials  CredentialIdentity
	Executable   pinnedexec.Identity
}

type helperVerifier func(string) (pinnedexec.Identity, error)

// StageHelperConfig writes the deterministic secret-bearing Hysteria config
// ONLY after verifying the exact role's existing protected credentials and
// the separately installed, officially pinned helper executable.
//
// The canonical Engine caller MUST already hold its maintenance, Link and
// resource locks and must journal the full planned host effects before this
// write. This component does not acquire locks or journal, install, spawn,
// activate, delete or reconcile anything. On failure any uncertain file is
// intentionally preserved rather than replaced or cleaned up.
func StageHelperConfig(root string, plan Plan, localWGUDPPort uint16, binary string) (HelperConfigIdentity, error) {
	return stageHelperConfig(root, plan, localWGUDPPort, binary, InspectPinnedHysteria)
}

// InspectHelperConfig regenerates the exact expected config from the
// protected role-specific credentials, then compares the checked on-disk
// helper.json bytes. It rejects secret/config drift, unsafe inode metadata
// and helper substitution without returning sensitive data.
func InspectHelperConfig(root string, plan Plan, localWGUDPPort uint16, binary string) (HelperConfigIdentity, error) {
	return inspectHelperConfig(root, plan, localWGUDPPort, binary, InspectPinnedHysteria)
}

func helperConfigPreflight(root string, plan Plan, localWGUDPPort uint16, binary string) error {
	if _, err := plan.CarrierClaims(localWGUDPPort); err != nil {
		return err
	}
	if !safePath(root) || root == "/" || !safePath(binary) || binary == "/" {
		return fmt.Errorf("QUIC helper config requires canonical absolute protected and binary paths")
	}
	return nil
}

// renderHelperConfigFromFiles shares one TLS/CA/bearer validation and
// renderer between read-only prepublication preview and protected readback.
// The caller owns and clears all sensitive file bytes.
func renderHelperConfigFromFiles(root string, plan Plan, binary string,
	files map[string][]byte) ([]byte, CredentialIdentity, error) {
	identity, err := validateRoleMaterial(plan, files)
	if err != nil {
		return nil, CredentialIdentity{}, err
	}
	names, _ := roleFiles(plan.Role)
	// Build accepts a string token. No credential or rendered config is
	// included in logs, public State, command args or returned identities.
	token := files[names[3]]
	cmd, err := Build(plan, binary, root, string(token[:64]))
	if err != nil {
		return nil, CredentialIdentity{}, err
	}
	defer cmd.Clear()
	content := cmd.ProtectedConfigBytes()
	if len(content) == 0 || len(content) > credentials.MaxPrivateFileBytes {
		clear(content)
		return nil, CredentialIdentity{}, fmt.Errorf("QUIC rendered private config size invalid")
	}
	return content, identity, nil
}

// renderHelperConfigFromProtected reads only exact role-private 0600
// credential files through held descriptors; the bytes never escape.
func renderHelperConfigFromProtected(root string, plan Plan, binary string) ([]byte, CredentialIdentity, error) {
	fd, err := openRoleDir(root, plan.LinkID, false)
	if err != nil {
		return nil, CredentialIdentity{}, err
	}
	defer unix.Close(fd)
	if err := requireExclusiveRole(fd, plan.Role); err != nil {
		return nil, CredentialIdentity{}, err
	}
	names, _ := roleFiles(plan.Role)
	files := make(map[string][]byte, len(names))
	defer clearRoleFiles(files)
	for _, name := range names {
		raw, err := credentials.ReadPrivateFile(fd, name)
		if err != nil {
			return nil, CredentialIdentity{}, err
		}
		files[name] = raw
	}
	return renderHelperConfigFromFiles(root, plan, binary, files)
}

// PreviewHelperConfig computes an anticipated secret-free fingerprint envelope
// from the supplied in-memory bundle, exact Plan, State root and officially
// pinned executable. It performs NO file publication or host effects. Its
// output may be recorded as expected identities in a future Engine journal;
// it does NOT prove any credential/config file exists or is owned.
func PreviewHelperConfig(root string, plan Plan, localWGUDPPort uint16, binary string,
	bundle CredentialBundle) (HelperConfigIdentity, error) {
	return previewHelperConfig(root, plan, localWGUDPPort, binary, bundle, InspectPinnedHysteria)
}

func previewHelperConfig(root string, plan Plan, localWGUDPPort uint16, binary string,
	bundle CredentialBundle, verify helperVerifier) (HelperConfigIdentity, error) {
	if err := helperConfigPreflight(root, plan, localWGUDPPort, binary); err != nil {
		return HelperConfigIdentity{}, err
	}
	if verify == nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC pinned helper inspection unavailable")
	}
	executable, err := verify(binary)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC official helper admission failed: %w", err)
	}
	files := bundle.ProtectedFiles()
	defer clearRoleFiles(files)
	content, credID, err := renderHelperConfigFromFiles(root, plan, binary, files)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	defer clear(content)
	sum := sha256.Sum256(content)
	return HelperConfigIdentity{
		ConfigSHA256: hex.EncodeToString(sum[:]),
		Credentials:  credID,
		Executable:   executable,
	}, nil
}

// StageExpectedMaterials is a SOURCE-ONLY protected-file writer for a
// canonical Engine that has ALREADY durably journaled the exact expected
// fingerprints, verified State and acquired maintenance/Link/resource locks.
// It rejects any bundle, Plan, binary or expected identity drift BEFORE the
// first write. Publication is no-replace and readback-checked; incomplete or
// uncertain private files are PRESERVED, never erased or adopted as owned.
// This does not start a helper, attest host resources, or clear quarantine.
func StageExpectedMaterials(ctx context.Context, root string, plan Plan, localWGUDPPort uint16, binary string,
	bundle CredentialBundle, expected HelperConfigIdentity) (HelperConfigIdentity, error) {
	return stageExpectedMaterials(ctx, root, plan, localWGUDPPort, binary, bundle, expected, InspectPinnedHysteria)
}

func stageExpectedMaterials(ctx context.Context, root string, plan Plan, localWGUDPPort uint16, binary string,
	bundle CredentialBundle, expected HelperConfigIdentity, verify helperVerifier) (HelperConfigIdentity, error) {
	if ctx == nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC material staging context is required")
	}
	if err := ctx.Err(); err != nil {
		return HelperConfigIdentity{}, err
	}
	preview, err := previewHelperConfig(root, plan, localWGUDPPort, binary, bundle, verify)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	if preview != expected {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC in-memory material does not match immutable expected journal identity")
	}
	// Official binary verification and TLS rendering may take time.
	// Cancellation found before publication must never create private files.
	if err := ctx.Err(); err != nil {
		return HelperConfigIdentity{}, err
	}
	creds, err := StageCredentials(root, plan, bundle)
	if err != nil || creds != expected.Credentials {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC protected credentials could not be staged and verified")
	}
	// Cancellation after credential publication is a potentially partial
	// write. Keep those files and the unresolved Engine journal intact.
	if err := ctx.Err(); err != nil {
		return HelperConfigIdentity{}, err
	}
	got, err := stageHelperConfig(root, plan, localWGUDPPort, binary, verify)
	if err != nil || got != expected {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC protected helper config publication could not be verified")
	}
	return got, nil
}

func inspectHelperConfig(root string, plan Plan, localWGUDPPort uint16, binary string,
	verify helperVerifier) (HelperConfigIdentity, error) {
	if err := helperConfigPreflight(root, plan, localWGUDPPort, binary); err != nil {
		return HelperConfigIdentity{}, err
	}
	if verify == nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC pinned helper inspection unavailable")
	}
	executable, err := verify(binary)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC official helper admission failed: %w", err)
	}
	expected, credID, err := renderHelperConfigFromProtected(root, plan, binary)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	defer clear(expected)
	fd, err := openRoleDir(root, plan.LinkID, false)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	defer unix.Close(fd)
	if err := requireExclusiveRole(fd, plan.Role); err != nil {
		return HelperConfigIdentity{}, err
	}
	actual, err := credentials.ReadPrivateFile(fd, "helper.json")
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	defer clear(actual)
	if !bytes.Equal(actual, expected) {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC protected helper config does not match exact role credentials and topology")
	}
	digest := sha256.Sum256(actual)
	return HelperConfigIdentity{
		ConfigSHA256: hex.EncodeToString(digest[:]),
		Credentials:  credID,
		Executable:   executable,
	}, nil
}

func stageHelperConfig(root string, plan Plan, localWGUDPPort uint16, binary string,
	verify helperVerifier) (HelperConfigIdentity, error) {
	if err := helperConfigPreflight(root, plan, localWGUDPPort, binary); err != nil {
		return HelperConfigIdentity{}, err
	}
	if verify == nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC pinned helper inspection unavailable")
	}
	executable, err := verify(binary)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC official helper admission failed: %w", err)
	}
	content, credID, err := renderHelperConfigFromProtected(root, plan, binary)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	defer clear(content)
	fd, err := openRoleDir(root, plan.LinkID, false)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	defer unix.Close(fd)
	if err := requireExclusiveRole(fd, plan.Role); err != nil {
		return HelperConfigIdentity{}, err
	}
	if err := credentials.WritePrivateNoReplace(fd, "helper.json", content); err != nil {
		return HelperConfigIdentity{}, err
	}
	sum := sha256.Sum256(content)
	identity := HelperConfigIdentity{
		ConfigSHA256: hex.EncodeToString(sum[:]),
		Credentials:  credID,
		Executable:   executable,
	}
	readback, err := inspectHelperConfig(root, plan, localWGUDPPort, binary, verify)
	if err != nil || readback != identity {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC protected helper config publication not durably verified")
	}
	return readback, nil
}
