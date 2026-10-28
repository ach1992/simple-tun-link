package quic

import (
	"bytes"
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

// renderHelperConfigFromProtected opens only the exact role's existing 0600
// credential files, validates TLS/CA/Link identity and reads the per-Link
// bearer through a held descriptor. The returned JSON is sensitive and
// MUST be cleared by the caller after use.
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
	identity, err := validateRoleMaterial(plan, files)
	if err != nil {
		return nil, CredentialIdentity{}, err
	}
	// Build accepts a string token. The protected byte copies are cleared
	// immediately after rendering; neither raw token nor config is logged.
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
