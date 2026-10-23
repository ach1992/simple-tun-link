package wss

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

// CaptureFileIdentity reads exact private issuance files under descriptor
// verified owner-only directories, returning only SHA-256 fingerprints.
func CaptureFileIdentity(root string, link domain.Link) (state.WSSFileIdentity, error) {
	if link.Backend != domain.BackendWireGuardWSS || link.ID.Validate() != nil {
		return state.WSSFileIdentity{}, fmt.Errorf("invalid WSS identity capture Link")
	}
	rootFD, err := credentials.OpenProtected(root, false)
	if err != nil {
		return state.WSSFileIdentity{}, err
	}
	defer unix.Close(rootFD)
	wssFD, err := openOwnedPrivateDir(rootFD, "wss")
	if err != nil {
		return state.WSSFileIdentity{}, err
	}
	defer unix.Close(wssFD)
	linkFD, err := openOwnedPrivateDir(wssFD, string(link.ID))
	if err != nil {
		return state.WSSFileIdentity{}, err
	}
	defer unix.Close(linkFD)
	names, err := WSSRoleFiles(link)
	if err != nil {
		return state.WSSFileIdentity{}, err
	}
	var values [5]string
	for i, name := range names {
		if name == "" {
			continue
		}
		raw, err := readPrivateFile(linkFD, name)
		if err != nil {
			return state.WSSFileIdentity{}, fmt.Errorf("missing original WSS credential fingerprint: %w", err)
		}
		value := sha256.Sum256(raw)
		clear(raw)
		values[i] = hex.EncodeToString(value[:])
	}
	result := state.WSSFileIdentity{
		Certificate: values[0], TLSKey: values[1], TrustCA: values[2],
		Authorization: values[3], Restrictions: values[4],
	}
	if err := result.VerifyLink(link); err != nil {
		return state.WSSFileIdentity{}, err
	}
	return result, nil
}
func WSSRoleFiles(link domain.Link) ([5]string, error) {
	switch link.WSS.Role {
	case "listen":
		return [5]string{"server-cert.pem", "server-key.pem", "client-ca.pem", "authorization-token", "restrictions.yaml"}, nil
	case "dial":
		return [5]string{"client-cert.pem", "client-key.pem", "server-ca.pem", "authorization-headers", ""}, nil
	default:
		return [5]string{}, errors.New("invalid WSS retirement role")
	}
}
