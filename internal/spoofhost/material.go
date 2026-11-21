// Package spoofhost owns link-scoped protected credentials and eventually the
// production Linux service lifecycle for the opt-in Direct TUN Spoof backend.
// It must not create an independent Link/State manager.
package spoofhost

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

const materialVersion = 1

// Material must be written ONLY into private exact-owner storage. It is
// intentionally not marshalable as ordinary JSON or printable with secrets.
type Material struct {
	id              domain.LinkID
	role            string
	staticPrivate   [32]byte
	bootstrapSecret [32]byte
}

func NewMaterial(id domain.LinkID, role string, localPrivate, bootstrap [32]byte) (Material, error) {
	m := Material{id: id, role: role, staticPrivate: localPrivate, bootstrapSecret: bootstrap}
	if err := m.Validate(); err != nil {
		return Material{}, err
	}
	return m, nil
}
func (m Material) String() string             { return fmt.Sprintf("SpoofMaterial<redacted link=%s>", m.id) }
func (m Material) GoString() string           { return m.String() }
func (m Material) Identity() domain.LinkID    { return m.id }
func (m Material) Role() string               { return m.role }
func (m Material) StaticPrivateKey() [32]byte { return m.staticPrivate }
func (m Material) BootstrapKey() [32]byte     { return m.bootstrapSecret }
func (m Material) PublicKey() ([32]byte, error) {
	var pub [32]byte
	key, err := ecdh.X25519().NewPrivateKey(m.staticPrivate[:])
	if err != nil {
		return pub, err
	}
	copy(pub[:], key.PublicKey().Bytes())
	return pub, nil
}
func (m Material) Validate() error {
	if err := m.id.Validate(); err != nil {
		return err
	}
	if m.role != "creator" && m.role != "recipient" {
		return errors.New("invalid Spoof material role")
	}
	if m.staticPrivate == ([32]byte{}) || m.bootstrapSecret == ([32]byte{}) {
		return errors.New("protected Spoof material needs nonzero local identity and bootstrap secret")
	}
	_, err := m.PublicKey()
	return err
}

type diskMaterial struct {
	SchemaVersion int           `json:"schema_version"`
	LinkID        domain.LinkID `json:"link_id"`
	Role          string        `json:"role"`
	PrivateKey    string        `json:"static_private_key"`
	Bootstrap     string        `json:"bootstrap_secret"`
}

func (m Material) encodeProtected() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(diskMaterial{SchemaVersion: materialVersion, LinkID: m.id, Role: m.role,
		PrivateKey: base64.RawURLEncoding.EncodeToString(m.staticPrivate[:]),
		Bootstrap:  base64.RawURLEncoding.EncodeToString(m.bootstrapSecret[:])})
}
func parseMaterial(raw []byte) (Material, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var wire diskMaterial
	if d.Decode(&wire) != nil || wire.SchemaVersion != materialVersion {
		return Material{}, errors.New("invalid Spoof protected material schema")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Material{}, errors.New("trailing Spoof protected material data")
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(wire.PrivateKey)
	if err != nil || len(secret) != 32 {
		return Material{}, errors.New("invalid Spoof local private identity")
	}
	bootstrap, err := base64.RawURLEncoding.Strict().DecodeString(wire.Bootstrap)
	if err != nil || len(bootstrap) != 32 {
		return Material{}, errors.New("invalid Spoof local bootstrap secret")
	}
	m := Material{id: wire.LinkID, role: wire.Role}
	copy(m.staticPrivate[:], secret)
	copy(m.bootstrapSecret[:], bootstrap)
	if err := m.Validate(); err != nil {
		return Material{}, err
	}
	canonical, err := m.encodeProtected()
	if err != nil || !bytes.Equal(raw, canonical) {
		return Material{}, errors.New("Spoof protected material is noncanonical or duplicated")
	}
	return m, nil
}

func MaterialFile(root string, id domain.LinkID) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" ||
		id.Validate() != nil {
		return "", errors.New("Spoof material requires canonical State root and Link ID")
	}
	return filepath.Join(root, "spoof", string(id), "material.json"), nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("protected Spoof directory %q has unsafe mode, type or owner", path)
	}
	return nil
}

func prepareDirectories(root string, id domain.LinkID) (string, error) {
	filename, err := MaterialFile(root, id)
	if err != nil {
		return "", err
	}
	// Existing root is managed by canonical State. Never grant trust to a
	// foreign inode or symlink solely because the path has the right name.
	if err := requirePrivateDirectory(root); err != nil {
		return "", err
	}
	parent := filepath.Join(root, "spoof")
	if err := os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	if err := requirePrivateDirectory(parent); err != nil {
		return "", err
	}
	linkDir := filepath.Dir(filename)
	if err := os.Mkdir(linkDir, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	if err := requirePrivateDirectory(linkDir); err != nil {
		return "", err
	}
	return filename, nil
}

// StageMaterial is idempotent for exact credentials and never replaces
// competing private material. It is called only from the Engine's protected
// provision callback after reservation/ownership checks.
func StageMaterial(root string, m Material) (string, error) {
	payload, err := m.encodeProtected()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	filename, err := prepareDirectories(root, m.id)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(filename); err == nil {
		_, previous, readErr := ReadMaterial(root, m.id, digest)
		if readErr != nil || previous != digest {
			return "", errors.New("Spoof original protected material already exists with another identity")
		}
		return digest, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	dir := filepath.Dir(filename)
	temp, err := os.CreateTemp(dir, ".stl-spoof-*.tmp")
	if err != nil {
		return "", err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return "", err
	}
	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, tempName, unix.AT_FDCWD, filename, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			_, previous, readErr := ReadMaterial(root, m.id, digest)
			if readErr == nil && previous == digest {
				return digest, nil
			}
			return "", errors.New("Spoof protected material collision: original credentials differ")
		}
		return "", fmt.Errorf("atomic Spoof material publication: %w", err)
	}
	f, err := os.Open(dir)
	if err != nil {
		return "", fmt.Errorf("Spoof material committed but durability uncertain: %w", err)
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return "", fmt.Errorf("Spoof material committed but directory durability uncertain: %w", err)
	}
	return digest, nil
}

// ReadMaterial must only be used by the original managed helper or by an
// Engine provisioning/retirement inspector. The expected SHA comes from
// committed desired State, not an arbitrary filename or process argument.
func ReadMaterial(root string, id domain.LinkID, expectedSHA string) (Material, string, error) {
	filename, err := MaterialFile(root, id)
	if err != nil {
		return Material{}, "", err
	}
	fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Material{}, "", fmt.Errorf("protected Spoof material absent: %w", err)
	}
	f := os.NewFile(uintptr(fd), "spoof-protected-material")
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 ||
		stat.Size() <= 0 || stat.Size() > 4096 ||
		stat.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return Material{}, "", errors.New("Spoof protected material has untrusted inode/ownership/permissions")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return Material{}, "", errors.New("cannot read protected Spoof material")
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if expectedSHA != "" && digest != expectedSHA {
		return Material{}, "", errors.New("Spoof original protected material SHA256 differs from committed Link")
	}
	m, err := parseMaterial(raw)
	if err != nil {
		return Material{}, "", err
	}
	if m.id != id {
		return Material{}, "", errors.New("protected Spoof material belongs to another Link")
	}
	return m, digest, nil
}

// ConfirmLocalIdentity checks the original protected material against the
// public immutable Link identity, preventing replacement of a staged key.
func ConfirmLocalIdentity(link domain.Link, material Material) error {
	if link.Backend != domain.BackendSpoof || material.id != link.ID ||
		material.role != link.Spoof.Role {
		return errors.New("Spoof original material does not belong to committed Link")
	}
	pub, err := material.PublicKey()
	if err != nil {
		return err
	}
	if link.Spoof.LocalPublicKey != base64.RawURLEncoding.EncodeToString(pub[:]) {
		return errors.New("Spoof committed Link local identity differs from protected key")
	}
	return nil
}
