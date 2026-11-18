package masquehost

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// BuildMaterial is pure pairing/planning: no service, State, filesystem or
// firewall changes. It returns exact fixed-name, protected per-Link files.
// Each endpoint gets only its own TLS private key; never a peer private key.
func BuildMaterial(root string, link domain.Link, pair masque.PairMaterial) (domain.Link, map[string][]byte, error) {
	if link.ID.Validate() != nil || link.Backend != domain.BackendMASQUE ||
		(link.MASQUE.Role != "dial" && link.MASQUE.Role != "listen") ||
		pair.ClientSPKIBase64 == "" || len(pair.ServerCA) == 0 ||
		len(pair.ServerCertificate) == 0 || len(pair.ClientCertificate) == 0 {
		return link, nil, errors.New("MASQUE pairing material or role invalid")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return link, nil, errors.New("MASQUE material target root must be canonical")
	}
	dir := filepath.Join(root, materialDir, string(link.ID))
	name, err := masque.AgentInterfaceName(link.ID)
	if err != nil {
		return link, nil, err
	}
	mtu := 1280
	if link.MTU.Mode == domain.MTUManual {
		mtu = link.MTU.Bytes
	}
	files := make(map[string][]byte)
	switch link.MASQUE.Role {
	case "listen":
		cfg := masque.ListenAgentConfig{
			SchemaVersion: 1, LinkID: link.ID, Interface: name,
			PrivateIPv4: link.Addresses.Local.Addr().String(),
			PeerIPv4:    link.Addresses.Peer.Addr().String(),
			MTU:         mtu, ListenAddress: net.JoinHostPort(link.Underlay.Local.String(), strconv.Itoa(int(link.MASQUE.TCPPort))),
			TLSServerName:  link.MASQUE.TLSServerName,
			ServerCertFile: filepath.Join(dir, "server-cert.pem"),
			ServerKeyFile:  filepath.Join(dir, "server-key.pem"),
			PeerSPKIBase64: pair.ClientSPKIBase64,
		}
		files["server-cert.pem"] = bytes.Clone(pair.ServerCertificate)
		files["server-key.pem"] = bytes.Clone(pair.ServerPrivateKey)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return link, nil, err
		}
		files["agent.json"] = raw
	case "dial":
		cfg := masque.DialAgentConfig{
			SchemaVersion: 1, LinkID: link.ID, Interface: name,
			PrivateIPv4: link.Addresses.Local.Addr().String(),
			PeerIPv4:    link.Addresses.Peer.Addr().String(),
			MTU:         mtu, Address: net.JoinHostPort(link.Underlay.Peer.String(), strconv.Itoa(int(link.MASQUE.TCPPort))),
			ServerName:     link.MASQUE.TLSServerName,
			CACertFile:     filepath.Join(dir, "server-ca.pem"),
			ClientCertFile: filepath.Join(dir, "client-cert.pem"),
			ClientKeyFile:  filepath.Join(dir, "client-key.pem"),
		}
		files["server-ca.pem"] = bytes.Clone(pair.ServerCA)
		files["client-cert.pem"] = bytes.Clone(pair.ClientCertificate)
		files["client-key.pem"] = bytes.Clone(pair.ClientPrivateKey)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return link, nil, err
		}
		files["agent.json"] = raw
	}
	hasher := sha256.New()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		writeMaterialHash(hasher, name, files[name])
	}
	link.MASQUE.MaterialSHA256 = hex.EncodeToString(hasher.Sum(nil))
	if err = link.Validate(); err != nil {
		ClearFiles(files)
		return link, nil, err
	}
	return link, files, nil
}

func ClearFiles(files map[string][]byte) {
	for name, raw := range files {
		clear(raw)
		delete(files, name)
	}
}

// VerifyMaterialBundle rejects altered/truncated private handoffs before any
// protected filesystem publication, instead of leaving a partially staged
// credential generation that the Engine cannot safely activate.
func VerifyMaterialBundle(root string, link domain.Link, files map[string][]byte) error {
	if link.Backend != domain.BackendMASQUE || link.Validate() != nil ||
		!filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("MASQUE imported Link/material root invalid")
	}
	names := materialNames(link)
	if len(names) != len(files) {
		return errors.New("MASQUE private material contains an unexpected file set")
	}
	hasher := sha256.New()
	for _, name := range names {
		raw, ok := files[name]
		if !ok || len(raw) == 0 || len(raw) > 1<<20 {
			return errors.New("MASQUE protected file missing or oversized")
		}
		writeMaterialHash(hasher, name, raw)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != link.MASQUE.MaterialSHA256 {
		return errors.New("MASQUE imported file digest does not match the Link")
	}
	dir := filepath.Join(root, materialDir, string(link.ID))
	name, _ := masque.AgentInterfaceName(link.ID)
	mtu := 1280
	if link.MTU.Mode == domain.MTUManual {
		mtu = link.MTU.Bytes
	}
	switch link.MASQUE.Role {
	case "listen":
		var cfg masque.ListenAgentConfig
		dec := json.NewDecoder(bytes.NewReader(files["agent.json"]))
		dec.DisallowUnknownFields()
		if dec.Decode(&cfg) != nil || cfg.SchemaVersion != 1 ||
			cfg.LinkID != link.ID || cfg.Interface != name ||
			cfg.PrivateIPv4 != link.Addresses.Local.Addr().String() ||
			cfg.PeerIPv4 != link.Addresses.Peer.Addr().String() || cfg.MTU != mtu ||
			cfg.ListenAddress != net.JoinHostPort(link.Underlay.Local.String(), strconv.Itoa(int(link.MASQUE.TCPPort))) ||
			cfg.TLSServerName != link.MASQUE.TLSServerName ||
			cfg.ServerCertFile != filepath.Join(dir, "server-cert.pem") ||
			cfg.ServerKeyFile != filepath.Join(dir, "server-key.pem") {
			return errors.New("MASQUE imported listener config differs from expected Link")
		}
		if _, _, err := cfg.Validate(); err != nil {
			return err
		}
		cert, err := tls.X509KeyPair(files["server-cert.pem"], files["server-key.pem"])
		if err != nil {
			return errors.New("MASQUE imported TLS listener certificate/key invalid")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil || leaf.VerifyHostname(link.MASQUE.TLSServerName) != nil {
			return errors.New("MASQUE imported TLS listener name not verified")
		}
	case "dial":
		var cfg masque.DialAgentConfig
		dec := json.NewDecoder(bytes.NewReader(files["agent.json"]))
		dec.DisallowUnknownFields()
		if dec.Decode(&cfg) != nil || cfg.SchemaVersion != 1 ||
			cfg.LinkID != link.ID || cfg.Interface != name ||
			cfg.PrivateIPv4 != link.Addresses.Local.Addr().String() ||
			cfg.PeerIPv4 != link.Addresses.Peer.Addr().String() || cfg.MTU != mtu ||
			cfg.Address != net.JoinHostPort(link.Underlay.Peer.String(), strconv.Itoa(int(link.MASQUE.TCPPort))) ||
			cfg.ServerName != link.MASQUE.TLSServerName ||
			cfg.ClientCertFile != filepath.Join(dir, "client-cert.pem") ||
			cfg.ClientKeyFile != filepath.Join(dir, "client-key.pem") ||
			cfg.CACertFile != filepath.Join(dir, "server-ca.pem") ||
			cfg.User != "" || cfg.PasswordFile != "" || cfg.RequestPath != "" {
			return errors.New("MASQUE imported dial config differs from expected Link")
		}
		if _, _, err := cfg.Validate(); err != nil {
			return err
		}
		if _, err := tls.X509KeyPair(files["client-cert.pem"], files["client-key.pem"]); err != nil {
			return errors.New("MASQUE imported client certificate/key invalid")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(files["server-ca.pem"]) {
			return errors.New("MASQUE imported server trust root invalid")
		}
	}
	return nil
}

// StageFiles must run exclusively inside the canonical Engine's Link lock.
// Create-only, descriptor-relative writes protect existing private identities;
// no foreign directory or pre-existing material is ever adopted or replaced.
func StageFiles(root string, link domain.Link, files map[string][]byte) error {
	if os.Geteuid() != 0 || link.Backend != domain.BackendMASQUE || link.Validate() != nil ||
		!filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("MASQUE stage requires root and validated Link")
	}
	if err := VerifyMaterialBundle(root, link, files); err != nil {
		return err
	}
	if err := safeRootDirectory(root); err != nil {
		return err
	}
	parent := filepath.Join(root, materialDir)
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := safeRootDirectory(parent); err != nil {
		return err
	}
	dir := filepath.Join(parent, string(link.ID))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("MASQUE material generation already exists or cannot be reserved: %w", err)
	}
	defer func() {
		// A failed Stage leaves an explicitly reserved directory for
		// reconciliation, never a confusing auto-adopted partial bundle.
	}()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	names := materialNames(link)
	if len(names) != len(files) {
		return errors.New("MASQUE staged material has unexpected file count")
	}
	hasher := sha256.New()
	for _, name := range names {
		raw, ok := files[name]
		if !ok || len(raw) == 0 || len(raw) > 1<<20 || strings.ContainsAny(name, "/\\\x00") {
			return errors.New("MASQUE staged file set is incomplete or malformed")
		}
		writeMaterialHash(hasher, name, raw)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != link.MASQUE.MaterialSHA256 {
		return errors.New("MASQUE staged protected material differs from Link binding")
	}
	for _, name := range names {
		fdFile, openErr := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if openErr != nil {
			return fmt.Errorf("MASQUE protected file already exists or unavailable: %w", openErr)
		}
		file := os.NewFile(uintptr(fdFile), "masque-staged")
		n, writeErr := file.Write(files[name])
		if writeErr == nil && n != len(files[name]) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("MASQUE protected credential write/durability failed")
		}
	}
	if err = unix.Fsync(fd); err != nil {
		return errors.New("MASQUE material directory durability failed")
	}
	// Every stage remains uncommitted until Engine's later backend Verify and
	// State publication; callers must not infer service success from this.
	return nil
}

func VerifyStagedFiles(root string, link domain.Link) error {
	h := &Host{root: root}
	_, _, err := h.inspectMaterial(link)
	return err
}
