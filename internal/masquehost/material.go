package masquehost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

const materialDir = "masque"

func (h *Host) materialPath(id domain.LinkID) (string, error) {
	if id.Validate() != nil {
		return "", errors.New("MASQUE invalid material owner identity")
	}
	return filepath.Join(h.root, materialDir, string(id)), nil
}

func safeRootDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("MASQUE directory is not an absolute canonical path")
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fmt.Errorf("MASQUE protected directory unavailable: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o077 != 0 {
		return errors.New("MASQUE protected directory must be root-owned and mode 0700")
	}
	return nil
}

func trustedFile(path string, maximum int64) ([]byte, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return nil, fmt.Errorf("MASQUE protected file unavailable: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 ||
		st.Mode&0o077 != 0 || st.Mode&0o6000 != 0 || st.Nlink != 1 ||
		st.Size == 0 || st.Size > maximum {
		return nil, errors.New("MASQUE protected file has invalid owner, type, permissions or size")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "masque-owned")
	defer file.Close()
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Uid != 0 || st.Mode&0o077 != 0 || st.Nlink != 1 || st.Size == 0 || st.Size > maximum {
		return nil, errors.New("MASQUE opened credential identity has changed")
	}
	raw := make([]byte, st.Size)
	if _, err = io.ReadFull(file, raw); err != nil {
		return nil, errors.New("MASQUE protected credential could not be read")
	}
	return raw, nil
}

func writeMaterialHash(w hash.Hash, filename string, contents []byte) {
	_, _ = w.Write([]byte(filename + "\x00"))
	_, _ = w.Write(contents)
	_, _ = w.Write([]byte("\x00"))
}

func materialNames(link domain.Link) []string {
	if link.MASQUE.Role == "listen" {
		return []string{"agent.json", "server-cert.pem", "server-key.pem"}
	}
	return []string{"agent.json", "client-cert.pem", "client-key.pem", "server-ca.pem"}
}

func (h *Host) inspectMaterial(link domain.Link) (string, string, error) {
	d, err := h.materialPath(link.ID)
	if err != nil {
		return "", "", err
	}
	for _, path := range []string{h.root, filepath.Join(h.root, materialDir), d} {
		if err = safeRootDirectory(path); err != nil {
			return "", "", err
		}
	}
	agent := filepath.Join(d, "agent.json")
	var (
		names  = materialNames(link)
		hasher = sha256.New()
	)
	for _, name := range names {
		raw, readErr := trustedFile(filepath.Join(d, name), 1<<20)
		if readErr != nil {
			return "", "", readErr
		}
		writeMaterialHash(hasher, name, raw)
		clear(raw)
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if link.MASQUE.MaterialSHA256 != digest {
		return "", "", errors.New("MASQUE exact protected material digest does not match committed Link identity")
	}
	name, err := masque.AgentInterfaceName(link.ID)
	if err != nil {
		return "", "", err
	}
	mtu := 1280
	if link.MTU.Mode == domain.MTUManual {
		mtu = link.MTU.Bytes
	}
	switch link.MASQUE.Role {
	case "dial":
		c, readErr := masque.ReadProtectedAgentConfig(agent)
		if readErr != nil {
			return "", "", readErr
		}
		if c.LinkID != link.ID || c.Interface != name || c.PrivateIPv4 != link.Addresses.Local.Addr().String() ||
			c.PeerIPv4 != link.Addresses.Peer.Addr().String() || c.MTU != mtu ||
			c.Address != net.JoinHostPort(link.Underlay.Peer.String(), strconv.Itoa(int(link.MASQUE.TCPPort))) ||
			c.ServerName != link.MASQUE.TLSServerName ||
			(c.RequestPath != "" && c.RequestPath != "/.well-known/masque/ip/") ||
			c.CACertFile != filepath.Join(d, "server-ca.pem") ||
			c.ClientCertFile != filepath.Join(d, "client-cert.pem") ||
			c.ClientKeyFile != filepath.Join(d, "client-key.pem") ||
			c.User != "" || c.PasswordFile != "" {
			return "", "", errors.New("MASQUE dial protected config differs from desired Link identity")
		}
	case "listen":
		c, readErr := masque.ReadProtectedListenConfig(agent)
		if readErr != nil {
			return "", "", readErr
		}
		if c.LinkID != link.ID || c.Interface != name || c.PrivateIPv4 != link.Addresses.Local.Addr().String() ||
			c.PeerIPv4 != link.Addresses.Peer.Addr().String() || c.MTU != mtu ||
			c.ListenAddress != net.JoinHostPort(link.Underlay.Local.String(), strconv.Itoa(int(link.MASQUE.TCPPort))) ||
			c.TLSServerName != link.MASQUE.TLSServerName ||
			c.ServerCertFile != filepath.Join(d, "server-cert.pem") ||
			c.ServerKeyFile != filepath.Join(d, "server-key.pem") ||
			strings.ContainsAny(c.PeerSPKIBase64, "\r\n\x00") {
			return "", "", errors.New("MASQUE listen protected config differs from desired Link identity")
		}
	default:
		return "", "", errors.New("MASQUE role invalid")
	}
	return agent, digest, nil
}
