package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/spoofhost"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func spoofCLIError(err error, stderr io.Writer) int {
	fmt.Fprintf(stderr, "Spoof Link: %v\n", err)
	// These typed, non-secret failures are operator-relevant diagnostics;
	// a machine may fix ownership, unit identity or systemd enablement.
	var restoreFailure *linux.RestoreFailure
	if errors.As(err, &restoreFailure) {
		fmt.Fprintf(stderr, "RestorePersistence: reason=%s; diagnostic=%v\n",
			restoreFailure.Kind, restoreFailure.Cause)
	}
	return 1
}
func spoofCLIOptions(options *runtimeOptions) (*runtimeOptions, error) {
	if options != nil {
		return options, nil
	}
	return assembleRuntimeOptionsForBackend(state.DefaultRoot, domain.BackendSpoof)
}
func sourceReady(path string) error {
	_, err := spoof.ReadSources(path)
	if err != nil {
		return fmt.Errorf("create/recheck the local Source list first: %w", err)
	}
	return nil
}
func writeProtectedOffer(path, code string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("Setup Code output must be an absolute normalized file path")
	}
	stat, err := os.Lstat(filepath.Dir(path))
	if err != nil || !stat.IsDir() || stat.Mode().Perm()&0022 != 0 {
		return errors.New("Setup Code parent directory unavailable or writable by others")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("refuse to overwrite confidential Setup Code: %w", err)
	}
	if _, err = f.WriteString(code + "\n"); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
func readProtectedOffer(path string) (pairing.SpoofSetup, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return pairing.SpoofSetup{}, errors.New("Setup Code must be in a protected absolute file")
	}
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 || stat.Size() > 4096 {
		return pairing.SpoofSetup{}, errors.New("Setup Code file missing, insecure or oversized")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return pairing.SpoofSetup{}, err
	}
	return pairing.DecodeSensitiveSpoofSetup(string(raw))
}
func spoofLinkFromSetup(offer pairing.SpoofSetup, material spoofhost.Material, sourceFile, device string) (domain.Link, error) {
	role := material.Role()
	if role != "creator" && role != "recipient" {
		return domain.Link{}, errors.New("invalid local Spoof identity role")
	}
	local, peer := offer.CreatorEndpoint(), offer.RecipientEndpoint()
	privateLocal, privatePeer := offer.CreatorPrivateIPv4(), offer.RecipientPrivateIPv4()
	remoteIdentity := ""
	if role == "recipient" {
		local, peer = peer, local
		privateLocal, privatePeer = privatePeer, privateLocal
		creatorPublic := offer.CreatorPublicKey()
		remoteIdentity = base64.RawURLEncoding.EncodeToString(creatorPublic[:])
	}
	self, err := material.PublicKey()
	if err != nil {
		return domain.Link{}, err
	}
	digest, err := material.Digest()
	if err != nil {
		return domain.Link{}, err
	}
	link := domain.Link{ID: offer.LinkID(), Backend: domain.BackendSpoof, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: local.Addr(), Peer: peer.Addr()},
		Addresses: domain.LinkAddresses{Local: netip.PrefixFrom(privateLocal, 32), Peer: netip.PrefixFrom(privatePeer, 32)},
		Spoof: domain.SpoofOptions{Role: role, SourceFile: sourceFile, ListenPort: local.Port(),
			PeerPort: peer.Port(), BindIPv4: local.Addr(), Interface: device,
			LocalPublicKey: base64.RawURLEncoding.EncodeToString(self[:]),
			PeerPublicKey:  remoteIdentity, MaterialSHA256: digest},
	}
	return link, link.Validate()
}
func spoofResult(out io.Writer, jsonOutput bool, op string, result app.Result, offerPath string) int {
	if jsonOutput {
		v := struct {
			SchemaVersion int           `json:"schema_version"`
			Operation     string        `json:"operation"`
			LinkID        domain.LinkID `json:"link_id"`
			Provisioned   bool          `json:"provisioned"`
			PeerConnected bool          `json:"peer_connected"`
			SetupCodeFile string        `json:"setup_code_file,omitempty"`
		}{1, op, result.LinkID, true, false, offerPath}
		if json.NewEncoder(out).Encode(v) != nil {
			return 1
		}
	} else {
		fmt.Fprintf(out, "Spoof %s: Link %s provisioned; peer connectivity NOT yet proven.\n", op, result.LinkID)
		if offerPath != "" {
			fmt.Fprintf(out, "Confidential one-time handoff file: %s\n", offerPath)
		}
	}
	return 0
}
func linkSpoofCommand(args []string, stdout, stderr io.Writer, options *runtimeOptions) int {
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "create-spoof":
		f := flag.NewFlagSet("create-spoof", flag.ContinueOnError)
		f.SetOutput(stderr)
		creator := f.String("creator", "", "creator's real IPv4:PORT")
		recipient := f.String("recipient", "", "recipient's real IPv4:PORT")
		creatorIP := f.String("creator-private", "", "creator's tunnel IPv4")
		recipientIP := f.String("recipient-private", "", "recipient's tunnel IPv4")
		sources := f.String("sources", spoof.DefaultSourcesPath, "local Source file path")
		device := f.String("device", "", "explicit local egress interface (optional)")
		output := f.String("output", "", "private 0600 Setup Code filename")
		asJSON := f.Bool("json", false, "machine response")
		if f.Parse(args[1:]) != nil || len(f.Args()) != 0 {
			return 2
		}
		if *output == "" {
			return spoofCLIError(errors.New("private --output filename required"), stderr)
		}
		if err := sourceReady(*sources); err != nil {
			return spoofCLIError(err, stderr)
		}
		a, err := netip.ParseAddrPort(*creator)
		if err != nil {
			return spoofCLIError(errors.New("invalid --creator IPv4:PORT"), stderr)
		}
		b, err := netip.ParseAddrPort(*recipient)
		if err != nil {
			return spoofCLIError(errors.New("invalid --recipient IPv4:PORT"), stderr)
		}
		aIP, err := netip.ParseAddr(*creatorIP)
		if err != nil {
			return spoofCLIError(errors.New("invalid --creator-private IPv4"), stderr)
		}
		bIP, err := netip.ParseAddr(*recipientIP)
		if err != nil {
			return spoofCLIError(errors.New("invalid --recipient-private IPv4"), stderr)
		}
		id, err := domain.NewLinkID()
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		private, pub, err := spoof.GenerateIdentity()
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		offer, err := pairing.NewSpoofSetup(id, a, b, aIP, bIP, pub)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		m, err := spoofhost.NewMaterial(id, "creator", private, offer.Secret())
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		link, err := spoofLinkFromSetup(offer, m, *sources, *device)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		if *output == "" {
			return spoofCLIError(errors.New("confidential Setup Code file required"), stderr)
		}
		code, err := offer.EncodeSensitive()
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		if err = writeProtectedOffer(*output, code); err != nil {
			return spoofCLIError(err, stderr)
		}
		opts, err := spoofCLIOptions(options)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		engine, err := buildRuntimeEngine(*opts)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		result, err := engine.EnsureWithSpoofProvision(ctx, link, func() error {
			if _, err := spoofhost.StageMaterial(opts.stateRoot, m); err != nil {
				return err
			}
			return spoofhost.StageConfig(opts.stateRoot, link)
		})
		if err != nil {
			return spoofCLIError(fmt.Errorf("Setup Code preserved at %s but Link provisioning not confirmed: %w", *output, err), stderr)
		}
		return spoofResult(stdout, *asJSON, "create", result, *output)

	case "import-spoof", "resume-spoof":
		f := flag.NewFlagSet(args[0], flag.ContinueOnError)
		f.SetOutput(stderr)
		setup := f.String("setup", "", "private creator-issued Setup Code file")
		sources := f.String("sources", spoof.DefaultSourcesPath, "recipient-local source list")
		device := f.String("device", "", "optional recipient-local egress interface")
		asJSON := f.Bool("json", false, "machine response")
		if f.Parse(args[1:]) != nil || len(f.Args()) != 0 {
			return 2
		}
		if err := sourceReady(*sources); err != nil {
			return spoofCLIError(err, stderr)
		}
		offer, err := readProtectedOffer(*setup)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		opts, err := spoofCLIOptions(options)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		// A confirmed re-import MUST reuse the original locally protected B key.
		filename, err := spoofhost.MaterialFile(opts.stateRoot, offer.LinkID())
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		if args[0] == "resume-spoof" {
			m, _, err := spoofhost.ReadMaterial(opts.stateRoot, offer.LinkID(), "")
			if err != nil {
				return spoofCLIError(err, stderr)
			}
			if m.Role() != "creator" || m.BootstrapKey() != offer.Secret() {
				return spoofCLIError(errors.New("Creator resume requires exact original protected identity"), stderr)
			}
			own, err := m.PublicKey()
			if err != nil {
				return spoofCLIError(err, stderr)
			}
			if own != offer.CreatorPublicKey() {
				return spoofCLIError(errors.New("Creator Setup Code and original public key differ"), stderr)
			}
			link, err := spoofLinkFromSetup(offer, m, *sources, *device)
			if err != nil {
				return spoofCLIError(err, stderr)
			}
			snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
			if err != nil {
				return spoofCLIError(err, stderr)
			}
			if saved, present := snapshot.Find(link.ID); present {
				if saved.Desired.Backend != domain.BackendSpoof {
					return spoofCLIError(errors.New("Link ID already owned by another backend"), stderr)
				}
				prior := saved.Desired
				prior.Spoof.PeerPublicKey = ""
				if prior != link {
					return spoofCLIError(errors.New("original protected Spoof topology differs from pending resume"), stderr)
				}
				link = saved.Desired
			}
			engine, err := buildRuntimeEngine(*opts)
			if err != nil {
				return spoofCLIError(err, stderr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			result, err := engine.EnsureWithSpoofProvision(ctx, link, func() error {
				if _, err := spoofhost.StageMaterial(opts.stateRoot, m); err != nil {
					return err
				}
				return spoofhost.StageConfig(opts.stateRoot, link)
			})
			if err != nil {
				return spoofCLIError(err, stderr)
			}
			return spoofResult(stdout, *asJSON, "resume", result, "")
		}
		var m spoofhost.Material
		if _, err = os.Lstat(filename); os.IsNotExist(err) {
			private, _, e := spoof.GenerateIdentity()
			if e != nil {
				return spoofCLIError(e, stderr)
			}
			m, e = spoofhost.NewMaterial(offer.LinkID(), "recipient", private, offer.Secret())
			if e != nil {
				return spoofCLIError(e, stderr)
			}
		} else if err == nil {
			m, _, err = spoofhost.ReadMaterial(opts.stateRoot, offer.LinkID(), "")
			if err != nil {
				return spoofCLIError(err, stderr)
			}
			if m.Role() != "recipient" || m.BootstrapKey() != offer.Secret() {
				return spoofCLIError(errors.New("existing Link has different protected recipient identity"), stderr)
			}
		} else {
			return spoofCLIError(err, stderr)
		}
		link, err := spoofLinkFromSetup(offer, m, *sources, *device)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		engine, err := buildRuntimeEngine(*opts)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		result, err := engine.EnsureWithSpoofProvision(ctx, link, func() error {
			if _, err := spoofhost.StageMaterial(opts.stateRoot, m); err != nil {
				return err
			}
			return spoofhost.StageConfig(opts.stateRoot, link)
		})
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		return spoofResult(stdout, *asJSON, "import", result, "")

	case "spoof-status":
		asJSON := false
		if len(args) == 3 && args[2] == "--json" {
			asJSON = true
		} else if len(args) != 2 {
			return 2
		}
		id := domain.LinkID(args[1])
		if id.Validate() != nil {
			return spoofCLIError(errors.New("invalid Spoof Link ID"), stderr)
		}
		opts, err := spoofCLIOptions(options)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		record, present := snapshot.Find(id)
		if !present || record.Desired.Backend != domain.BackendSpoof {
			return spoofCLIError(errors.New("Spoof Link not committed in local State"), stderr)
		}
		var host *spoofhost.Host
		executable := opts.executable
		if executable == "" {
			executable, err = os.Executable()
			if err != nil {
				return spoofCLIError(err, stderr)
			}
			executable, err = canonicalSTLExecutable(executable)
			if err != nil {
				return spoofCLIError(err, stderr)
			}
		}
		host, err = spoofhost.New(opts.stateRoot, executable)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		observed, err := host.Inspect(context.Background(), record.Desired)
		if err != nil {
			return spoofCLIError(err, stderr)
		}
		status := spoofhost.TrustedRuntimeStatus(opts.stateRoot, id, observed)
		if asJSON {
			r := struct {
				SchemaVersion      int                     `json:"schema_version"`
				LocallyProvisioned bool                    `json:"locally_provisioned"`
				ManagedHelperReady bool                    `json:"managed_helper_ready"`
				Runtime            spoofhost.RuntimeStatus `json:"runtime"`
			}{1, true, observed.RuntimeReady, status}
			if json.NewEncoder(stdout).Encode(r) != nil {
				return 1
			}
		} else {
			fmt.Fprintf(stdout, "Link %s, helper ready=%t, runtime=%s, bilateral=%t, private tx/rx=%d/%d, candidates=%d, last error=%s\n",
				id, observed.RuntimeReady, status.State, status.BilateralConfirmed, status.SentPrivatePackets, status.ReceivedPrivatePackets, status.SourceCandidates, status.LastError)
		}
		return 0
	default:
		return 2
	}
}

func spoofHelperCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--config" || os.Geteuid() != 0 {
		return 2
	}
	filename := args[1]
	id := domain.LinkID(filepath.Base(filepath.Dir(filename)))
	expected, err := spoofhost.ConfigPath(state.DefaultRoot, id)
	if err != nil || filename != expected {
		return spoofCLIError(errors.New("Spoof helper config is not a committed Link-scoped path"), stderr)
	}
	opts, err := assembleRuntimeBackendOptions(state.DefaultRoot, domain.BackendSpoof)
	if err != nil {
		return spoofCLIError(err, stderr)
	}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		return spoofCLIError(err, stderr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = spoofhost.RunAgent(ctx, state.DefaultRoot, id, func(session *spoof.Session) error {
		_, err := engine.BindAuthenticatedSpoofPeer(ctx, session)
		return err
	})
	if err != nil {
		return spoofCLIError(err, stderr)
	}
	fmt.Fprintln(stdout, "Spoof helper stopped")
	return 0
}
