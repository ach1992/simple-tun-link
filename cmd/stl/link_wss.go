package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// This CLI request is deliberately distinct from Native WG v1/v2 and from
// durable State v4. No supplied secret bytes are accepted in creator JSON.
type wssCreateRequest struct {
	SchemaVersion        int                    `json:"schema_version"`
	LinkID               domain.LinkID          `json:"link_id,omitempty"`
	DisplayName          string                 `json:"display_name,omitempty"`
	Underlay             desiredUnderlayV1      `json:"underlay"`
	Addresses            desiredLinkAddressesV1 `json:"addresses"`
	ListenPort           uint16                 `json:"listen_port"`
	PeerPort             uint16                 `json:"peer_port"`
	LocalKeepalive       uint16                 `json:"local_keepalive,omitempty"`
	PeerKeepalive        uint16                 `json:"peer_keepalive,omitempty"`
	Role                 string                 `json:"role"`
	TCPPort              uint16                 `json:"tcp_port"`
	LocalForwardUDPPort  uint16                 `json:"local_forward_udp_port,omitempty"`
	RemoteForwardUDPPort uint16                 `json:"remote_forward_udp_port,omitempty"`
	TLSServerName        string                 `json:"tls_server_name,omitempty"`
}

// Private WSS handoffs cannot be imported by old v1/v2/v3 pairing code.
// The recipient carries only its own key and TLS material. The sender
// retains neither recipient private key nor the trust authority signing key
// in generic state, logs, or normal CLI output.
type wssOffer struct {
	SchemaVersion int               `json:"schema_version"`
	Sender        domain.Link       `json:"sender"`
	Receiver      domain.Link       `json:"receiver"`
	ReceiverWGKey string            `json:"receiver_wireguard_private_key"`
	ReceiverTLS   wss.PrivateBundle `json:"receiver_tls"`
}

func (o *wssOffer) clear() {
	o.ReceiverWGKey = ""
	o.ReceiverTLS.Clear()
}
func (o wssOffer) validate() error {
	if o.SchemaVersion != 1 || o.Sender.Backend != domain.BackendWireGuardWSS ||
		o.Receiver.Backend != domain.BackendWireGuardWSS {
		return fmt.Errorf("unsupported WSS peer handoff")
	}
	key, err := wg.DecodePrivateKey(o.ReceiverWGKey)
	if err != nil {
		return fmt.Errorf("invalid recipient private WireGuard identity")
	}
	defer key.Zeroize()
	pub, err := key.PublicKey()
	if err != nil || pub != o.Receiver.WireGuard.LocalPublicKey {
		return fmt.Errorf("recipient WireGuard private key and public state differ")
	}
	switch o.Sender.WSS.Role {
	case "dial":
		if err := composition.ValidateWSSPeerPair(o.Sender, composition.CarrierForLink(o.Sender),
			o.Receiver, composition.CarrierForLink(o.Receiver)); err != nil {
			return err
		}
	case "listen":
		if err := composition.ValidateWSSPeerPair(o.Receiver, composition.CarrierForLink(o.Receiver),
			o.Sender, composition.CarrierForLink(o.Sender)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid WSS sender role")
	}
	if len(o.ReceiverTLS) != 4 {
		return fmt.Errorf("incomplete receiver TLS handoff")
	}
	return nil
}
func decodeWSSOffer(in io.Reader) (wssOffer, []byte, error) {
	if in == nil {
		return wssOffer{}, nil, fmt.Errorf("missing WSS handoff")
	}
	raw, err := io.ReadAll(io.LimitReader(in, 64<<10+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return wssOffer{}, nil, fmt.Errorf("oversized or unavailable WSS handoff")
	}
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	if err = ensureUnambiguousJSON(raw); err != nil {
		return wssOffer{}, nil, fmt.Errorf("ambiguous WSS handoff")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var offer wssOffer
	if err = dec.Decode(&offer); err != nil {
		return wssOffer{}, nil, fmt.Errorf("invalid WSS handoff schema")
	}
	if err = offer.validate(); err != nil {
		offer.clear()
		return wssOffer{}, nil, fmt.Errorf("invalid or unsupported WSS handoff")
	}
	return offer, raw, nil
}
func makeWSSPair(r wssCreateRequest, id domain.LinkID, localPub, peerPub string) (domain.Link, domain.Link, error) {
	if r.SchemaVersion != 1 || id.Validate() != nil {
		return domain.Link{}, domain.Link{}, fmt.Errorf("invalid WSS request schema or identity")
	}
	sender := domain.Link{
		ID: id, DisplayName: r.DisplayName,
		Underlay:  domain.Underlay{Local: r.Underlay.Local, Peer: r.Underlay.Peer},
		Addresses: domain.LinkAddresses{Local: r.Addresses.Local, Peer: r.Addresses.Peer},
		Backend:   domain.BackendWireGuardWSS, Encapsulation: domain.EncapUDP,
		WireGuard: domain.WireGuardOptions{
			LocalPublicKey: localPub, PeerPublicKey: peerPub,
			ListenPort: r.ListenPort, PeerPort: r.PeerPort,
			LocalKeepalive: r.LocalKeepalive, PeerKeepalive: r.PeerKeepalive,
		},
		WSS: domain.WSSOptions{Role: r.Role, TCPPort: r.TCPPort,
			ForwardUDPPort: r.LocalForwardUDPPort, TLSServerName: r.TLSServerName},
	}
	peerRole := "listen"
	if r.Role == "listen" {
		peerRole = "dial"
	}
	receiver := domain.Link{
		ID: id, DisplayName: r.DisplayName,
		Underlay:  domain.Underlay{Local: r.Underlay.Peer, Peer: r.Underlay.Local},
		Addresses: domain.LinkAddresses{Local: r.Addresses.Peer, Peer: r.Addresses.Local},
		Backend:   domain.BackendWireGuardWSS, Encapsulation: domain.EncapUDP,
		WireGuard: domain.WireGuardOptions{
			LocalPublicKey: peerPub, PeerPublicKey: localPub,
			ListenPort: r.PeerPort, PeerPort: r.ListenPort,
			LocalKeepalive: r.PeerKeepalive, PeerKeepalive: r.LocalKeepalive,
		},
		WSS: domain.WSSOptions{Role: peerRole, TCPPort: r.TCPPort,
			ForwardUDPPort: r.RemoteForwardUDPPort, TLSServerName: r.TLSServerName},
	}
	if r.Role == "dial" && r.RemoteForwardUDPPort != 0 {
		return domain.Link{}, domain.Link{}, fmt.Errorf("WSS listener must not specify a remote forwarder")
	}
	if r.Role == "listen" && r.LocalForwardUDPPort != 0 {
		return domain.Link{}, domain.Link{}, fmt.Errorf("WSS listener must not specify a local forwarder")
	}
	if r.Role == "dial" {
		if err := composition.ValidateWSSPeerPair(sender, composition.CarrierForLink(sender),
			receiver, composition.CarrierForLink(receiver)); err != nil {
			return domain.Link{}, domain.Link{}, err
		}
	} else {
		if err := composition.ValidateWSSPeerPair(receiver, composition.CarrierForLink(receiver),
			sender, composition.CarrierForLink(sender)); err != nil {
			return domain.Link{}, domain.Link{}, err
		}
	}
	return sender, receiver, nil
}
func wssCommandError(operation string, jsonOut bool, id domain.LinkID, code stlerr.Code, reason string, out, errOut io.Writer) int {
	return wireGuardCreationError(out, errOut, jsonOut, code, id, operation+": "+reason)
}

// wssActivationFailure preserves the canonical Engine's typed, secret-free
// lifecycle evidence instead of collapsing all host failures to state_unverified.
// The legacy operation/error code and generic detail remain stable; raw
// backend/process/credential errors must never reach the CLI output.
func wssActivationFailure(operation string, jsonOut bool, id domain.LinkID,
	result app.Result, cause error, detail string, out, errOut io.Writer) int {
	if result.LinkID.Validate() != nil {
		result.LinkID = id
	}
	return lifecycleFailureWithEvidence(out, errOut, jsonOut, stlerr.CodeState,
		"link_create_wireguard", &result, operation+": "+detail, stlerr.EvidenceOf(cause), cause)
}
func wssEngine(options *runtimeOptions) (*app.Engine, *wg.KeyStore, error) {
	if options == nil {
		return nil, nil, fmt.Errorf("WSS runtime unavailable")
	}
	engine, err := buildRuntimeEngine(*options)
	if err != nil {
		return nil, nil, err
	}
	keys, err := wg.NewKeyStore(options.stateRoot)
	if err != nil {
		return nil, nil, err
	}
	return engine, keys, nil
}
func wssCtx() (context.Context, context.CancelFunc) {
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	return ctx, func() { cancel(); stop() }
}
func linkWSSCommand(args []string, in io.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	jsonOut := slices.Contains(args, "--json")
	if len(args) == 0 {
		return wssCommandError("wss", jsonOut, "", stlerr.CodeInvalid, "missing operation", out, errOut)
	}
	operation := args[0]
	switch operation {
	case "create-wss":
		valid := (len(args) == 4 || (len(args) == 5 && args[4] == "--json")) &&
			args[1] == "--stdin" && args[2] == "--output"
		if !valid {
			return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "usage: stl link create-wss --stdin --output <private-file> [--json]", out, errOut)
		}
		return createWSS(in, args[3], out, errOut, jsonOut, options)
	case "preview-wss":
		if !((len(args) == 2 || len(args) == 3 && args[2] == "--json") && args[1] == "--stdin") {
			return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "usage: stl link preview-wss --stdin [--json]", out, errOut)
		}
		offer, raw, err := decodeWSSOffer(in)
		if err != nil {
			return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "invalid private WSS handoff", out, errOut)
		}
		defer offer.clear()
		response := struct {
			SchemaVersion int            `json:"schema_version"`
			LinkID        domain.LinkID  `json:"link_id"`
			Backend       domain.Backend `json:"backend"`
			Role          string         `json:"receiver_role"`
			Underlay      string         `json:"receiver_underlay"`
			PrivateIP     string         `json:"receiver_private_ip"`
			Confirm       string         `json:"confirmation_sha256"`
			Sensitive     bool           `json:"sensitive"`
		}{1, offer.Receiver.ID, offer.Receiver.Backend, offer.Receiver.WSS.Role,
			offer.Receiver.Underlay.Local.String(), offer.Receiver.Addresses.Local.String(),
			setupLinkConfirmation(string(raw)), true}
		if jsonOut {
			if json.NewEncoder(out).Encode(response) != nil {
				return 1
			}
			return 0
		}
		fmt.Fprintf(out, "SENSITIVE WSS receiver: Link %s, role %s, underlay %s, private IP %s\n",
			response.LinkID, response.Role, response.Underlay, response.PrivateIP)
		fmt.Fprintf(out, "After independently verifying this peer, import with --confirm %s\n", response.Confirm)
		return 0
	case "import-wss", "resume-wss":
		if !((len(args) == 4 || len(args) == 5 && args[4] == "--json") && args[1] == "--stdin" && args[2] == "--confirm" &&
			len(args[3]) == 64 && !strings.ContainsAny(args[3], " 	\n")) {
			return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "usage: stl link "+operation+" --stdin --confirm <sha256> [--json]", out, errOut)
		}
		offer, raw, err := decodeWSSOffer(in)
		if err != nil {
			return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "invalid WSS handoff", out, errOut)
		}
		defer offer.clear()
		if subtle.ConstantTimeCompare([]byte(args[3]), []byte(setupLinkConfirmation(string(raw)))) != 1 {
			return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "preview confirmation differs", out, errOut)
		}
		if options == nil {
			options, err = productionRuntimeOptions()
			if err != nil {
				return wssCommandError(operation, jsonOut, "", stlerr.CodeState, "runtime unavailable", out, errOut)
			}
		}
		engine, keys, err := wssEngine(options)
		if err != nil {
			return wssCommandError(operation, jsonOut, "", stlerr.CodeState, "engine/credential store unavailable", out, errOut)
		}
		ctx, cancel := wssCtx()
		defer cancel()
		var result app.Result
		if operation == "import-wss" {
			secret := []byte(offer.ReceiverWGKey)
			defer clear(secret)
			result, err = engine.EnsureWithWSSCredential(ctx, offer.Receiver, secret, keys,
				func() error { return wss.Stage(options.stateRoot, offer.Receiver, offer.ReceiverTLS) })
		} else {
			// Resume uses the EXACT sender-oriented Link from the original
			// handoff and previously staged credentials; never generate keys.
			result, err = engine.Ensure(ctx, offer.Sender)
		}
		if err != nil {
			return wssActivationFailure(operation, jsonOut, offer.Sender.ID, result, err,
				"activation not verified; preserve original private handoff and inspect owned State before retry", out, errOut)
		}
		return writeWSSResult(operation, result, jsonOut, out, errOut, "")
	default:
		return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "unsupported WSS command", out, errOut)
	}
}
func createWSS(in io.Reader, output string, out, errOut io.Writer, jsonOut bool, options *runtimeOptions) int {
	const operation = "create-wss"
	raw, err := io.ReadAll(io.LimitReader(in, maxDesiredLinkBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxDesiredLinkBytes || ensureUnambiguousJSON(raw) != nil {
		return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "invalid or ambiguous WSS creator input", out, errOut)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request wssCreateRequest
	if decoder.Decode(&request) != nil || request.SchemaVersion != 1 {
		return wssCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "unsupported WSS creator fields/schema", out, errOut)
	}
	id := request.LinkID
	if id == "" {
		choose := domain.NewLinkID
		if options != nil && options.createLinkID != nil {
			choose = options.createLinkID
		}
		id, err = choose()
		if err != nil {
			return wssCommandError(operation, jsonOut, "", stlerr.CodeState, "cannot allocate Link ID", out, errOut)
		}
	}
	if id.Validate() != nil || checkSensitiveHandoffDestination(output) != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeInvalid, "Link identity or private output path is unsafe", out, errOut)
	}
	local, localPub, err := wg.GenerateKeyPair()
	if err != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeState, "cannot generate local private WireGuard identity", out, errOut)
	}
	defer local.Zeroize()
	remote, remotePub, err := wg.GenerateKeyPair()
	if err != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeState, "cannot generate recipient WireGuard identity", out, errOut)
	}
	defer remote.Zeroize()
	sender, receiver, err := makeWSSPair(request, id, localPub, remotePub)
	if err != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeInvalid, "invalid WSS topology, ports or identities", out, errOut)
	}
	listener := sender
	if receiver.WSS.Role == "listen" {
		listener = receiver
	}
	path, err := composition.Build(listener, composition.CarrierForLink(listener))
	if err != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeInvalid, "invalid WSS certificate endpoint", out, errOut)
	}
	listenBundle, dialBundle, err := wss.GeneratePair(id, path.TLSName)
	if err != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeState, "WSS mTLS issuance failed", out, errOut)
	}
	defer listenBundle.Clear()
	defer dialBundle.Clear()
	own, other := listenBundle, dialBundle
	if sender.WSS.Role == "dial" {
		own, other = dialBundle, listenBundle
	}
	offer := wssOffer{SchemaVersion: 1, Sender: sender, Receiver: receiver,
		ReceiverWGKey: remote.SecretWireValue(), ReceiverTLS: other}
	defer func() { offer.ReceiverWGKey = "" }()
	if err := offer.validate(); err != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeInvalid, "generated WSS pair failed validation", out, errOut)
	}
	encoded, err := json.Marshal(offer)
	if err != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeState, "cannot encode sensitive receiver material", out, errOut)
	}
	defer clear(encoded)
	if options == nil {
		options, err = productionRuntimeOptions()
		if err != nil {
			return wssCommandError(operation, jsonOut, id, stlerr.CodeState, "WSS runtime unavailable", out, errOut)
		}
	}
	engine, keys, err := wssEngine(options)
	if err != nil {
		return wssCommandError(operation, jsonOut, id, stlerr.CodeState, "Engine initialization unavailable", out, errOut)
	}
	ctx, cancel := wssCtx()
	defer cancel()
	secret := []byte(local.SecretWireValue())
	defer clear(secret)
	result, err := engine.EnsureWithWSSCredential(ctx, sender, secret, keys, func() error {
		if err := wss.Stage(options.stateRoot, sender, own); err != nil {
			return err
		}
		return writeSensitiveHandoff(output, append(encoded, '\n'))
	})
	if err != nil {
		return wssActivationFailure(operation, jsonOut, id, result, err,
			"WSS activation unconfirmed; preserve any published handoff and protected credentials for exact resume", out, errOut)
	}
	return writeWSSResult(operation, result, jsonOut, out, errOut, output)
}
func writeWSSResult(operation string, r app.Result, jsonOut bool, out, errOut io.Writer, output string) int {
	response := struct {
		SchemaVersion int           `json:"schema_version"`
		Operation     string        `json:"operation"`
		LinkID        domain.LinkID `json:"link_id"`
		Changed       bool          `json:"changed"`
		Sensitive     bool          `json:"sensitive"`
		HandoffFile   string        `json:"handoff_file,omitempty"`
	}{1, operation, r.LinkID, r.Changed, true, output}
	if jsonOut {
		if json.NewEncoder(out).Encode(response) != nil {
			fmt.Fprintln(errOut, "WSS operation completed but result output failed; inspect committed State")
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "WSS Link %s locally ensured (carrier/helper + WireGuard). Real peer handshake and private IP traffic still require explicit bilateral verification.\n", r.LinkID)
	if output != "" {
		fmt.Fprintln(out, "SENSITIVE receiver handoff published to:", output)
	}
	return 0
}
