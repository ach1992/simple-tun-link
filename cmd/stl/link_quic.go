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
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// This CLI request is deliberately distinct from Native WG v1/v2 and from
// durable State schema. No supplied secret bytes are accepted in creator JSON.
type quicCreateRequestV1 struct {
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
	UDPPort              uint16                 `json:"udp_port"`
	LocalForwardUDPPort  uint16                 `json:"local_forward_udp_port,omitempty"`
	RemoteForwardUDPPort uint16                 `json:"remote_forward_udp_port,omitempty"`
	TLSServerName        string                 `json:"tls_server_name,omitempty"`
}

type quicCreateRequest struct {
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
	UDPPort              uint16                 `json:"udp_port"`
	LocalForwardUDPPort  uint16                 `json:"local_forward_udp_port,omitempty"`
	RemoteForwardUDPPort uint16                 `json:"remote_forward_udp_port,omitempty"`
	TLSServerName        string                 `json:"tls_server_name,omitempty"`
	Obfuscation          string                 `json:"obfuscation,omitempty"`
}

// Only explicit new-version public boundaries accept the spelling "plain".
// The internal empty representation preserves every existing Plain identity.
func normalizeQUICObfuscation(mode string) (string, error) {
	switch mode {
	case "", "plain":
		return "", nil
	case "salamander":
		return mode, nil
	default:
		return "", fmt.Errorf("QUIC obfuscation must be plain or salamander")
	}
}
func publicQUICObfuscation(mode string) string {
	if mode == "" {
		return "plain"
	}
	return mode
}
func (r quicCreateRequestV1) request() quicCreateRequest {
	return quicCreateRequest{SchemaVersion: r.SchemaVersion, LinkID: r.LinkID, DisplayName: r.DisplayName,
		Underlay: r.Underlay, Addresses: r.Addresses, ListenPort: r.ListenPort, PeerPort: r.PeerPort,
		LocalKeepalive: r.LocalKeepalive, PeerKeepalive: r.PeerKeepalive, Role: r.Role, UDPPort: r.UDPPort,
		LocalForwardUDPPort: r.LocalForwardUDPPort, RemoteForwardUDPPort: r.RemoteForwardUDPPort, TLSServerName: r.TLSServerName}
}
func decodeQUICCreateRequest(raw []byte) (quicCreateRequest, error) {
	var version struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &version); err != nil {
		return quicCreateRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request quicCreateRequest
	switch version.SchemaVersion {
	case 1:
		var old quicCreateRequestV1
		if err := decoder.Decode(&old); err != nil {
			return request, err
		}
		request = old.request()
	case 2:
		if err := decoder.Decode(&request); err != nil {
			return request, err
		}
		var err error
		request.Obfuscation, err = normalizeQUICObfuscation(request.Obfuscation)
		if err != nil {
			return quicCreateRequest{}, err
		}
	default:
		return request, fmt.Errorf("unsupported QUIC creator schema")
	}
	return request, nil
}

// These frozen Link DTOs close the old offer at its nested QUIC boundary.
// They intentionally do not decode a domain.Link directly.
type quicOfferLinkV1 struct {
	desiredLinkV4
	WSS struct {
		Role           string `json:"role"`
		TCPPort        uint16 `json:"tcp_port"`
		ForwardUDPPort uint16 `json:"forward_udp_port,omitempty"`
		TLSServerName  string `json:"tls_server_name,omitempty"`
	} `json:"wss,omitzero"`
}

func (l quicOfferLinkV1) link() domain.Link {
	link := l.desiredLinkV4.link()
	link.WSS = domain.WSSOptions{Role: l.WSS.Role, TCPPort: l.WSS.TCPPort, ForwardUDPPort: l.WSS.ForwardUDPPort, TLSServerName: l.WSS.TLSServerName}
	return link
}

type quicOfferV1 struct {
	SchemaVersion int               `json:"schema_version"`
	Sender        quicOfferLinkV1   `json:"sender"`
	Receiver      quicOfferLinkV1   `json:"receiver"`
	ReceiverWGKey string            `json:"receiver_wireguard_private_key"`
	ReceiverTLS   map[string][]byte `json:"receiver_tls"`
}
type quicOfferLinkV2 struct {
	quicOfferLinkV1
	QUIC desiredQUICOptionsV2 `json:"quic"`
}

func (l quicOfferLinkV2) link() (domain.Link, error) {
	link := l.quicOfferLinkV1.link()
	var err error
	link.QUIC, err = l.QUIC.options()
	return link, err
}

type quicOfferV2 struct {
	SchemaVersion int               `json:"schema_version"`
	Sender        quicOfferLinkV2   `json:"sender"`
	Receiver      quicOfferLinkV2   `json:"receiver"`
	ReceiverWGKey string            `json:"receiver_wireguard_private_key"`
	ReceiverTLS   map[string][]byte `json:"receiver_tls"`
}

// Private QUIC handoffs cannot be imported by old v1/v2/v3 pairing code.
// The recipient carries only its own key and TLS material. The sender
// retains neither recipient private key nor the trust authority signing key
// in generic state, logs, or normal CLI output.
type quicOffer struct {
	SchemaVersion int               `json:"schema_version"`
	Sender        domain.Link       `json:"sender"`
	Receiver      domain.Link       `json:"receiver"`
	ReceiverWGKey string            `json:"receiver_wireguard_private_key"`
	ReceiverTLS   map[string][]byte `json:"receiver_tls"`
}

func (o *quicOffer) clear() {
	o.ReceiverWGKey = ""
	for name, raw := range o.ReceiverTLS {
		clear(raw)
		delete(o.ReceiverTLS, name)
	}
	o.ReceiverTLS = nil
}
func (o quicOffer) validate() error {
	if (o.SchemaVersion != 1 && o.SchemaVersion != 2) ||
		(o.SchemaVersion == 1 && (o.Sender.QUIC.Obfuscation != "" || o.Receiver.QUIC.Obfuscation != "")) || o.Sender.Backend != domain.BackendWireGuardQUIC ||
		o.Receiver.Backend != domain.BackendWireGuardQUIC || o.Sender.Validate() != nil || o.Receiver.Validate() != nil ||
		o.Sender.MTU.Mode == "" || o.Receiver.MTU.Mode == "" {
		return fmt.Errorf("unsupported QUIC peer handoff")
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
	switch o.Sender.QUIC.Role {
	case "dial":
		if err := composition.ValidateQUICPeerPair(o.Sender, composition.CarrierForLink(o.Sender),
			o.Receiver, composition.CarrierForLink(o.Receiver)); err != nil {
			return err
		}
	case "listen":
		if err := composition.ValidateQUICPeerPair(o.Receiver, composition.CarrierForLink(o.Receiver),
			o.Sender, composition.CarrierForLink(o.Sender)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid QUIC sender role")
	}
	plan, err := quicPlanForLink(o.Receiver)
	if err != nil {
		return err
	}
	bundle, err := quic.ImportCredentialBundle(plan, o.ReceiverTLS)
	if err != nil {
		return fmt.Errorf("invalid receiver QUIC credentials")
	}
	bundle.Clear()
	return nil
}

// Convert the canonical public composition; this performs no host admission.
func quicPlanForLink(link domain.Link) (quic.Plan, error) {
	return quic.PlanFromLink(link)
}
func decodeQUICOffer(in io.Reader) (quicOffer, []byte, error) {
	if in == nil {
		return quicOffer{}, nil, fmt.Errorf("missing QUIC handoff")
	}
	raw, err := io.ReadAll(io.LimitReader(in, 64<<10+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		clear(raw)
		return quicOffer{}, nil, fmt.Errorf("oversized or unavailable QUIC handoff")
	}
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	if err = ensureUnambiguousJSON(raw); err != nil {
		clear(raw)
		return quicOffer{}, nil, fmt.Errorf("ambiguous QUIC handoff")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var version struct {
		SchemaVersion int `json:"schema_version"`
	}
	if json.Unmarshal(raw, &version) != nil {
		clear(raw)
		return quicOffer{}, nil, fmt.Errorf("invalid QUIC handoff schema")
	}
	var offer quicOffer
	switch version.SchemaVersion {
	case 1:
		var old quicOfferV1
		err = dec.Decode(&old)
		offer = quicOffer{SchemaVersion: old.SchemaVersion, Sender: old.Sender.link(), Receiver: old.Receiver.link(), ReceiverWGKey: old.ReceiverWGKey, ReceiverTLS: old.ReceiverTLS}
	case 2:
		var current quicOfferV2
		err = dec.Decode(&current)
		offer = quicOffer{SchemaVersion: current.SchemaVersion, ReceiverWGKey: current.ReceiverWGKey, ReceiverTLS: current.ReceiverTLS}
		if err == nil {
			offer.Sender, err = current.Sender.link()
		}
		if err == nil {
			offer.Receiver, err = current.Receiver.link()
		}
	default:
		err = fmt.Errorf("unsupported QUIC handoff schema")
	}
	if err != nil {
		offer.clear()
		clear(raw)
		return quicOffer{}, nil, fmt.Errorf("invalid QUIC handoff schema")
	}
	if err = offer.validate(); err != nil {
		offer.clear()
		clear(raw)
		return quicOffer{}, nil, fmt.Errorf("invalid or unsupported QUIC handoff")
	}
	return offer, raw, nil
}
func makeQUICPair(r quicCreateRequest, id domain.LinkID, localPub, peerPub string) (domain.Link, domain.Link, error) {
	if (r.SchemaVersion != 1 && r.SchemaVersion != 2) || (r.SchemaVersion == 1 && r.Obfuscation != "") || id.Validate() != nil {
		return domain.Link{}, domain.Link{}, fmt.Errorf("invalid QUIC request schema or identity")
	}
	mode, modeErr := normalizeQUICObfuscation(r.Obfuscation)
	if modeErr != nil {
		return domain.Link{}, domain.Link{}, modeErr
	}
	sender := domain.Link{
		ID: id, DisplayName: r.DisplayName,
		Underlay:  domain.Underlay{Local: r.Underlay.Local, Peer: r.Underlay.Peer},
		Addresses: domain.LinkAddresses{Local: r.Addresses.Local, Peer: r.Addresses.Peer},
		Backend:   domain.BackendWireGuardQUIC, Encapsulation: domain.EncapUDP,
		MTU: domain.MTUPolicy{Mode: domain.MTUAuto},
		WireGuard: domain.WireGuardOptions{
			LocalPublicKey: localPub, PeerPublicKey: peerPub,
			ListenPort: r.ListenPort, PeerPort: r.PeerPort,
			LocalKeepalive: r.LocalKeepalive, PeerKeepalive: r.PeerKeepalive,
		},
		QUIC: domain.QUICOptions{Role: r.Role, UDPPort: r.UDPPort, Obfuscation: mode,
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
		Backend:   domain.BackendWireGuardQUIC, Encapsulation: domain.EncapUDP,
		MTU: domain.MTUPolicy{Mode: domain.MTUAuto},
		WireGuard: domain.WireGuardOptions{
			LocalPublicKey: peerPub, PeerPublicKey: localPub,
			ListenPort: r.PeerPort, PeerPort: r.ListenPort,
			LocalKeepalive: r.PeerKeepalive, PeerKeepalive: r.LocalKeepalive,
		},
		QUIC: domain.QUICOptions{Role: peerRole, UDPPort: r.UDPPort, Obfuscation: mode,
			ForwardUDPPort: r.RemoteForwardUDPPort, TLSServerName: r.TLSServerName},
	}
	if r.Role == "dial" && r.RemoteForwardUDPPort != 0 {
		return domain.Link{}, domain.Link{}, fmt.Errorf("QUIC listener must not specify a remote forwarder")
	}
	if r.Role == "listen" && r.LocalForwardUDPPort != 0 {
		return domain.Link{}, domain.Link{}, fmt.Errorf("QUIC listener must not specify a local forwarder")
	}
	if r.Role == "dial" {
		if err := composition.ValidateQUICPeerPair(sender, composition.CarrierForLink(sender),
			receiver, composition.CarrierForLink(receiver)); err != nil {
			return domain.Link{}, domain.Link{}, err
		}
	} else {
		if err := composition.ValidateQUICPeerPair(receiver, composition.CarrierForLink(receiver),
			sender, composition.CarrierForLink(sender)); err != nil {
			return domain.Link{}, domain.Link{}, err
		}
	}
	return sender, receiver, nil
}
func quicCommandError(operation string, jsonOut bool, id domain.LinkID, code stlerr.Code, reason string, out, errOut io.Writer) int {
	var result *app.Result
	if id.Validate() == nil {
		result = &app.Result{LinkID: id}
	}
	return lifecycleFailure(out, errOut, jsonOut, code, "link_"+operation, result, operation+": "+reason)
}

// quicActivationFailure preserves the canonical Engine's typed category and
// lifecycle evidence. Only known categories and the authored detail reach the
// public surface; raw backend/process/credential errors remain private.
func quicActivationFailure(operation string, jsonOut bool, id domain.LinkID,
	result app.Result, cause error, detail string, out, errOut io.Writer) int {
	if result.LinkID.Validate() != nil {
		result.LinkID = id
	}
	code := stlerr.CodeOf(cause)
	switch code {
	case stlerr.CodeInvalid, stlerr.CodeUnsupported, stlerr.CodeConflict,
		stlerr.CodeInspect, stlerr.CodePlan, stlerr.CodeValidate, stlerr.CodeApply,
		stlerr.CodeVerify, stlerr.CodeState, stlerr.CodeRollback, stlerr.CodeInternal:
	default:
		code = stlerr.CodeInternal
	}
	return lifecycleFailureWithEvidence(out, errOut, jsonOut, code,
		"link_"+operation, &result, operation+": "+detail, stlerr.EvidenceOf(cause), cause)
}
func quicEngine(options *runtimeOptions) (*app.Engine, *wg.KeyStore, error) {
	if options == nil {
		return nil, nil, fmt.Errorf("QUIC runtime unavailable")
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
func quicCtx() (context.Context, context.CancelFunc) {
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	return ctx, func() { cancel(); stop() }
}
func linkQUICCommand(args []string, in io.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	jsonOut := slices.Contains(args, "--json")
	if len(args) == 0 {
		return quicCommandError("quic", jsonOut, "", stlerr.CodeInvalid, "missing operation", out, errOut)
	}
	operation := args[0]
	switch operation {
	case "create-quic":
		valid := (len(args) == 4 || (len(args) == 5 && args[4] == "--json")) &&
			args[1] == "--stdin" && args[2] == "--output"
		if !valid {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "usage: stl link create-quic --stdin --output <private-file> [--json]", out, errOut)
		}
		return createQUIC(in, args[3], out, errOut, jsonOut, options)
	case "preview-quic":
		if !((len(args) == 2 || len(args) == 3 && args[2] == "--json") && args[1] == "--stdin") {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "usage: stl link preview-quic --stdin [--json]", out, errOut)
		}
		offer, raw, err := decodeQUICOffer(in)
		if err != nil {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "invalid private QUIC handoff", out, errOut)
		}
		defer offer.clear()
		defer clear(raw)
		plan, err := quicPlanForLink(offer.Receiver)
		if err != nil {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "invalid canonical QUIC receiver plan", out, errOut)
		}
		response := struct {
			SchemaVersion      int            `json:"schema_version"`
			LinkID             domain.LinkID  `json:"link_id"`
			Backend            domain.Backend `json:"backend"`
			Role               string         `json:"receiver_role"`
			PeerRole           string         `json:"peer_role"`
			Underlay           string         `json:"receiver_underlay"`
			PeerUnderlay       string         `json:"receiver_peer_underlay"`
			PrivateIP          string         `json:"receiver_private_ip"`
			PeerPrivateIP      string         `json:"receiver_peer_private_ip"`
			UDPPort            uint16         `json:"quic_udp_port"`
			ForwardUDPPort     uint16         `json:"receiver_forward_udp_port"`
			PeerForwardUDPPort uint16         `json:"peer_forward_udp_port"`
			WGListenPort       uint16         `json:"receiver_wireguard_udp_port"`
			WGPeerPort         uint16         `json:"peer_wireguard_udp_port"`
			TLSListener        string         `json:"tls_listener_name"`
			Obfuscation        string         `json:"obfuscation"`
			Confirm            string         `json:"confirmation_sha256"`
			Sensitive          bool           `json:"sensitive"`
		}{SchemaVersion: 1, LinkID: offer.Receiver.ID, Backend: offer.Receiver.Backend,
			Role: offer.Receiver.QUIC.Role, PeerRole: offer.Sender.QUIC.Role,
			Underlay: offer.Receiver.Underlay.Local.String(), PeerUnderlay: offer.Receiver.Underlay.Peer.String(),
			PrivateIP: offer.Receiver.Addresses.Local.String(), PeerPrivateIP: offer.Receiver.Addresses.Peer.String(),
			UDPPort: offer.Receiver.QUIC.UDPPort, ForwardUDPPort: offer.Receiver.QUIC.ForwardUDPPort,
			PeerForwardUDPPort: offer.Sender.QUIC.ForwardUDPPort, WGListenPort: offer.Receiver.WireGuard.ListenPort,
			WGPeerPort: offer.Receiver.WireGuard.PeerPort, TLSListener: plan.TLSName, Obfuscation: publicQUICObfuscation(offer.Receiver.QUIC.Obfuscation),
			Confirm: setupLinkConfirmation(string(raw)), Sensitive: true}
		if jsonOut {
			if json.NewEncoder(out).Encode(response) != nil {
				return 1
			}
			return 0
		}
		fmt.Fprintf(out, "SENSITIVE QUIC receiver: Link %s\n", response.LinkID)
		fmt.Fprintf(out, "THIS server: physical %s, private %s, role %s\n", response.Underlay, response.PrivateIP, response.Role)
		fmt.Fprintf(out, "PEER server: physical %s, private %s, role %s\n", response.PeerUnderlay, response.PeerPrivateIP, response.PeerRole)
		fmt.Fprintf(out, "QUIC public UDP %d; effective TLS listener identity %s; obfuscation %s\n", response.UDPPort, response.TLSListener, response.Obfuscation)
		fmt.Fprintf(out, "Loopback forward UDP: this %d, peer %d (0 = no forwarder); guarded WG UDP: this %d, peer %d\n", response.ForwardUDPPort, response.PeerForwardUDPPort, response.WGListenPort, response.WGPeerPort)
		fmt.Fprintf(out, "After independently verifying both endpoints and the TLS identity, import with --confirm %s\n", response.Confirm)
		return 0
	case "import-quic", "resume-quic":
		if !((len(args) == 4 || len(args) == 5 && args[4] == "--json") && args[1] == "--stdin" && args[2] == "--confirm" &&
			len(args[3]) == 64 && !strings.ContainsAny(args[3], " 	\n")) {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "usage: stl link "+operation+" --stdin --confirm <sha256> [--json]", out, errOut)
		}
		offer, raw, err := decodeQUICOffer(in)
		if err != nil {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "invalid QUIC handoff", out, errOut)
		}
		defer offer.clear()
		defer clear(raw)
		if subtle.ConstantTimeCompare([]byte(args[3]), []byte(setupLinkConfirmation(string(raw)))) != 1 {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "preview confirmation differs", out, errOut)
		}
		if options == nil {
			options, err = productionRuntimeOptions()
			if err != nil {
				return quicCommandError(operation, jsonOut, "", stlerr.CodeState, "runtime unavailable", out, errOut)
			}
		}
		engine, keys, err := quicEngine(options)
		if err != nil {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeState, "engine/credential store unavailable", out, errOut)
		}
		ctx, cancel := quicCtx()
		defer cancel()
		var result app.Result
		if operation == "import-quic" {
			secret := []byte(offer.ReceiverWGKey)
			defer clear(secret)
			plan, planErr := quicPlanForLink(offer.Receiver)
			if planErr != nil {
				return quicCommandError(operation, jsonOut, offer.Receiver.ID, stlerr.CodeInvalid, "invalid receiver topology", out, errOut)
			}
			bundle, bundleErr := quic.ImportCredentialBundle(plan, offer.ReceiverTLS)
			if bundleErr != nil {
				return quicCommandError(operation, jsonOut, offer.Receiver.ID, stlerr.CodeInvalid, "invalid receiver protected material", out, errOut)
			}
			defer bundle.Clear()
			result, err = engine.EnsureWithQUICCredential(ctx, offer.Receiver, secret, keys, bundle, nil)
		} else {
			// Resume uses the EXACT sender-oriented Link from the original
			// handoff and previously staged credentials; never generate keys.
			result, err = engine.Ensure(ctx, offer.Sender)
		}
		if err != nil {
			return quicActivationFailure(operation, jsonOut, offer.Sender.ID, result, err,
				"activation not verified; preserve original private handoff and inspect owned State before retry", out, errOut)
		}
		return writeQUICResult(operation, result, jsonOut, out, errOut, "")
	default:
		return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "unsupported QUIC command", out, errOut)
	}
}
func createQUIC(in io.Reader, output string, out, errOut io.Writer, jsonOut bool, options *runtimeOptions) int {
	const operation = "create-quic"
	raw, err := io.ReadAll(io.LimitReader(in, maxDesiredLinkBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxDesiredLinkBytes || ensureUnambiguousJSON(raw) != nil {
		return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "invalid or ambiguous QUIC creator input", out, errOut)
	}
	request, err := decodeQUICCreateRequest(raw)
	if err != nil {
		return quicCommandError(operation, jsonOut, "", stlerr.CodeInvalid, "unsupported QUIC creator fields/schema", out, errOut)
	}
	id := request.LinkID
	if id == "" {
		choose := domain.NewLinkID
		if options != nil && options.createLinkID != nil {
			choose = options.createLinkID
		}
		id, err = choose()
		if err != nil {
			return quicCommandError(operation, jsonOut, "", stlerr.CodeState, "cannot allocate Link ID", out, errOut)
		}
	}
	if id.Validate() != nil || checkSensitiveHandoffDestination(output) != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeInvalid, "Link identity or private output path is unsafe", out, errOut)
	}
	local, localPub, err := wg.GenerateKeyPair()
	if err != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeState, "cannot generate local private WireGuard identity", out, errOut)
	}
	defer local.Zeroize()
	remote, remotePub, err := wg.GenerateKeyPair()
	if err != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeState, "cannot generate recipient WireGuard identity", out, errOut)
	}
	defer remote.Zeroize()
	sender, receiver, err := makeQUICPair(request, id, localPub, remotePub)
	if err != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeInvalid, "invalid QUIC topology, ports or identities", out, errOut)
	}
	listener := sender
	if receiver.QUIC.Role == "listen" {
		listener = receiver
	}
	path, err := composition.Build(listener, composition.CarrierForLink(listener))
	if err != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeInvalid, "invalid QUIC certificate endpoint", out, errOut)
	}
	listenBundle, dialBundle, err := quic.GeneratePairWithObfuscation(id, path.TLSName, sender.QUIC.Obfuscation)
	if err != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeState, "QUIC mTLS issuance failed", out, errOut)
	}
	defer listenBundle.Clear()
	defer dialBundle.Clear()
	own, other := listenBundle, dialBundle
	if sender.QUIC.Role == "dial" {
		own, other = dialBundle, listenBundle
	}
	offer := quicOffer{SchemaVersion: request.SchemaVersion, Sender: sender, Receiver: receiver,
		ReceiverWGKey: remote.SecretWireValue(), ReceiverTLS: other.ProtectedFiles()}
	defer offer.clear()
	if err := offer.validate(); err != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeInvalid, "generated QUIC pair failed validation", out, errOut)
	}
	encoded, err := json.Marshal(offer)
	if err != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeState, "cannot encode sensitive receiver material", out, errOut)
	}
	defer clear(encoded)
	if options == nil {
		options, err = productionRuntimeOptions()
		if err != nil {
			return quicCommandError(operation, jsonOut, id, stlerr.CodeState, "QUIC runtime unavailable", out, errOut)
		}
	}
	engine, keys, err := quicEngine(options)
	if err != nil {
		return quicCommandError(operation, jsonOut, id, stlerr.CodeState, "Engine initialization unavailable", out, errOut)
	}
	ctx, cancel := quicCtx()
	defer cancel()
	secret := []byte(local.SecretWireValue())
	defer clear(secret)
	result, err := engine.EnsureWithQUICCredential(ctx, sender, secret, keys, own, func() error {
		publish := writeSensitiveHandoff
		if options.writeHandoff != nil {
			publish = options.writeHandoff
		}
		return publish(output, append(encoded, '\n'))
	})
	if err != nil {
		return quicActivationFailure(operation, jsonOut, id, result, err,
			"QUIC activation unconfirmed; preserve the original handoff, protected material and journal; inspect State before recovery", out, errOut)
	}
	return writeQUICResult(operation, result, jsonOut, out, errOut, output)
}
func writeQUICResult(operation string, r app.Result, jsonOut bool, out, errOut io.Writer, output string) int {
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
			fmt.Fprintln(errOut, "QUIC operation completed but result output failed; inspect committed State")
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "QUIC Link %s locally ensured (carrier/helper + WireGuard). Real peer handshake and private IP traffic still require explicit bilateral verification.\n", r.LinkID)
	if output != "" {
		fmt.Fprintln(out, "SENSITIVE receiver handoff published to:", output)
	}
	return 0
}
