package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// A read-only prerequisite assessment. It never opens a socket, changes a
// route, asks the provider for a probe, or interprets a successful check as
// proof of reachability. Runtime errors may still happen after the check.
func fieldPreflight(o fieldOptions, role string) (map[string]any, error) {
	result, err := inspectFieldPreflight(o, role)
	if err != nil && result != nil {
		result["status"] = "BLOCKED"
		result["reason"] = err.Error()
	}
	return result, err
}

func inspectFieldPreflight(o fieldOptions, role string) (map[string]any, error) {
	if role != "sender" && role != "receiver" {
		return nil, errors.New("role must be sender or receiver")
	}
	c, g, _, err := readPreparedField(o)
	if err != nil {
		return nil, err
	}
	ch := c.Challenge
	certUsage := x509.ExtKeyUsageClientAuth
	node := ch.Sender
	if role == "receiver" {
		certUsage, node = x509.ExtKeyUsageServerAuth, ch.Receiver
	}
	cert, _, err := checkLocalFieldCredential(o.Cert, o.Key, o.CA, node, certUsage)
	if err != nil {
		return nil, err
	}
	local, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	issued, err := parseFieldCertificate(c.SenderCertificatePEM)
	if err != nil {
		return nil, err
	}
	if role == "sender" && !local.Equal(issued) {
		return nil, errors.New("local sender identity differs from signed challenge")
	}
	if role == "receiver" {
		approved, err := parseFieldCertificate(g.ReceiverCertificatePEM)
		if err != nil || !local.Equal(approved) {
			return nil, errors.New("local receiver identity differs from signed grant")
		}
	}
	var inv CandidateFile
	if role == "receiver" {
		inv, err = receiverSourceSelection(ch, o.File)
	} else {
		inv, err = readCandidates(o.File)
	}
	if err != nil {
		return nil, err
	}
	if err := validateFieldSamples(ch.Samples, inv, ch.Sender, ch.Receiver); err != nil {
		return nil, err
	}
	required := automaticFieldWindowSeconds(len(ch.Samples))
	remaining := time.Until(time.Unix(ch.ExpiresUnix, 0))
	result := map[string]any{
		"run_id": ch.RunID, "role": role, "transport": ch.Environment,
		"status":          "STATIC_CHECKS_ONLY_FIELD_NETWORK_NOT_TESTED",
		"planned_samples": len(ch.Samples), "receiver_recommended_window_seconds": required,
		"challenge_seconds_remaining": int(remaining.Seconds()),
		"port_availability":           "NOT_TESTED_NO_SOCKET_OPENED",
		"provider_source_acceptance":  "NOT_TESTED",
		"peer_reachability":           "NOT_TESTED",
	}
	if remaining < time.Duration(required+5)*time.Second {
		return result, errors.New("signed challenge has insufficient remaining time for planned receiver window; create a fresh run")
	}
	if role == "receiver" {
		bind := g.Grant.BindIP
		if bind == "" {
			bind = ch.DestinationIP
		}
		if o.BindIP != bind || (bind != ch.DestinationIP && !o.ForwardedDestination) {
			return result, errors.New("receiver bind/forwarded consent differs from signed grant")
		}
		if err := localAssignedIPv4(bind); err != nil {
			return result, err
		}
		result["receiver_bind_ip"] = bind
		if bind != ch.DestinationIP {
			result["nat_forwarding"] = "OPERATOR_CONFIGURED_NOT_VERIFIED"
		}
	} else if ch.Environment == "field_udp_bound" {
		for _, sample := range ch.Samples {
			if err := localAssignedIPv4(sample.Candidate.IP); err != nil {
				return result, err
			}
		}
		result["sender_source_binding"] = "LOCAL_INTERFACE_ADDRESSES_CHECKED"
	} else {
		if !o.ProviderAuthorized {
			return result, errors.New("raw transport needs separately verified Owner/provider authorization, not just a software check")
		}
		if strings.TrimSpace(o.Interface) == "" {
			return result, errors.New("raw transport requires an explicit interface")
		}
		device, err := net.InterfaceByName(o.Interface)
		if err != nil {
			return result, err
		}
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
			return result, errors.New("raw interface is down or loopback")
		}
		maxPayload := 0
		for _, sample := range ch.Samples {
			if sample.Size > maxPayload {
				maxPayload = sample.Size
			}
		}
		if device.MTU > 0 && device.MTU < maxPayload+28 {
			return result, fmt.Errorf("interface MTU %d is below IPv4/UDP sample size %d", device.MTU, maxPayload+28)
		}
		if !effectiveCapNetRaw() {
			return result, errors.New("effective CAP_NET_RAW is unavailable")
		}
		result["device"] = device.Name
		result["device_mtu"] = device.MTU
		result["cap_net_raw"] = "EFFECTIVE"
		result["route_policy_and_provider"] = "NOT_VERIFIED"
	}
	return result, nil
}

func effectiveCapNetRaw() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return false
		}
		value, err := strconv.ParseUint(fields[1], 16, 64)
		return err == nil && value&(uint64(1)<<13) != 0
	}
	return false
}
