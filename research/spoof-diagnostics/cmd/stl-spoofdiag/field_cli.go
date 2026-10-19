package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"
)

func fieldCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: field identity|challenge|grant|accept|check|listen|send|verify")
	}
	op := args[0]
	if op == "identity" {
		f := flag.NewFlagSet("field identity", flag.ContinueOnError)
		dir := f.String("dir", "", "new private offline provisioning directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" {
			return errors.New("field identity requires --dir")
		}
		if err := createFieldIdentity(*dir); err != nil {
			return err
		}
		return pretty(map[string]any{"identity_dir": *dir, "status": "CREATED_OFFLINE_NOT_DEPLOYED",
			"caution": "contains BOTH node keys AND ca.key: distribute only each node's private key; never copy the CA private key onto field hosts"})
	}
	f := flag.NewFlagSet("field "+op, flag.ContinueOnError)
	if op == "verify" {
		challenge := f.String("challenge", "", "sender signed field challenge JSON")
		grant := f.String("grant", "", "receiver signed consent grant JSON")
		receipt := f.String("receipt", "", "receiver signed packet observation JSON")
		senderReport := f.String("sender-report", "", "optional signed sender syscall evidence JSON")
		ca := f.String("ca", "", "trusted CA certificate PEM")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *challenge == "" || *grant == "" || *receipt == "" || *ca == "" {
			return errors.New("field verify requires --challenge --grant --receipt --ca")
		}
		result, err := verifyFieldPair(*challenge, *grant, *receipt, *ca)
		if err != nil {
			return err
		}
		if *senderReport != "" {
			challenge, err := readSignedFieldChallenge(*challenge)
			if err != nil {
				return err
			}
			submissions, err := verifySenderEvidence(*senderReport, challenge.Challenge, *ca)
			if err != nil {
				return err
			}
			result["sender_evidence"] = submissions
		}
		return pretty(result)
	}
	o := fieldOptions{}
	f.StringVar(&o.File, "file", "", "local exact source allowlist field_candidates JSON/CSV")
	f.StringVar(&o.Cert, "cert", "", "local node certificate PEM")
	f.StringVar(&o.Key, "key", "", "local node private key PEM")
	f.StringVar(&o.CA, "ca", "", "trusted CA public PEM")
	f.StringVar(&o.Sender, "sender", "A", "sender node role A or B")
	f.StringVar(&o.Receiver, "receiver", "B", "receiver node role B or A")
	f.StringVar(&o.DestinationIP, "destination-ip", "", "explicit receiver IPv4 (no DNS)")
	f.StringVar(&o.BindIP, "bind-ip", "", "receiver's locally assigned IPv4; must equal destination")
	f.IntVar(&o.DataPort, "data-port", 24572, "receiver UDP port 1024..65535")
	f.IntVar(&o.PacketSize, "packet-size", 192, "signed UDP payload size 128..1200")
	f.IntVar(&o.SamplesPerSource, "samples-per-source", 5, "independent signed diagnostic samples per selected IP (1..10)")
	f.IntVar(&o.TTLSeconds, "ttl-seconds", 600, "signed challenge validity 60..900 seconds")
	f.IntVar(&o.WindowSeconds, "window-seconds", 0, "receiver listen window 0=auto from signed sample count (max 120); or 1..120")
	f.StringVar(&o.Epoch, "epoch", "operator-declared", "operator-defined policy epoch")
	f.StringVar(&o.Transport, "transport", "field_udp_bound", "field_udp_bound or field_raw_ipv4")
	f.StringVar(&o.Output, "out", "", "write a new JSON artifact without overwriting")
	f.StringVar(&o.Challenge, "challenge", "", "existing sender signed challenge JSON")
	f.StringVar(&o.Grant, "grant", "", "existing receiver signed grant JSON")
	f.StringVar(&o.ReadyFile, "ready", "", "optional receiver-signed live-listener readiness JSON for sender")
	f.StringVar(&o.ReadyOutput, "ready-out", "", "optional receiver-signed readiness JSON emitted only after bind")
	role := f.String("role", "", "for field check: sender or receiver")
	grantOut := f.String("grant-out", "", "field accept: new B-signed grant JSON file")
	f.StringVar(&o.StateDir, "state-dir", "", "private 0700 consumed-run ledger")
	f.StringVar(&o.Interface, "interface", "", "exact source egress NIC for raw IPv4")
	f.BoolVar(&o.ForwardedDestination, "allow-forwarded-destination", false,
		"receiver explicitly accepts local DNAT bind differing from advertised signed destination; does not prove NAT works")
	f.BoolVar(&o.ProviderAuthorized, "provider-authorized", false,
		"operator acknowledgement ONLY; independent owner and provider permission still required for raw source tests")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if o.Cert == "" || o.Key == "" || o.CA == "" {
		return errors.New("field operation requires --cert --key --ca")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch op {
	case "challenge":
		if o.File == "" || o.DestinationIP == "" || o.Output == "" {
			return errors.New("field challenge requires --file --destination-ip --out")
		}
		signed, err := newFieldChallenge(o)
		if err != nil {
			return err
		}
		if err := saveNewJSON(o.Output, signed); err != nil {
			return err
		}
		return pretty(map[string]any{"run_id": signed.Challenge.RunID, "challenge": o.Output,
			"samples": len(signed.Challenge.Samples), "samples_per_source": signed.Challenge.SamplesPerSource,
			"selected_source_count": len(signed.Challenge.Samples) / signed.Challenge.SamplesPerSource,
			"selected_sources":      signed.Challenge.Samples,
			"transport":             signed.Challenge.Environment, "status": "SIGNED_PLAN_ONLY_NETWORK_NOT_RUN"})
	case "grant":
		if o.Challenge == "" || o.File == "" || o.Output == "" {
			return errors.New("field grant requires --challenge --file --out")
		}
		signed, err := newFieldGrant(o)
		if err != nil {
			return err
		}
		if err := saveNewJSON(o.Output, signed); err != nil {
			return err
		}
		return pretty(map[string]any{"run_id": signed.Grant.RunID,
			"grant": o.Output, "status": "RECEIVER_SIGNED_APPROVAL_NOT_PROVIDER_AUTHORIZATION"})
	case "check":
		if o.Challenge == "" || o.Grant == "" || o.File == "" || o.DestinationIP == "" {
			return errors.New("field check requires --challenge --grant --file --destination-ip --role")
		}
		result, err := fieldPreflight(o, *role)
		if result != nil {
			if printErr := pretty(result); printErr != nil {
				return printErr
			}
		}
		return err
	case "accept":
		if o.Challenge == "" || o.File == "" || o.Output == "" || o.ReadyOutput == "" || o.StateDir == "" || *grantOut == "" {
			return errors.New("field accept requires --challenge --file --grant-out --ready-out --out --state-dir (plus B credentials)")
		}
		ch, err := readSignedFieldChallenge(o.Challenge)
		if err != nil {
			return err
		}
		o.Sender, o.Receiver = ch.Challenge.Sender, ch.Challenge.Receiver
		o.DestinationIP, o.DataPort = ch.Challenge.DestinationIP, ch.Challenge.DataPort
		if o.BindIP == "" {
			o.BindIP = o.DestinationIP
		}
		o.Grant = *grantOut
		grant, err := newFieldGrant(o)
		if err != nil {
			return err
		}
		if err := saveNewJSON(o.Grant, grant); err != nil {
			return err
		}
		if err := pretty(map[string]any{"status": "SIGNED_GRANT_READY_TRANSFER_TO_SENDER",
			"grant": o.Grant, "run_id": grant.Grant.RunID,
			"note": "receiver will now start finite listening; signed grant is not physical readiness proof"}); err != nil {
			return err
		}
		return runFieldListener(ctx, o)
	case "listen":
		if o.Challenge == "" || o.Grant == "" || o.File == "" || o.BindIP == "" || o.DestinationIP == "" ||
			o.Output == "" || o.StateDir == "" {
			return errors.New("field listen requires --challenge --grant --file --bind-ip --destination-ip --out --state-dir")
		}
		return runFieldListener(ctx, o)
	case "send":
		if o.Challenge == "" || o.Grant == "" || o.File == "" || o.DestinationIP == "" || o.Output == "" {
			return errors.New("field send requires --challenge --grant --file --destination-ip --out (signed sender evidence)")
		}
		result, err := fieldSend(ctx, o)
		if result != nil {
			if printErr := pretty(result); printErr != nil {
				return printErr
			}
		}
		return err
	default:
		return errors.New("unknown field operation; expected identity|challenge|grant|accept|check|listen|send|verify")
	}
}

func runFieldListener(ctx context.Context, o fieldOptions) error {
	ready := make(chan map[string]any, 1)
	done := make(chan error, 1)
	go func() { done <- fieldListen(ctx, o, ready) }()
	select {
	case status := <-ready:
		if err := pretty(status); err != nil {
			return err
		}
		if err := <-done; err != nil {
			return err
		}
		return pretty(map[string]any{"status": "SIGNED_FIELD_RECEIPT_WRITTEN",
			"receipt": o.Output, "independent_verification": "field verify --challenge ... --grant ... --receipt ... --ca ..."})
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
