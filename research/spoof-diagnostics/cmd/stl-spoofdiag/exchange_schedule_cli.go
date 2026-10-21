package main

// Preparation-only Case commands; no transition here invokes Field networking.
import (
	"errors"
	"flag"
	"fmt"
	"time"
)

func exchangeCaseCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: exchange case create|inspect|sign|verify (offline only)")
	}
	op := args[0]
	f := flag.NewFlagSet("exchange case "+op, flag.ContinueOnError)
	id := f.String("case-id", "", "shared 32-hex Case ID")
	base := f.String("base", exchangeDefaultBase, "private exchange root for automatic discovery")
	ab := f.String("ab-dir", "", "private immutable A_TO_B Campaign")
	ba := f.String("ba-dir", "", "private immutable B_TO_A Campaign")
	aCert := f.String("a-cert", "", "provisioned public A certificate")
	bCert := f.String("b-cert", "", "provisioned public B certificate")
	file := f.String("file", "", "Case definition JSON")
	sigA := f.String("sig-a", "", "separate A-signed Case JSON")
	sigB := f.String("sig-b", "", "separate B-signed Case JSON")
	cert := f.String("cert", "", "own node public certificate")
	key := f.String("key", "", "own node private signing key (never exported)")
	ca := f.String("ca", "", "independently trusted CA public certificate")
	node := f.String("node", "", "local signer A or B")
	out := f.String("out", "", "new output .json (never overwrite)")
	ack := f.String("ack-case", "", "must be SIGN_CASE after reviewing immutable campaigns")
	days := f.Int("valid-days", 7, "Case validity 1..7 days, not runtime listener TTL")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	switch op {
	case "create":
		if *id == "" || *ab == "" || *ba == "" || *aCert == "" || *bCert == "" || *out == "" {
			return errors.New("case create requires --case-id --ab-dir --ba-dir --a-cert --b-cert --out")
		}
		c, err := scheduledCaseCreate(*id, *ab, *ba, *aCert, *bCert, *out, *days)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "UNSIGNED_CASE_DEFINITION_NO_NETWORK_NOT_AUTHORIZED",
			"case_id": c.CaseID, "case_sha256": scheduledCaseDigest(c),
			"expires_unix": c.ExpiresUnix, "file": *out,
			"next": "Operator copies exactly this JSON to both nodes. Both must independently review and sign."})
	case "inspect":
		if *file == "" {
			return errors.New("case inspect requires --file")
		}
		c, err := scheduledReadCase(*file)
		if err != nil {
			return err
		}
		if err := validateScheduledCase(c, time.Now(), false); err != nil {
			return err
		}
		return pretty(map[string]any{"status": "CASE_STRUCTURE_ONLY_UNVERIFIED_NOT_APPROVED",
			"case_id": c.CaseID, "case_sha256": scheduledCaseDigest(c),
			"campaigns": c.Campaigns, "expires_unix": c.ExpiresUnix,
			"a_cert_sha256": c.ACertificateSHA256, "b_cert_sha256": c.BCertificateSHA256})
	case "sign":
		if *file == "" || *node == "" || *cert == "" || *key == "" || *ca == "" || *out == "" || *ack != "SIGN_CASE" {
			return errors.New("case sign requires --file --node --cert --key --ca --out --ack-case SIGN_CASE")
		}
		if err := scheduledCaseSign(*file, *node, *cert, *key, *ca, *out); err != nil {
			return err
		}
		return pretty(map[string]any{"status": "INDEPENDENT_NODE_CASE_SIGNATURE_ONLY_NO_NETWORK",
			"node": *node, "signed_case": *out, "next": "Transfer public signed Case JSON, never this node's private key."})
	case "verify":
		if *ca == "" {
			return errors.New("case verify requires a trusted --ca public certificate")
		}
		var c scheduledCase
		var err error
		if *file == "" && *sigA == "" && *sigB == "" && *id != "" {
			c, err = exchangeValidateStagedCase(*base, *id, *ca)
		} else {
			if *file == "" || *sigA == "" || *sigB == "" {
				return errors.New("case verify needs --file --sig-a --sig-b --ca OR --case-id --base --ca")
			}
			c, err = verifyScheduledCase(*file, *sigA, *sigB, *ca, time.Now(), true)
		}
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "CASE_DUAL_SIGNATURES_VERIFIED_PREPARATION_ONLY",
			"case_id": c.CaseID, "case_sha256": scheduledCaseDigest(c),
			"expires_unix":             c.ExpiresUnix,
			"activation":               "NOT_IMPLEMENTED_IN_THIS_OFFLINE_PREPARATION_CANDIDATE",
			"peer_currently_listening": "UNKNOWN_NO_CONTROL_CHANNEL", "network_calls": "NONE"})
	default:
		return fmt.Errorf("unknown offline Case operation %q", op)
	}
}
