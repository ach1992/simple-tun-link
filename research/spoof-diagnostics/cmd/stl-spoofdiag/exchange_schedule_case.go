package main

// Scheduled Case declarations have a separate v2 signed trust contract.
// No short-lived Field run is created when a Case is created or signed.
import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"time"
)

const scheduledPreparationVersion = "sdx-scheduled-v2"
const scheduledCaseFormat = "sdx-case-v2"

type scheduledCampaignRef struct {
	Direction      string `json:"direction"`
	CampaignID     string `json:"campaign_id"`
	ManifestSHA256 string `json:"campaign_sha256"`
}

type scheduledCase struct {
	Format             string                 `json:"format"`
	CaseID             string                 `json:"case_id"`
	CreatedUTC         string                 `json:"created_utc"`
	ExpiresUnix        int64                  `json:"expires_unix"`
	ACertificateSHA256 string                 `json:"a_certificate_sha256"`
	BCertificateSHA256 string                 `json:"b_certificate_sha256"`
	Campaigns          []scheduledCampaignRef `json:"campaigns"`
}

type signedScheduledCase struct {
	Case           scheduledCase `json:"case"`
	Node           string        `json:"node"`
	CertificatePEM string        `json:"certificate_pem"`
	SignatureHex   string        `json:"signature_hex"`
}

func scheduledCaseDigest(c scheduledCase) string {
	b, _ := json.Marshal(c)
	return exchangeSHA(b)
}

func scheduledLocalLeaf(certPath string) (*x509.Certificate, error) {
	raw, err := readSmallRegular(certPath, 16384)
	if err != nil {
		return nil, err
	}
	return parseFieldCertificate(string(raw))
}

func scheduledCaseCreate(caseID, abDir, baDir, aCert, bCert, out string, validDays int) (scheduledCase, error) {
	var zero scheduledCase
	if !exchangeIDPattern.MatchString(caseID) || validDays < 1 || validDays > 7 {
		return zero, errors.New("Case ID must be 32 lowercase hex and validity 1..7 days")
	}
	mAB, err := readCampaign(abDir)
	if err != nil {
		return zero, err
	}
	mBA, err := readCampaign(baDir)
	if err != nil {
		return zero, err
	}
	if mAB.Direction != "A_TO_B" || mBA.Direction != "B_TO_A" {
		return zero, errors.New("Case requires two distinct A_TO_B / B_TO_A campaigns")
	}
	a, err := scheduledLocalLeaf(aCert)
	if err != nil {
		return zero, err
	}
	b, err := scheduledLocalLeaf(bCert)
	if err != nil {
		return zero, err
	}
	if len(a.DNSNames) != 1 || a.DNSNames[0] != roleName("A") ||
		len(b.DNSNames) != 1 || b.DNSNames[0] != roleName("B") || a.Equal(b) {
		return zero, errors.New("Case signer identities must be distinct A/B node certificates")
	}
	sha := func(dir string) (string, error) {
		contents, err := readSmallRegular(filepath.Join(dir, "campaign.json"), exchangeMaxFile)
		if err != nil {
			return "", err
		}
		return exchangeSHA(contents), nil
	}
	abHash, err := sha(abDir)
	if err != nil {
		return zero, err
	}
	baHash, err := sha(baDir)
	if err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	c := scheduledCase{Format: scheduledCaseFormat, CaseID: caseID, CreatedUTC: now.Format(time.RFC3339Nano),
		ExpiresUnix:        now.Add(time.Duration(validDays) * 24 * time.Hour).Unix(),
		ACertificateSHA256: exchangeSHA(a.Raw), BCertificateSHA256: exchangeSHA(b.Raw),
		Campaigns: []scheduledCampaignRef{
			{Direction: "A_TO_B", CampaignID: mAB.CampaignID, ManifestSHA256: abHash},
			{Direction: "B_TO_A", CampaignID: mBA.CampaignID, ManifestSHA256: baHash},
		},
	}
	if err := validateScheduledCase(c, now, true); err != nil {
		return zero, err
	}
	if err := saveNewJSON(out, c); err != nil {
		return zero, err
	}
	return c, nil
}

func validateScheduledCase(c scheduledCase, now time.Time, live bool) error {
	if c.Format != scheduledCaseFormat || !exchangeIDPattern.MatchString(c.CaseID) ||
		!exchangeDigestPattern.MatchString(c.ACertificateSHA256) ||
		!exchangeDigestPattern.MatchString(c.BCertificateSHA256) ||
		c.ACertificateSHA256 == c.BCertificateSHA256 || len(c.Campaigns) != 2 {
		return errors.New("invalid scheduled Case format/identities")
	}
	created, err := time.Parse(time.RFC3339Nano, c.CreatedUTC)
	if err != nil || created.After(now.Add(60*time.Second)) || c.ExpiresUnix <= created.Unix()+60 ||
		c.ExpiresUnix > created.Add(7*24*time.Hour).Unix() ||
		(live && c.ExpiresUnix <= now.Unix()) {
		return errors.New("Case creation, expiry or validity horizon invalid")
	}
	for n, dir := range []string{"A_TO_B", "B_TO_A"} {
		item := c.Campaigns[n]
		if item.Direction != dir || !exchangeIDPattern.MatchString(item.CampaignID) ||
			!exchangeDigestPattern.MatchString(item.ManifestSHA256) {
			return errors.New("Case must bind immutable, exactly ordered directional campaigns")
		}
	}
	if c.Campaigns[0].CampaignID == c.Campaigns[1].CampaignID ||
		c.Campaigns[0].ManifestSHA256 == c.Campaigns[1].ManifestSHA256 {
		return errors.New("different Case directions may not alias the same campaign")
	}
	return nil
}

func scheduledReadCase(file string) (scheduledCase, error) {
	var c scheduledCase
	data, err := readSmallRegular(file, fieldMaxControl)
	if err != nil {
		return c, err
	}
	if err := strictJSON(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

func scheduledCaseSign(file, node, certPath, keyPath, caPath, out string) error {
	if node != "A" && node != "B" {
		return errors.New("Case signer must be A or B")
	}
	c, err := scheduledReadCase(file)
	if err != nil {
		return err
	}
	if err := validateScheduledCase(c, time.Now(), true); err != nil {
		return err
	}
	cred, _, err := checkLocalFieldCredential(certPath, keyPath, caPath, node, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cred.Certificate[0])
	if err != nil {
		return err
	}
	want := c.ACertificateSHA256
	if node == "B" {
		want = c.BCertificateSHA256
	}
	if exchangeSHA(leaf.Raw) != want {
		return errors.New("Case was defined for a different node signing certificate")
	}
	pem, sig, err := signatureFromCredential(c, cred)
	if err != nil {
		return err
	}
	return saveNewJSON(out, signedScheduledCase{Case: c, Node: node, CertificatePEM: pem, SignatureHex: sig})
}

func verifyScheduledCase(casePath, sigAPath, sigBPath, caPath string, now time.Time, live bool) (scheduledCase, error) {
	var zero scheduledCase
	if casePath == "" || sigAPath == "" || sigBPath == "" || caPath == "" {
		return zero, errors.New("scheduled activation requires Case and BOTH distinct node signatures plus independently provisioned CA")
	}
	c, err := scheduledReadCase(casePath)
	if err != nil {
		return zero, err
	}
	if err := validateScheduledCase(c, now, live); err != nil {
		return zero, err
	}
	roots, err := certificateRoots(caPath)
	if err != nil {
		return zero, err
	}
	for _, item := range []struct {
		node, path string
		sha        string
	}{
		{"A", sigAPath, c.ACertificateSHA256}, {"B", sigBPath, c.BCertificateSHA256},
	} {
		data, err := readSmallRegular(item.path, fieldMaxControl)
		if err != nil {
			return zero, err
		}
		var signed signedScheduledCase
		if err := strictJSON(data, &signed); err != nil {
			return zero, err
		}
		if signed.Node != item.node || !reflect.DeepEqual(signed.Case, c) {
			return zero, fmt.Errorf("independent %s Case statement does not match shared Case", item.node)
		}
		// Evaluate the signer at its actual declared Case signing window;
		// current host trust/expiry is also enforced when 'live' is true.
		signedAt, err := time.Parse(time.RFC3339Nano, c.CreatedUTC)
		if err != nil {
			return zero, err
		}
		leaf, err := verifyFieldSignature(c, signed.CertificatePEM, signed.SignatureHex, roots, item.node, signedAt, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return zero, fmt.Errorf("%s Case signature: %w", item.node, err)
		}
		if exchangeSHA(leaf.Raw) != item.sha {
			return zero, fmt.Errorf("%s signer certificate differs from pinned Case identity", item.node)
		}
		if live {
			if err := verifyFieldLeaf(leaf, roots, item.node, now, x509.ExtKeyUsageClientAuth); err != nil {
				return zero, err
			}
		}
	}
	return c, nil
}

func scheduledCaseCampaignRef(c scheduledCase, dir string) (scheduledCampaignRef, error) {
	for _, v := range c.Campaigns {
		if v.Direction == dir {
			return v, nil
		}
	}
	return scheduledCampaignRef{}, errors.New("direction not present in mutually signed Case")
}

func verifyScheduledLocalCampaign(c scheduledCase, dir, campaignDir string) (campaignManifest, error) {
	m, err := readCampaign(campaignDir)
	if err != nil {
		return m, err
	}
	item, err := scheduledCaseCampaignRef(c, dir)
	if err != nil {
		return m, err
	}
	contents, err := readSmallRegular(filepath.Join(campaignDir, "campaign.json"), exchangeMaxFile)
	if err != nil {
		return m, err
	}
	if m.CampaignID != item.CampaignID || m.Direction != item.Direction || exchangeSHA(contents) != item.ManifestSHA256 {
		return m, errors.New("local immutable Campaign differs from mutually approved Case")
	}
	return m, nil
}
