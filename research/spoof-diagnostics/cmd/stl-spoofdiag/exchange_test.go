package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every sample and receipt in these fixtures is synthetically signed; no
// sockets, fake public traffic, raw packet calls or network namespaces run.
type exchangeFixture struct {
	caseID string
	ca     string
	ids    string
	zips   []string
	dirs   []string
}

func exchangeCopyFixtureFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func exchangeGenerateFixture(t *testing.T, batches int, includeReceipts bool) exchangeFixture {
	t.Helper()
	base := t.TempDir()
	idDir := filepath.Join(base, "identity")
	if err := createFieldIdentity(idDir); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(idDir, "ca.crt")
	out := filepath.Join(base, "exchange")
	if err := exchangeCreateBase(out); err != nil {
		t.Fatal(err)
	}
	test := exchangeFixture{caseID: "0123456789abcdef0123456789abcdef", ca: ca, ids: idDir}
	for _, direction := range []string{"A_TO_B", "B_TO_A"} {
		sender, receiver := "A", "B"
		ipBase, destination := "10.91.1.", "10.99.0.2"
		if direction == "B_TO_A" {
			sender, receiver = "B", "A"
			ipBase, destination = "10.91.4.", "10.99.0.3"
		}
		input := filepath.Join(base, direction+"-sources.json")
		inv := CandidateFile{SchemaVersion: schema, Mode: "field_candidates"}
		for n := 1; n <= batches; n++ {
			inv.Candidates = append(inv.Candidates, Candidate{IP: ipBase + string(rune('0'+n)),
				Direction: direction, Sender: sender, Receiver: receiver})
		}
		if err := writeCandidateInventory(input, inv); err != nil {
			t.Fatal(err)
		}
		senderDir := filepath.Join(base, direction+"-sender")
		settings := campaignManifest{Direction: direction, DestinationIP: destination,
			Transport: "field_raw_ipv4", DataPort: 24572, PacketSize: 192,
			BatchSize: 1, SamplesPerSource: 1, TTLSeconds: 600, Epoch: "fixture"}
		m, err := createCampaign(input, senderDir, settings)
		if err != nil {
			t.Fatal(err)
		}
		for _, batch := range m.Batches {
			p, err := campaignNewAttempt(senderDir, m, batch, 1, filepath.Join(idDir, sender+".crt"),
				filepath.Join(idDir, sender+".key"), ca)
			if err != nil || p == nil {
				t.Fatalf("offline batch creation: %v", err)
			}
			runDir := campaignAttemptDir(senderDir, batch.Number, 1)
			chPath := filepath.Join(runDir, "challenge.json")
			g, err := newFieldGrantWithDestinationOwnership(fieldOptions{File: filepath.Join(senderDir, batch.File),
				Challenge: chPath, Sender: sender, Receiver: receiver,
				Cert: filepath.Join(idDir, receiver+".crt"), Key: filepath.Join(idDir, receiver+".key"), CA: ca,
			}, func(string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := saveNewJSON(filepath.Join(runDir, "grant.json"), g); err != nil {
				t.Fatal(err)
			}
			plan, err := readSignedFieldChallenge(chPath)
			if err != nil {
				t.Fatal(err)
			}
			cred, err := loadFieldCredential(filepath.Join(idDir, sender+".crt"), filepath.Join(idDir, sender+".key"))
			if err != nil {
				t.Fatal(err)
			}
			ev := newSenderEvidence(plan.Challenge)
			senderPath := filepath.Join(runDir, "sender.json")
			if err := signedSenderSnapshot(senderPath, ev, cred, false); err != nil {
				t.Fatal(err)
			}
			if _, err := submitFieldRun(plan.Challenge, &ev, cred, senderPath,
				func(fieldSample, []byte) error { return nil }, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if includeReceipts {
				receiverCert, err := loadFieldCredential(filepath.Join(idDir, receiver+".crt"), filepath.Join(idDir, receiver+".key"))
				if err != nil {
					t.Fatal(err)
				}
				s := plan.Challenge.Samples[0]
				r := fieldReceipt{SchemaVersion: schema, Environment: plan.Challenge.Environment,
					RunID: plan.Challenge.RunID, Observer: roleName(receiver),
					Status: "COMPLETE", CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
					ExpectedSamples: len(plan.Challenge.Samples), ChallengeDigest: fieldChallengeDigest(plan.Challenge),
					EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
					ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
					Observations: []fieldSeen{{Index: 0, SourceCandidate: s.Candidate.IP,
						ActualPacketSource: s.Candidate.IP, PacketSize: s.Size, Direction: direction,
						PolicyEpoch: s.Epoch, Authenticated: true, SourceMatched: true}},
				}
				signed, err := signFieldReceipt(r, receiverCert)
				if err != nil {
					t.Fatal(err)
				}
				if err := saveNewJSON(filepath.Join(runDir, "receipt.json"), signed); err != nil {
					t.Fatal(err)
				}
			}
		}
		recvDir := filepath.Join(base, direction+"-receiver")
		if err := os.Mkdir(recvDir, 0700); err != nil {
			t.Fatal(err)
		}
		exchangeCopyFixtureFile(t, filepath.Join(senderDir, "campaign.json"), filepath.Join(recvDir, "campaign.json"))
		for _, batch := range m.Batches {
			exchangeCopyFixtureFile(t, filepath.Join(senderDir, batch.File), filepath.Join(recvDir, batch.File))
			rp := campaignAttemptDir(senderDir, batch.Number, 1)
			dst := campaignAttemptDir(recvDir, batch.Number, 1)
			for _, file := range []string{"challenge.json", "grant.json"} {
				exchangeCopyFixtureFile(t, filepath.Join(rp, file), filepath.Join(dst, file))
			}
			if includeReceipts {
				exchangeCopyFixtureFile(t, filepath.Join(rp, "receipt.json"), filepath.Join(dst, "receipt.json"))
				if err := os.Remove(filepath.Join(rp, "receipt.json")); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, role := range []string{"sender", "receiver"} {
			dir, node := senderDir, sender
			if role == "receiver" {
				dir, node = recvDir, receiver
			}
			filename := filepath.Join(out, "outbox", direction+"-"+role+".zip")
			if _, err := exchangeSignBundle(test.caseID, dir, role,
				filepath.Join(idDir, node+".crt"), filepath.Join(idDir, node+".key"), ca, filename); err != nil {
				t.Fatal(err)
			}
			test.zips = append(test.zips, filename)
			test.dirs = append(test.dirs, dir)
		}
	}
	return test
}

func TestExchangeFourSignedBundlesReorderedRenamedAndIndependent(t *testing.T) {
	f := exchangeGenerateFixture(t, 2, true)
	for _, file := range f.zips {
		b, err := exchangeOpenBundle(file, f.ca)
		if err != nil {
			t.Fatal(err)
		}
		if err := exchangeValidateBundleContent(b, f.ca); err != nil {
			t.Fatal(err)
		}
	}
	renamed := []string{}
	for i := len(f.zips) - 1; i >= 0; i-- {
		p := filepath.Join(t.TempDir(), "renamed-no-extension")
		exchangeCopyFixtureFile(t, f.zips[i], p)
		renamed = append(renamed, p)
	}
	r, err := exchangeAnalyze(f.caseID, f.ca, renamed)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "COMPLETE_SIGNED_EVIDENCE_NOT_CONNECTIVITY_PROOF" || len(r.Inputs) != 4 ||
		len(r.Directions) != 2 || len(r.MissingSlots) != 0 {
		t.Fatalf("four bundles were not independently reconciled: %+v", r)
	}
	for _, d := range r.Directions {
		if d.Status != "COMPLETE_SIGNED_EVIDENCE" || len(d.Sources) != 2 {
			t.Fatalf("missing directional batch: %+v", d)
		}
		for _, s := range d.Sources {
			if s.Planned != 1 || s.Submitted != 1 || s.Observed != 1 || s.SourceMatched != 1 {
				t.Fatalf("bad signed sample join %+v", s)
			}
		}
	}
	r2, err := exchangeAnalyze(f.caseID, f.ca, f.zips)
	if err != nil || !reflect.DeepEqual(r, r2) {
		t.Fatalf("report changed on filename/order differences: %v", err)
	}
	outputDir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(outputDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := exchangeSaveReports(outputDir, r); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(outputDir, "SDX-"+f.caseID+"-final.html"))
	if err != nil || !bytes.Contains(html, []byte("NOT_CONNECTIVITY_PROOF")) {
		t.Fatalf("offline report missing bounded qualification: %v", err)
	}
	if err := exchangeSaveReports(outputDir, r); err != nil {
		t.Fatal("same report should be safely idempotent:", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "SDX-"+f.caseID+"-results.csv"), []byte("different"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exchangeSaveReports(outputDir, r); err == nil {
		t.Fatal("a conflicting pre-existing report was overwritten")
	}
}

func TestExchangePartialDuplicateWrongCaseAndArchiveTamper(t *testing.T) {
	f := exchangeGenerateFixture(t, 1, false)
	onlyThree := f.zips[:3]
	r, err := exchangeAnalyze(f.caseID, f.ca, onlyThree)
	if err != nil || r.Status != "INCOMPLETE" || len(r.MissingSlots) != 1 {
		t.Fatalf("partial input was treated as success: %+v %v", r, err)
	}
	copyPath := filepath.Join(t.TempDir(), "duplicate.bin")
	exchangeCopyFixtureFile(t, f.zips[0], copyPath)
	r, err = exchangeAnalyze(f.caseID, f.ca, append(append([]string{}, f.zips...), copyPath))
	if err != nil || len(r.Conflicts) != 0 || len(r.Inputs) != 4 {
		t.Fatalf("same bytes not deduplicated: %+v %v", r, err)
	}
	r, err = exchangeAnalyze("ffffffffffffffffffffffffffffffff", f.ca, f.zips)
	if err != nil || len(r.MissingSlots) != 4 || len(r.Inputs) != 0 {
		t.Fatalf("different case mixed: %+v %v", r, err)
	}
	data, err := os.ReadFile(f.zips[0])
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		if i > len(data)/2 && data[i] != 0 {
			data[i] ^= 0x3f
			break
		}
	}
	bad := filepath.Join(t.TempDir(), "tampered.zip")
	if err := os.WriteFile(bad, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err = exchangeAnalyze(f.caseID, f.ca, append(append([]string{}, f.zips[1:]...), bad))
	if err != nil || r.Status != "INCOMPLETE" || len(r.Rejected) == 0 {
		t.Fatalf("tampered ZIP was trusted: %+v %v", r, err)
	}
}

func TestExchangeRejectsTraversalSymlinksAndMismatchedRole(t *testing.T) {
	f := exchangeGenerateFixture(t, 1, true)
	base := t.TempDir()
	z := filepath.Join(base, "evil.zip")
	fd, err := os.OpenFile(z, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(fd)
	_, err = zw.Create("../escape.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	fd.Close()
	if _, err := exchangeOpenBundle(z, f.ca); err == nil {
		t.Fatal("path traversal ZIP was accepted")
	}
	link := filepath.Join(base, "link.zip")
	if err := os.Symlink(f.zips[0], link); err != nil {
		t.Fatal(err)
	}
	if _, err := exchangeOpenBundle(link, f.ca); err == nil {
		t.Fatal("symlink bundle was accepted")
	}
	good, err := exchangeOpenBundle(f.zips[0], f.ca)
	if err != nil {
		t.Fatal(err)
	}
	badManifest := good.Manifest
	badManifest.Node = "B" // sender A_TO_B must be A
	if err := exchangeValidateManifest(badManifest); err == nil {
		t.Fatal("wrong-role export identity accepted")
	}
	if exchangeSanitizeCSV("=SUM(1,2)") != "'=SUM(1,2)" {
		t.Fatal("CSV formula guard failed")
	}
	jsonReport, err := json.Marshal(exchangeCaseReport{CaseID: f.caseID})
	if err != nil || strings.Contains(string(jsonReport), "private_key") {
		t.Fatal("report accidentally contains key material")
	}
}
