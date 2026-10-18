// stl-spoofdiag is a standalone research tool. This Go port currently implements
// offline operator validation, local two-agent loopback measurement and signed receipts.
// It does not provide a public field/source-spoof probe engine.
package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

var version = "dev"
var commit = "unpublished"

const schema = 1

type Candidate struct {
	IP        string `json:"ip"`
	Direction string `json:"direction"`
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
}

type CandidateFile struct {
	SchemaVersion int         `json:"schema_version"`
	Mode          string      `json:"mode"`
	Candidates    []Candidate `json:"candidates"`
}

type Observation struct {
	SampleID            string `json:"sample_id"`
	RunID               string `json:"run_id"`
	Direction           string `json:"direction"`
	Sender              string `json:"sender"`
	Receiver            string `json:"receiver"`
	SourceIP            string `json:"source_ip"`
	PacketSize          int    `json:"packet_size"`
	Epoch               string `json:"policy_epoch"`
	Attempted           bool   `json:"attempted"`
	EgressObserved      *bool  `json:"egress_observed"`
	PeerObserved        *bool  `json:"peer_observed"`
	AuthVerified        *bool  `json:"auth_verified"`
	ReturnObserver      string `json:"return_observer,omitempty"`
	ReturnAuthenticated *bool  `json:"return_authenticated"`
	Environment         string `json:"environment"`
}

type EvidenceFile struct {
	SchemaVersion int           `json:"schema_version"`
	Observations  []Observation `json:"observations"`
}

type Summary struct {
	EvidenceTrust  string `json:"evidence_trust"`
	SampleID       string `json:"sample_id"`
	SchemaVersion  int    `json:"schema_version"`
	RunID          string `json:"run_id"`
	Environment    string `json:"environment"`
	Direction      string `json:"direction"`
	SourceIP       string `json:"source_ip"`
	Sender         string `json:"sender"`
	Receiver       string `json:"receiver"`
	PacketSize     int    `json:"packet_size"`
	Epoch          string `json:"policy_epoch"`
	Result         string `json:"result"`
	Reason         string `json:"reason"`
	ReturnObserver string `json:"return_observer,omitempty"`
	ReturnStatus   string `json:"return_status"`
	PrivateL3      string `json:"private_l3"`
}

func validDirection(d string) bool { return d == "A_TO_B" || d == "B_TO_A" }

func validateIP(value string, mode string) error {
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("invalid exact IPv4 address %q", value)
	}
	if mode == "private_lab" {
		if !ip.IsPrivate() {
			return fmt.Errorf("private_lab requires RFC1918 address: %q", value)
		}
	} else if mode == "approved_field_plan" {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || reservedFieldIP(ip) {
			return fmt.Errorf("non-routable or private candidate in field plan: %q", value)
		}
	} else {
		return fmt.Errorf("unknown mode %q", mode)
	}
	return nil
}

func reservedFieldIP(ip netip.Addr) bool {
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return true
		}
	}
	return false
}

func validateCandidates(c CandidateFile) error {
	if c.SchemaVersion != schema {
		return errors.New("unsupported candidate schema")
	}
	if c.Mode != "private_lab" && c.Mode != "approved_field_plan" {
		return errors.New("unsupported candidate mode")
	}
	if len(c.Candidates) == 0 {
		return errors.New("candidate list is empty")
	}
	seen := make(map[string]bool)
	for _, item := range c.Candidates {
		if !validDirection(item.Direction) {
			return fmt.Errorf("invalid direction %q", item.Direction)
		}
		if strings.TrimSpace(item.Sender) == "" || strings.TrimSpace(item.Receiver) == "" || item.Sender == item.Receiver {
			return errors.New("distinct sender and receiver are required")
		}
		if err := validateIP(item.IP, c.Mode); err != nil {
			return err
		}
		key := strings.Join([]string{item.IP, item.Direction, item.Sender, item.Receiver}, "|")
		if seen[key] {
			return fmt.Errorf("duplicate candidate identity %q", key)
		}
		seen[key] = true
	}
	return nil
}

func readCandidates(path string) (CandidateFile, error) {
	var result CandidateFile
	data, err := readSmallRegular(path, 4<<20)
	if err != nil {
		return result, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&result); err != nil {
			return result, err
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return result, errors.New("trailing JSON data or excessive input")
		}
	case ".csv":
		result.SchemaVersion = schema
		result.Mode = "private_lab"
		r := csv.NewReader(bytes.NewReader(data))
		r.FieldsPerRecord = 4
		rows, err := r.ReadAll()
		if err != nil {
			return result, err
		}
		if len(rows) > 0 && strings.EqualFold(rows[0][0], "ip") {
			rows = rows[1:]
		}
		for _, row := range rows {
			result.Candidates = append(result.Candidates, Candidate{IP: strings.TrimSpace(row[0]), Direction: strings.TrimSpace(row[1]), Sender: strings.TrimSpace(row[2]), Receiver: strings.TrimSpace(row[3])})
		}
	default:
		return result, errors.New("candidate file must be .json or .csv")
	}
	return result, validateCandidates(result)
}

func classify(o Observation) (Summary, error) {
	s := Summary{EvidenceTrust: "UNVERIFIED_INPUT_DECLARATION", SampleID: o.SampleID, SchemaVersion: schema, RunID: o.RunID, Environment: o.Environment, Direction: o.Direction, SourceIP: o.SourceIP, Sender: o.Sender, Receiver: o.Receiver, PacketSize: o.PacketSize, Epoch: o.Epoch, PrivateL3: "NOT_TESTED", ReturnStatus: "NOT_TESTED", Result: "INCONCLUSIVE"}
	if !validDirection(o.Direction) || o.Sender == "" || o.Receiver == "" || o.Sender == o.Receiver || o.RunID == "" || o.SampleID == "" || o.Epoch == "" || o.PacketSize <= 0 {
		return s, errors.New("missing observation identity")
	}
	if o.Environment != "private_lab" && o.Environment != "approved_field" {
		return s, errors.New("invalid evidence environment")
	}
	if err := validateIP(o.SourceIP, map[bool]string{true: "private_lab", false: "approved_field_plan"}[o.Environment == "private_lab"]); err != nil {
		return s, err
	}
	if o.ReturnAuthenticated != nil && *o.ReturnAuthenticated && (o.ReturnObserver == "" || o.PeerObserved == nil || !*o.PeerObserved || o.AuthVerified == nil || !*o.AuthVerified) {
		return s, errors.New("contradictory authenticated-return observation")
	}
	if o.ReturnAuthenticated != nil {
		if *o.ReturnAuthenticated {
			s.ReturnStatus = "CLAIMED_AUTHENTICATED_AT:" + o.ReturnObserver
			s.ReturnObserver = o.ReturnObserver
		} else {
			s.ReturnStatus = "NOT_OBSERVED"
		}
	}
	if !o.Attempted {
		s.Result = "NOT_TESTED"
		s.Reason = "no sender attempt"
		return s, nil
	}
	if o.EgressObserved == nil {
		s.Result = "SUBMITTED_ONLY"
		s.Reason = "independent egress observation missing"
		return s, nil
	}
	if !*o.EgressObserved {
		s.Result = "INCONCLUSIVE"
		s.Reason = "no independently observed egress"
		return s, nil
	}
	if o.PeerObserved == nil {
		s.Result = "EGRESS_OBSERVED"
		s.Reason = "no independent peer observation"
		return s, nil
	}
	if !*o.PeerObserved {
		s.Result = "NOT_OBSERVED_BY_PEER"
		s.Reason = "packet absent at peer observation point"
		return s, nil
	}
	if o.AuthVerified == nil || !*o.AuthVerified {
		s.Result = "PEER_OBSERVED_UNAUTHENTICATED"
		s.Reason = "receiver proof lacks authentication"
		return s, nil
	}
	s.Result = "CLAIMED_AUTHENTICATED_PEER_OBSERVED"
	s.Reason = "local/field scope bounded by observation provenance"
	return s, nil
}

func report(path string) ([]Summary, error) {
	data, err := readSmallRegular(path, 8<<20)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var src EvidenceFile
	if err := dec.Decode(&src); err != nil {
		return nil, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("trailing/oversize evidence data")
	}
	if src.SchemaVersion != schema {
		return nil, errors.New("unsupported evidence schema")
	}
	out := make([]Summary, 0, len(src.Observations))
	seen := make(map[string]bool)
	for _, o := range src.Observations {
		k := fmt.Sprint(o.RunID, "|", o.SampleID, "|", o.Direction, "|", o.Sender, "|", o.Receiver, "|", o.SourceIP, "|", o.PacketSize, "|", o.Epoch)
		if seen[k] {
			return nil, errors.New("duplicate evidence identity")
		}
		seen[k] = true
		s, err := classify(o)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Direction+out[i].SourceIP < out[j].Direction+out[j].SourceIP })
	return out, nil
}

func pretty(v any) error { e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); return e.Encode(v) }
func versionInfo() map[string]string {
	return map[string]string{"product": "stl-spoofdiag", "version": version, "commit": commit, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
}

func menu() error {
	s := bufio.NewScanner(os.Stdin)
	fmt.Println("STL Spoof Diagnostics | offline research console")
	for {
		fmt.Print("\n1) Version  2) Preflight  3) Validate candidates  4) Classify evidence  5) Add source  0) Exit\nChoice: ")
		if !s.Scan() {
			return s.Err()
		}
		switch strings.TrimSpace(s.Text()) {
		case "0", "q":
			return nil
		case "1":
			if err := pretty(versionInfo()); err != nil {
				return err
			}
		case "2":
			if err := preflight(); err != nil {
				return err
			}
		case "3":
			fmt.Print("CSV/JSON file: ")
			if !s.Scan() {
				return s.Err()
			}
			c, err := readCandidates(strings.TrimSpace(s.Text()))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				break
			}
			fmt.Printf("Validated %d explicitly listed candidates (NO network traffic).\n", len(c.Candidates))
		case "5":
			fields := make([]string, 6)
			prompts := []string{"JSON path", "Mode (private_lab/approved_field_plan; blank for existing)", "Exact source IPv4", "Direction (A_TO_B/B_TO_A)", "Sender ID", "Receiver ID"}
			for i, prompt := range prompts {
				fmt.Print(prompt, ": ")
				if !s.Scan() {
					return s.Err()
				}
				fields[i] = strings.TrimSpace(s.Text())
			}
			if err := addSource(fields[0], fields[1], Candidate{IP: fields[2], Direction: fields[3], Sender: fields[4], Receiver: fields[5]}); err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				fmt.Println("Source saved; no traffic emitted")
			}
		case "4":
			fmt.Print("Evidence JSON file: ")
			if !s.Scan() {
				return s.Err()
			}
			items, err := report(strings.TrimSpace(s.Text()))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				break
			}
			if err := pretty(items); err != nil {
				return err
			}
		default:
			fmt.Println("Unknown command")
		}
	}
}
func preflight() error {
	return pretty(map[string]any{"schema_version": schema, "utc": time.Now().UTC().Format(time.RFC3339), "os": runtime.GOOS, "arch": runtime.GOARCH, "go_runtime": runtime.Version(), "probe_engine": "LAB_PRIVATE_NETNS_RAW_ADAPTER_UNDER_VALIDATION", "field_traffic": "DISABLED", "test_network": "LOOPBACK_OR_PROVEN_ISOLATED_RFC1918_NETNS_ONLY", "loopback_two_agent": "AVAILABLE"})
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: stl-spoofdiag version|preflight|sources|plan|report|lab|menu")
	}
	switch args[0] {
	case "version":
		return pretty(versionInfo())
	case "preflight":
		return preflight()
	case "menu":
		return menu()
	case "sources":
		return sourceAdd(args[1:])
	case "lab":
		return labCLI(args[1:])
	case "plan", "report":
		cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
		p := cmd.String("file", "", "existing CSV or JSON file")
		if err := cmd.Parse(args[1:]); err != nil {
			return err
		}
		if *p == "" {
			return errors.New("--file is required")
		}
		if args[0] == "plan" {
			c, err := readCandidates(*p)
			if err != nil {
				return err
			}
			return pretty(map[string]any{"schema_version": schema, "mode": c.Mode, "candidates": c.Candidates, "count": len(c.Candidates), "network": "NOT_RUN", "source_egress": "NOT_TESTED", "peer_observation": "NOT_TESTED", "return_path": "NOT_TESTED", "private_l3": "NOT_TESTED"})
		}
		s, err := report(*p)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"schema_version": schema, "evaluations": s, "network": "NO_NETWORK_CALLS_IN_REPORT"})
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "stl-spoofdiag:", err)
		os.Exit(2)
	}
}
