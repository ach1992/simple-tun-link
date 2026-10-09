package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type lifecycleObserved struct{ present bool }

func (lifecycleObserved) ObservedResources() []domain.ResourceClaim { return nil }

type lifecyclePlan struct {
	operation backend.Operation
	changed   bool
	resources []domain.ResourceClaim
}

func (p lifecyclePlan) Empty() bool                       { return !p.changed }
func (p lifecyclePlan) Resources() []domain.ResourceClaim { return p.resources }

type lifecycleFakeBackend struct {
	present    map[domain.LinkID]bool
	applies    []domain.LinkID
	operations []backend.Operation
	failApply  bool
	failVerify bool
}

func newLifecycleFake() *lifecycleFakeBackend {
	return &lifecycleFakeBackend{present: make(map[domain.LinkID]bool)}
}
func (*lifecycleFakeBackend) Kind() domain.Backend { return domain.BackendGRE }
func (b *lifecycleFakeBackend) Inspect(_ context.Context, link domain.Link) (backend.Observation, error) {
	return lifecycleObserved{present: b.present[link.ID]}, nil
}
func (b *lifecycleFakeBackend) Plan(_ context.Context, req backend.Request, obs backend.Observation) (backend.Plan, error) {
	observed, ok := obs.(lifecycleObserved)
	if !ok {
		return nil, errors.New("invalid fake observation")
	}
	switch req.Operation {
	case backend.OperationEnsure:
		return lifecyclePlan{operation: req.Operation, changed: !observed.present, resources: []domain.ResourceClaim{
			{Kind: domain.ResourceInterface, Key: "test" + string(req.Link.ID)[4:16]},
			{Kind: domain.ResourceLinkSubnet, Key: req.Link.Addresses.Local.Masked().String()},
		}}, nil
	case backend.OperationRemove:
		return lifecyclePlan{operation: req.Operation, changed: observed.present}, nil
	}
	return nil, errors.New("unexpected fake operation")
}
func (*lifecycleFakeBackend) Validate(_ context.Context, req backend.Request, _ backend.Observation, p backend.Plan) error {
	if req.Operation == backend.OperationRemove && len(req.OwnedResources) == 0 {
		return errors.New("missing owned resources; refusing destructive removal")
	}
	if p == nil {
		return errors.New("missing plan")
	}
	return nil
}
func (b *lifecycleFakeBackend) Apply(_ context.Context, req backend.Request, _ backend.Observation, _ backend.Plan) (backend.Rollback, error) {
	if b.failApply {
		return nil, errors.New("private_key=VERY_SECRET_NOT_FOR_OUTPUT")
	}
	id := req.Link.ID
	prior := b.present[id]
	b.applies = append(b.applies, id)
	b.operations = append(b.operations, req.Operation)
	b.present[id] = req.Operation == backend.OperationEnsure
	return func(context.Context) error { b.present[id] = prior; return nil }, nil
}
func (b *lifecycleFakeBackend) Verify(_ context.Context, req backend.Request) (backend.Observation, error) {
	if b.failVerify {
		return nil, errors.New("private_key=VERY_SECRET_NOT_FOR_OUTPUT")
	}
	if b.present[req.Link.ID] != (req.Operation == backend.OperationEnsure) {
		return nil, errors.New("fake backend status mismatch")
	}
	return lifecycleObserved{present: b.present[req.Link.ID]}, nil
}

func makeLifecycleDesired(t *testing.T, idChar string, subnet string) (domain.Link, string) {
	t.Helper()
	link := domain.Link{
		ID:          domain.LinkID("lnk_" + strings.Repeat(idChar, 32)),
		DisplayName: "very_private_label=DO_NOT_EXPOSE",
		Underlay:    domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("192.0.2.20")},
		Addresses:   domain.LinkAddresses{Local: netip.MustParsePrefix(subnet), Peer: netip.MustParsePrefix(strings.Replace(subnet, ".0/31", ".1/31", 1))},
		Backend:     domain.BackendGRE, Encapsulation: domain.EncapNative,
	}
	return link, desiredRequestJSON(t, link, desiredLinkSchemaVersion)
}

// Requests are always sent using the public versioned CLI envelope, even
// when their inner Link is constructed with the current domain fixture.
func desiredRequestJSON(t *testing.T, link domain.Link, version int) string {
	t.Helper()
	// Existing test fixtures must also serialize the pinned public v1
	// contract, not internal domain.Link; domain JSON changes cannot
	// silently reconfigure these automation acceptance scenarios.
	request := desiredLinkRequestV1{
		SchemaVersion: version,
		Link: desiredLinkV1{
			ID: link.ID, DisplayName: link.DisplayName,
			Underlay: desiredUnderlayV1{
				Local: link.Underlay.Local, Peer: link.Underlay.Peer,
			},
			Addresses: desiredLinkAddressesV1{
				Local: link.Addresses.Local, Peer: link.Addresses.Peer,
			},
			Backend: link.Backend, Encapsulation: link.Encapsulation,
			GRE: desiredGREOptionsV1{
				KeyEnabled: link.GRE.KeyEnabled, Key: link.GRE.Key,
				TTL: link.GRE.TTL, TOS: link.GRE.TOS,
				DisablePMTUD: link.GRE.DisablePMTUD,
				Checksum:     link.GRE.Checksum, Sequence: link.GRE.Sequence,
				UDPPort: link.GRE.UDPPort,
			},
		},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func runLifecycleTest(t *testing.T, root string, b *lifecycleFakeBackend, args []string, stdin string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	var backends []backend.Backend
	if b != nil {
		backends = []backend.Backend{b}
	}
	code := runWithRuntimeInput(args, strings.NewReader(stdin), &out, &errOut,
		&runtimeOptions{stateRoot: root, backends: backends})
	return code, out.String(), errOut.String()
}

func TestLifecycleCLIEnsuresIdempotentlyAndRemovesOnlyExplicitLink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	backendFake := newLifecycleFake()
	a, rawA := makeLifecycleDesired(t, "a", "10.70.0.0/31")
	b, rawB := makeLifecycleDesired(t, "b", "10.70.1.0/31")
	for i, tc := range []struct {
		link    domain.Link
		raw     string
		changed bool
	}{
		{a, rawA, true}, {a, rawA, false}, {b, rawB, true},
	} {
		code, out, stderr := runLifecycleTest(t, root, backendFake, []string{"link", "ensure", "--stdin", "--json"}, tc.raw)
		if code != 0 || stderr != "" || strings.Contains(out, "very_private_label") {
			t.Fatalf("ensure[%d] returned unsafe outcome: code=%d out=%q stderr=%q", i, code, out, stderr)
		}
		var got lifecycleResultResponse
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if got.SchemaVersion != jsonSchemaVersion || got.LinkID != tc.link.ID ||
			got.Changed != tc.changed || got.Removed || got.Operation != "link_ensure" {
			t.Fatalf("inaccurate idempotent result: %+v", got)
		}
	}
	if len(backendFake.applies) != 2 {
		t.Fatalf("idempotent Ensure unnecessarily applied: %+v", backendFake.applies)
	}
	snap, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snap.Links) != 2 {
		t.Fatalf("two same-peer Links not persisted: %+v, %v", snap, err)
	}
	for _, rec := range snap.Links {
		if len(rec.OwnedResources) == 0 {
			t.Fatal("committed Link has no owned resources")
		}
	}

	code, out, stderr := runLifecycleTest(t, root, backendFake, []string{"link", "remove", string(a.ID), "--confirm", string(a.ID), "--json"}, "")
	if code != 0 || stderr != "" {
		t.Fatalf("remove failed: %d %q %q", code, out, stderr)
	}
	var got lifecycleResultResponse
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.LinkID != a.ID || !got.Removed || !got.Changed || got.Operation != "link_remove" {
		t.Fatalf("remove falsely reported: %+v", got)
	}
	if backendFake.present[a.ID] || !backendFake.present[b.ID] {
		t.Fatalf("removal disturbed unrelated same-peer Link: %+v", backendFake.present)
	}
	snap, err = state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snap.Links) != 1 || snap.Links[0].Desired.ID != b.ID {
		t.Fatalf("canonical state lost wrong Link: %+v %v", snap, err)
	}
	if info, err := os.Stat(filepath.Join(root, "state.json")); err != nil ||
		info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("persisted Link state has unsafe file mode: %+v %v", info, err)
	}
}

func TestLifecycleCLIRejectedInputCannotCreateLocksStateOrModifyHost(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state-not-existing")
	backendFake := newLifecycleFake()
	link, raw := makeLifecycleDesired(t, "c", "10.70.2.0/31")
	_ = link
	inputs := []struct{ name, input string }{
		{"empty", ""},
		{"secret Quick Link", "stl://2.sensitive.DO_NOT_EXPOSE"},
		{"missing required id", `{"backend":"gre"}`},
		{"null field", strings.Replace(raw, `"backend":"gre"`, `"backend":null`, 1)},
		{"duplicate root", strings.Replace(raw, `"backend":"gre"`, `"backend":"gre","backend":"ipip"`, 1)},
		{"case-folded duplicate", strings.Replace(raw, `"backend":"gre"`, `"backend":"gre","Backend":"ipip"`, 1)},
		{"nested duplicate", strings.Replace(raw, `"peer":"192.0.2.20"`, `"peer":"192.0.2.20","peer":"203.0.113.1"`, 1)},
		{"unknown extra", strings.TrimSuffix(raw, "}") + `,"recipient_secret":"DO_NOT_EXPOSE"}`},
		{"second object", raw + raw},
		{"nested arrays", strings.Replace(raw, `"local":"192.0.2.10"`, `"local":["192.0.2.10"]`, 1)},
		{"very large", raw + strings.Repeat("DO_NOT_EXPOSE", maxDesiredLinkBytes)},
		{"legacy unversioned Link object", string(mustMarshalJSON(t, link))},
		{"missing schema_version", strings.Replace(raw, `"schema_version":1,`, "", 1)},
		{"schema_version null", strings.Replace(raw, `"schema_version":1`, `"schema_version":null`, 1)},
		{"schema_version string", strings.Replace(raw, `"schema_version":1`, `"schema_version":"1"`, 1)},
		{"schema_version floating", strings.Replace(raw, `"schema_version":1`, `"schema_version":1.5`, 1)},
		{"schema_version boolean", strings.Replace(raw, `"schema_version":1`, `"schema_version":true`, 1)},
		{"schema_version zero", strings.Replace(raw, `"schema_version":1`, `"schema_version":0`, 1)},
		{"schema_version negative", strings.Replace(raw, `"schema_version":1`, `"schema_version":-1`, 1)},
		{"duplicate schema_version", strings.Replace(raw, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)},
		{"case-folded duplicate schema_version", strings.Replace(raw, `"schema_version":1`, `"schema_version":1,"SCHEMA_VERSION":2`, 1)},
		{"missing link", `{"schema_version":1}`},
		{"link null", `{"schema_version":1,"link":null}`},
		{"link array", `{"schema_version":1,"link":[]}`},
		{"unknown envelope field", strings.Replace(raw, `"schema_version":1,`, `"schema_version":1,"recipient_secret":"DO_NOT_EXPOSE",`, 1)},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := runLifecycleTest(t, root, backendFake, []string{"link", "ensure", "--stdin", "--json"}, tc.input)
			if code != 2 || stderr != "" || strings.Contains(out, "DO_NOT_EXPOSE") ||
				strings.Contains(out, "very_private_label") || strings.Contains(out, "stl://") {
				t.Fatalf("untrusted ensure input accepted or echoed: code=%d out=%q err=%q", code, out, stderr)
			}
			var response linkReadErrorResponse
			if err := json.Unmarshal([]byte(out), &response); err != nil ||
				response.Error == nil || response.Error.Code != stlerr.CodeInvalid {
				t.Fatalf("invalid Link response not structured: %q", out)
			}
		})
	}
	if len(backendFake.applies) != 0 {
		t.Fatalf("invalid inputs reached mutation: %+v", backendFake.applies)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected input created state or locks: %v", err)
	}
}

func TestLifecycleCLIRemoveRequiresExplicitMatchingConfirmation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	backendFake := newLifecycleFake()
	link, raw := makeLifecycleDesired(t, "d", "10.70.3.0/31")
	code, _, _ := runLifecycleTest(t, root, backendFake, []string{"link", "ensure", "--stdin"}, raw)
	if code != 0 {
		t.Fatal("test setup Ensure failed")
	}
	appliedBefore := len(backendFake.applies)
	for _, args := range [][]string{
		{"link", "remove", string(link.ID), "--confirm", "lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "--json"},
		{"link", "remove", string(link.ID), "--json"},
		{"link", "remove", "lnk_bad", "--confirm", "lnk_bad", "--json"},
		{"link", "remove", string(link.ID), "--confirm", string(link.ID), "--danger", "--json"},
	} {
		code, out, stderr := runLifecycleTest(t, root, backendFake, args, "")
		if code != 2 || stderr != "" || strings.Contains(out, "very_private_label") {
			t.Fatalf("invalid removal accepted: %d %q %q", code, out, stderr)
		}
	}
	if len(backendFake.applies) != appliedBefore || !backendFake.present[link.ID] {
		t.Fatal("unconfirmed removal changed a Link")
	}
}

func TestLifecycleCLIUnsupportedBackendNeverPretendsSuccess(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link, raw := makeLifecycleDesired(t, "e", "10.70.4.0/31")
	code, out, stderr := runLifecycleTest(t, root, nil, []string{"link", "ensure", "--stdin", "--json"}, raw)
	if code != 4 || stderr != "" || strings.Contains(out, "private_key") || strings.Contains(out, "very_private_label") {
		t.Fatalf("missing backend falsely succeeded: %d %q %q", code, out, stderr)
	}
	var failure lifecycleFailureResponse
	if err := json.Unmarshal([]byte(out), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Error.Code != stlerr.CodeUnsupported || failure.Outcome != "unconfirmed" ||
		!failure.ReconciliationRequired {
		t.Fatalf("untruthful failure: %+v", failure)
	}
	if _, found := backendFakeNoopLookup(root, link.ID); found {
		t.Fatal("unsupported backend committed Link")
	}
}

func backendFakeNoopLookup(root string, id domain.LinkID) (state.LinkRecord, bool) {
	snap, _ := state.NewFileStore(root).Load(context.Background())
	return snap.Find(id)
}

func TestLifecycleCLIRollbackAndBackendErrorsAreRedactedAndNonzero(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	b := newLifecycleFake()
	_, raw := makeLifecycleDesired(t, "f", "10.70.5.0/31")
	b.failApply = true
	code, out, stderr := runLifecycleTest(t, root, b, []string{"link", "ensure", "--stdin", "--json"}, raw)
	if code != 1 || stderr != "" || strings.Contains(out, "VERY_SECRET_NOT_FOR_OUTPUT") ||
		strings.Contains(out, "very_private_label") || !strings.Contains(out, "reconciliation_required") {
		t.Fatalf("backend error leaked or falsely succeeded: %d %q %q", code, out, stderr)
	}
	var failure lifecycleFailureResponse
	if err := json.Unmarshal([]byte(out), &failure); err != nil || failure.Error.Code != stlerr.CodeApply ||
		failure.Outcome != "unconfirmed" {
		t.Fatalf("structured backend failure wrong: %+v %v", failure, err)
	}
	if len(b.applies) != 0 {
		t.Fatal("failed backend operation mutated state")
	}
	b.failApply = false
	b.failVerify = true
	code, out, stderr = runLifecycleTest(t, root, b, []string{"link", "ensure", "--stdin", "--json"}, raw)
	if code != 1 || stderr != "" || strings.Contains(out, "VERY_SECRET_NOT_FOR_OUTPUT") {
		t.Fatalf("verification failure was not safely reported: %d %q %q", code, out, stderr)
	}
	if b.present[domain.LinkID("lnk_"+strings.Repeat("f", 32))] {
		t.Fatal("verification failure did not roll back new backend state")
	}
}

func TestLifecycleCLIDispatchNeverTreatsHumanTextAsAutomationSuccess(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	b := newLifecycleFake()
	link, raw := makeLifecycleDesired(t, "1", "10.70.6.0/31")
	code, out, stderr := runLifecycleTest(t, root, b, []string{"link", "ensure", "--stdin"}, raw)
	if code != 0 || stderr != "" || !strings.Contains(out, "changes applied and verified") {
		t.Fatalf("human Ensure response incorrect: %d %q %q", code, out, stderr)
	}
	code, out, stderr = runLifecycleTest(t, root, b, []string{"link", "ensure", "--stdin"}, raw)
	if code != 0 || stderr != "" || !strings.Contains(out, "already matches desired state") {
		t.Fatalf("idempotent response incorrect: %d %q %q", code, out, stderr)
	}
	code, out, stderr = runLifecycleTest(t, root, b, []string{"link", "remove", string(link.ID), "--confirm", string(link.ID)}, "")
	if code != 0 || stderr != "" || !strings.Contains(out, "removed via canonical Engine") {
		t.Fatalf("human Remove response incorrect: %d %q %q", code, out, stderr)
	}
}

func TestLifecycleFailurePartialResultUsesStableJSONNames(t *testing.T) {
	var stdout, stderr bytes.Buffer
	id := domain.LinkID("lnk_99999999999999999999999999999999")
	result := &app.Result{LinkID: id, Changed: true, Removed: true}
	code := lifecycleFailure(&stdout, &stderr, true, stlerr.CodeState,
		"link_remove", result, "Link removal needs reconciliation")
	if code != 1 || stderr.Len() != 0 {
		t.Fatalf("partial result must remain non-success: %d %q", code, stderr.String())
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, has := got["PartialResult"]; has {
		t.Fatal("Go field names leaked into machine JSON")
	}
	var partial map[string]any
	if err := json.Unmarshal(got["partial_result"], &partial); err != nil {
		t.Fatal(err)
	}
	if partial["link_id"] != string(id) || partial["changed"] != true || partial["removed"] != true {
		t.Fatalf("partial reconciliation hints have wrong schema: %#v", partial)
	}
	if _, has := partial["LinkID"]; has {
		t.Fatal("internal Go property leaked")
	}
}

// The machine request's v1 schema is distinct from internal domain.Link.
// An unknown future schema version is a deterministic unsupported-capability
// result; unsupported version/domain requests are rejected before runtime.
func TestLifecycleCLIUnsupportedSchemaAndDomainCapabilities(t *testing.T) {
	base, _ := makeLifecycleDesired(t, "8", "10.70.8.0/31")
	tests := []struct {
		name    string
		link    domain.Link
		version int
	}{
		{"future request schema v2", base, 2},
		{"unsupported GRE encapsulation", func() domain.Link {
			changed := base
			changed.Encapsulation = domain.EncapUDP
			return changed
		}(), 1},
		{"unsupported IPv6 Link addresses", func() domain.Link {
			changed := base
			changed.Addresses.Local = netip.MustParsePrefix("fd12:3456::/127")
			changed.Addresses.Peer = netip.MustParsePrefix("fd12:3456::1/127")
			return changed
		}(), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "must-not-exist")
			fake := newLifecycleFake()
			raw := desiredRequestJSON(t, tc.link, tc.version)
			code, out, stderr := runLifecycleTest(t, root, fake,
				[]string{"link", "ensure", "--stdin", "--json"}, raw)
			if code != 4 || stderr != "" || strings.Contains(out, "very_private_label") ||
				strings.Contains(out, string(tc.link.ID)) {
				t.Fatalf("unsupported request was misclassified/leaked: exit=%d out=%q err=%q",
					code, out, stderr)
			}
			var got linkReadErrorResponse
			if err := json.Unmarshal([]byte(out), &got); err != nil ||
				got.SchemaVersion != jsonSchemaVersion || got.Error == nil ||
				got.Error.Code != stlerr.CodeUnsupported {
				t.Fatalf("unsupported request lacks safe versioned error: %q %v", out, err)
			}
			if len(fake.applies) != 0 || len(fake.present) != 0 {
				t.Fatalf("unsupported request touched backend: %+v", fake)
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsupported request created state/locks: %v", err)
			}
		})
	}
}

// The exact v1 public JSON field set is an acceptance boundary. An internal
// domain field addition must not widen the request, and even an intentional
// addition to these wire structs must be accompanied by a schema decision.
func TestDesiredLinkV1WireContractFieldAllowlist(t *testing.T) {
	cases := []struct {
		name     string
		value    any
		expected []string
	}{
		{"request", desiredLinkRequestV1{}, []string{"schema_version", "link"}},
		{"link", desiredLinkV1{}, []string{
			"id", "display_name", "underlay", "addresses", "backend", "encapsulation", "gre",
		}},
		{"underlay", desiredUnderlayV1{}, []string{"local", "peer"}},
		{"addresses", desiredLinkAddressesV1{}, []string{"local", "peer"}},
		{"gre", desiredGREOptionsV1{}, []string{
			"key_enabled", "key", "ttl", "tos", "disable_pmtud", "checksum", "sequence", "udp_port",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ty := reflect.TypeOf(tc.value)
			got := make([]string, 0, ty.NumField())
			for i := 0; i < ty.NumField(); i++ {
				field := ty.Field(i)
				if !field.IsExported() {
					t.Fatalf("unexported field %s in public input wire struct", field.Name)
				}
				tag := strings.Split(field.Tag.Get("json"), ",")[0]
				if tag == "" || tag == "-" {
					t.Fatalf("missing/hidden JSON tag on %s", field.Name)
				}
				got = append(got, tag)
			}
			sort.Strings(got)
			sort.Strings(tc.expected)
			if !slices.Equal(got, tc.expected) {
				t.Fatalf("schema v1 field allowlist drift: got %v, want %v; review version compatibility", got, tc.expected)
			}
		})
	}
	for _, tc := range []struct {
		name string
		want reflect.Type
	}{
		{"Underlay", reflect.TypeOf(desiredUnderlayV1{})},
		{"Addresses", reflect.TypeOf(desiredLinkAddressesV1{})},
		{"GRE", reflect.TypeOf(desiredGREOptionsV1{})},
	} {
		field, ok := reflect.TypeOf(desiredLinkV1{}).FieldByName(tc.name)
		if !ok || field.Type != tc.want {
			t.Fatalf("nested %s must be the private frozen CLI v1 type, never a mutable domain type", tc.name)
		}
	}
}

func TestDesiredLinkV1PreservesAllGREOptionsAndEndpointValues(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected domain.Link
	}{
		{
			name: "FOU includes keyed zero and all applicable v1 options",
			raw:  `{"schema_version":1,"link":{"id":"lnk_77777777777777777777777777777777","display_name":"not_for_public_output","underlay":{"local":"192.0.2.10","peer":"192.0.2.20"},"addresses":{"local":"10.70.20.0/31","peer":"10.70.20.1/31"},"backend":"gre","encapsulation":"fou","gre":{"key_enabled":true,"key":0,"ttl":42,"tos":16,"disable_pmtud":false,"checksum":true,"sequence":true,"udp_port":4500}}}`,
			expected: domain.Link{
				ID:          "lnk_77777777777777777777777777777777",
				DisplayName: "not_for_public_output",
				Underlay: domain.Underlay{
					Local: netip.MustParseAddr("192.0.2.10"),
					Peer:  netip.MustParseAddr("192.0.2.20"),
				},
				Addresses: domain.LinkAddresses{
					Local: netip.MustParsePrefix("10.70.20.0/31"),
					Peer:  netip.MustParsePrefix("10.70.20.1/31"),
				},
				Backend: domain.BackendGRE, Encapsulation: domain.EncapFOU,
				GRE: domain.GREOptions{
					KeyEnabled: true, Key: 0, TTL: 42, TOS: 16, DisablePMTUD: false,
					Checksum: true, Sequence: true, UDPPort: 4500,
				},
			},
		},
		{
			name: "GUE preserves nonzero key and disable PMTUD",
			raw:  `{"schema_version":1,"link":{"id":"lnk_88888888888888888888888888888888","underlay":{"local":"192.0.2.11","peer":"192.0.2.22"},"addresses":{"local":"10.70.21.0/31","peer":"10.70.21.1/31"},"backend":"gre","encapsulation":"gue","gre":{"key_enabled":true,"key":4294967295,"ttl":0,"tos":0,"disable_pmtud":true,"checksum":false,"sequence":false,"udp_port":4501}}}`,
			expected: domain.Link{
				ID: "lnk_88888888888888888888888888888888",
				Underlay: domain.Underlay{
					Local: netip.MustParseAddr("192.0.2.11"),
					Peer:  netip.MustParseAddr("192.0.2.22"),
				},
				Addresses: domain.LinkAddresses{
					Local: netip.MustParsePrefix("10.70.21.0/31"),
					Peer:  netip.MustParsePrefix("10.70.21.1/31"),
				},
				Backend: domain.BackendGRE, Encapsulation: domain.EncapGUE,
				GRE: domain.GREOptions{KeyEnabled: true, Key: 4294967295, DisablePMTUD: true, UDPPort: 4501},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeDesiredLink(strings.NewReader(tc.raw))
			if err != nil {
				t.Fatalf("canonical v1 input rejected: %v", err)
			}
			if decoded != tc.expected {
				t.Fatalf("v1 to domain conversion lost or changed config: got %+v want %+v", decoded, tc.expected)
			}
			// Exercise the actual new CLI boundary, not only the helper.
			root := filepath.Join(t.TempDir(), "state")
			fake := newLifecycleFake()
			code, out, stderr := runLifecycleTest(t, root, fake, []string{"link", "ensure", "--stdin", "--json"}, tc.raw)
			if code != 0 || stderr != "" || strings.Contains(out, "not_for_public_output") || len(fake.applies) != 1 {
				t.Fatalf("v1 request did not traverse canonical Engine safely: %d %q %q", code, out, stderr)
			}
			snapshot, err := state.NewFileStore(root).Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			stored, ok := snapshot.Find(tc.expected.ID)
			if !ok || stored.Desired != tc.expected {
				t.Fatalf("canonical Engine did not persist exact mapped v1 Link: found=%v got=%+v", ok, stored.Desired)
			}
		})
	}
}

func TestDesiredLinkV1RejectsUnknownNestedDomainExtensionsBeforeRuntime(t *testing.T) {
	// A future field in internal/domain may be valid in the internal state
	// format; it must NOT become part of the public CLI v1 input automatically.
	base := `{"schema_version":1,"link":{"id":"lnk_99999999999999999999999999999999","underlay":{"local":"192.0.2.10","peer":"192.0.2.20"},"addresses":{"local":"10.70.22.0/31","peer":"10.70.22.1/31"},"backend":"gre","encapsulation":"fou","gre":{"key_enabled":true,"key":7,"udp_port":4500}}}`
	cases := []struct {
		name        string
		old         string
		replacement string
	}{
		{"future underlay field", `"peer":"192.0.2.20"`, `"peer":"192.0.2.20","source_ifindex":123`},
		{"future Link Address field", `"peer":"10.70.22.1/31"`, `"peer":"10.70.22.1/31","gateway":"10.70.22.7"`},
		{"future GRE credential field", `"udp_port":4500`, `"udp_port":4500,"private_key":"NEVER_EXPOSE_TO_CLIENT"`},
		{"future GRE encryption switch", `"udp_port":4500`, `"udp_port":4500,"future_crypto":true`},
		{"future link field", `"encapsulation":"fou"`, `"encapsulation":"fou","interface_name":"foreign0"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(base, tc.old) {
				t.Fatalf("missing test anchor %s", tc.old)
			}
			payload := strings.Replace(base, tc.old, tc.replacement, 1)
			root := filepath.Join(t.TempDir(), "no-state")
			fake := newLifecycleFake()
			code, out, stderr := runLifecycleTest(t, root, fake, []string{"link", "ensure", "--stdin", "--json"}, payload)
			if code != 2 || stderr != "" || strings.Contains(out, "NEVER_EXPOSE_TO_CLIENT") ||
				strings.Contains(out, "foreign0") || strings.Contains(out, "future_crypto") {
				t.Fatalf("schema v1 accidentally admitted unknown nested field: code=%d out=%q err=%q", code, out, stderr)
			}
			var response linkReadErrorResponse
			if err := json.Unmarshal([]byte(out), &response); err != nil ||
				response.SchemaVersion != jsonSchemaVersion || response.Error == nil ||
				response.Error.Code != stlerr.CodeInvalid {
				t.Fatalf("unknown input lacked redacted versioned invalid response: %q", out)
			}
			if len(fake.applies) != 0 || len(fake.present) != 0 {
				t.Fatalf("unknown nested v1 field reached backend: %+v", fake)
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unknown field created state/locks: %v", err)
			}
		})
	}
}
