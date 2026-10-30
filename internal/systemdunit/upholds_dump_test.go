package systemdunit

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const legacyDumpFixture = `Manager: systemd 249 (249.11-0ubuntu3)
Features: +PAM +AUDIT
-> Unit unrelated.service:
	Unit Load State: loaded
	Unit Active State: active
	Upholds: unrelated-child.service (origin-file)
	StopWhenUnneeded: no
-> Unit selected.service:
	Unit Load State: loaded
	Unit Active State: active
	Need Daemon Reload: no
	Transient: yes
	Fragment Path: /run/systemd/transient/selected.service
	StopWhenUnneeded: no
`

func TestParseVersionStrictManagerProperty(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"Version=247.3-7~deb11u9\n", 247},
		{"Version=248\n", 248},
		{"Version=249.11-0ubuntu3.17\n", 249},
		{"Version=250.1\n", 250},
		{"Version=251\n", 251},
		{"Version=259\n", 259},
		{"Version=249fake\n", 0},
		{"Version=249\nVersion=250\n", 0},
		{"Version=249 \n", 0},
		{"Version=249\x00\n", 0},
		{"Version=-249\n", 0},
		{"Version=2499\n", 0},
		{"Version=25\n", 0},
		{"Version=249", 0},
		{"systemd 249 (249.11)\n", 0},
	} {
		t.Run(fmt.Sprintf("%q", tc.raw), func(t *testing.T) {
			got, ok := ParseVersion([]byte(tc.raw))
			if got != tc.want || ok != (tc.want != 0) {
				t.Fatalf("parsed version=%d valid=%v; want=%d", got, ok, tc.want)
			}
		})
	}
}

func TestLegacyUnitSnapshotPreservesPresenceAndConditionalIdentity(t *testing.T) {
	for _, version := range []int{249, 250} {
		dump := strings.Replace(legacyDumpFixture, "systemd 249 (", fmt.Sprintf("systemd %d (", version), 1)
		observed, err := ParseLegacyManagerDump(strings.NewReader(dump), version, "selected.service")
		if err != nil || !observed.Present || len(observed.Fields) != 6 ||
			observed.Fields["Transient"] != "yes" || observed.Fields["Fragment Path"] != "/run/systemd/transient/selected.service" ||
			observed.IncomingUpholds || observed.OutgoingUpholds {
			t.Fatalf("selected legacy unit identity mismatch: %+v %v", observed, err)
		}
	}
	stub := strings.Replace(legacyDumpFixture, "\tUnit Load State: loaded\n\tUnit Active State: active\n\tNeed Daemon Reload: no\n\tTransient: yes\n\tFragment Path: /run/systemd/transient/selected.service\n\tStopWhenUnneeded: no\n",
		"\tUnit Load State: not-found\n\tUnit Active State: inactive\n\tNeed Daemon Reload: no\n\tTransient: no\n", 1)
	observed, err := ParseLegacyManagerDump(strings.NewReader(stub), 249, "selected.service")
	if err != nil || !observed.Present || len(observed.Fields) != 4 || observed.Fields["Unit Load State"] != "not-found" {
		t.Fatalf("conditional v249 fields were made mandatory for unloaded stub: %+v %v", observed, err)
	}
	if _, exists := observed.Fields["Fragment Path"]; exists {
		t.Fatal("absent conditional fragment was fabricated as present empty")
	}
	emptyFragment := stub + "\tFragment Path: \n"
	observed, err = ParseLegacyManagerDump(strings.NewReader(emptyFragment), 249, "selected.service")
	if value, exists := observed.Fields["Fragment Path"]; err != nil || !exists || value != "" {
		t.Fatal("present empty conditional field lost its presence evidence")
	}
	observed, err = ParseLegacyManagerDump(strings.NewReader(legacyDumpFixture), 249, "garbage-collected.service")
	if err != nil || observed.Present || len(observed.Fields) != 0 || observed.IncomingUpholds || observed.OutgoingUpholds {
		t.Fatalf("complete source observation could not represent absent selected unit: %+v %v", observed, err)
	}
}

func TestLegacyUnitSnapshotTracksOnlyRelevantDependencyDirections(t *testing.T) {
	for _, tc := range []struct {
		name, dump         string
		incoming, outgoing bool
	}{
		{"unrelated", legacyDumpFixture, false, false},
		{"global-forward", strings.Replace(legacyDumpFixture, "Upholds: unrelated-child.service", "Upholds: selected.service", 1), true, false},
		{"alias-forward", strings.Replace(legacyDumpFixture, "Upholds: unrelated-child.service", "Upholds: selected-alias.service", 1), true, false},
		{"selected-reverse", legacyDumpFixture + "\tUpheldBy: owner.service (destination-file)\n", true, false},
		{"selected-forward", legacyDumpFixture + "\tUpholds: child.service (origin-file)\n", false, true},
		{"global-reverse", strings.Replace(legacyDumpFixture, "Upholds: unrelated-child.service", "UpheldBy: selected.service", 1), false, true},
		{"unrelated-reverse", strings.Replace(legacyDumpFixture, "Upholds: unrelated-child.service", "UpheldBy: unrelated-parent.service", 1), false, false},
		{"similar-name", strings.Replace(legacyDumpFixture, "Upholds: unrelated-child.service", "Upholds: selected.service.other", 1), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed, err := ParseLegacyManagerDump(strings.NewReader(tc.dump), 249, "selected.service", "selected-alias.service")
			if err != nil || observed.IncomingUpholds != tc.incoming || observed.OutgoingUpholds != tc.outgoing {
				t.Fatalf("dependency direction or exact selected identity lost: %+v %v", observed, err)
			}
		})
	}
	// GC can remove a not-found target between property and dump queries.
	// A remaining forward reference must still block the target's admission.
	absent := strings.Replace(legacyDumpFixture, "Upholds: unrelated-child.service", "Upholds: absent.service", 1)
	observed, err := ParseLegacyManagerDump(strings.NewReader(absent), 249, "absent.service")
	if err != nil || observed.Present || !observed.IncomingUpholds {
		t.Fatalf("global reference disappeared with an absent selected block: %+v %v", observed, err)
	}
}

func TestLegacyUnitSnapshotFailsClosedOnMalformedOrIncompleteSources(t *testing.T) {
	for _, tc := range []struct {
		name, dump string
		version    int
	}{
		{"version-drift", legacyDumpFixture, 250},
		{"unsupported-version", legacyDumpFixture, 251},
		{"missing-final-newline", strings.TrimSuffix(legacyDumpFixture, "\n"), 249},
		{"duplicate-manager", legacyDumpFixture + "Manager: systemd 249 (249.11)\n", 249},
		{"duplicate-unit", legacyDumpFixture + "-> Unit selected.service:\n", 249},
		{"duplicate-unrelated", legacyDumpFixture + "-> Unit unrelated.service:\n", 249},
		{"duplicate-field", legacyDumpFixture + "\tUnit Load State: loaded\n", 249},
		{"duplicate-transient", legacyDumpFixture + "\tTransient: yes\n", 249},
		{"missing-core-identity", strings.Replace(legacyDumpFixture, "\tNeed Daemon Reload: no\n", "", 1), 249},
		{"field-delimiter", strings.Replace(legacyDumpFixture, "\tNeed Daemon Reload: no", "\tNeed Daemon Reload:no", 1), 249},
		{"nul", legacyDumpFixture + "\x00\n", 249},
		{"carriage-return", strings.Replace(legacyDumpFixture, "Features:", "Features:\r", 1), 249},
		{"malformed-section", legacyDumpFixture + "-> Unit selected.service\n", 249},
		{"incomplete-header", "Manager: systemd 249 (249.11)\n", 249},
		{"header-only", "Manager: systemd 249 (249.11)\nFeatures: +PAM\n", 249},
		{"long-line", legacyDumpFixture + strings.Repeat("X", 1024*1024) + "\n", 249},
		{"edge-missing-origin", legacyDumpFixture + "\tUpheldBy: owner.service\n", 249},
		{"edge-wrong-indent", legacyDumpFixture + " UpheldBy: owner.service (destination-file)\n", 249},
		{"edge-extra-origin", legacyDumpFixture + "\tUpheldBy: owner.service (destination-file)(extra)\n", 249},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseLegacyManagerDump(strings.NewReader(tc.dump), tc.version, "selected.service"); err == nil {
				t.Fatal("malformed or incomplete manager snapshot accepted")
			}
		})
	}
	reader := io.MultiReader(strings.NewReader(legacyDumpFixture), failingDumpReader{})
	if _, err := ParseLegacyManagerDump(reader, 249, "selected.service"); err == nil || strings.Contains(err.Error(), "PRIVATE_DUMP_DETAIL") {
		t.Fatal("reader failure was accepted or source content escaped through diagnostics")
	}
}

type failingDumpReader struct{}

func (failingDumpReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_DUMP_DETAIL") }

func TestLegacyUnitSnapshotStreamsWithoutHostUnitCountOrTotalOutputQuota(t *testing.T) {
	var dump strings.Builder
	dump.WriteString(legacyDumpFixture)
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&dump, "-> Unit unrelated-%d.service:\n\tUnit Load State: loaded\n\tUnit Active State: inactive\n\tNeed Daemon Reload: no\n\tStopWhenUnneeded: no\n", i)
	}
	observed, err := ParseLegacyManagerDump(strings.NewReader(dump.String()), 249, "selected.service")
	if err != nil || !observed.Present || observed.IncomingUpholds || observed.OutgoingUpholds {
		t.Fatalf("bounded streaming parser imposed a host-wide unit/output quota: %v", err)
	}
}
