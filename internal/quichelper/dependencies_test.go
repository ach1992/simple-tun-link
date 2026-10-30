package quichelper

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/systemdunit"
)

func vacantProperties(s unitSpec) map[string]string {
	return map[string]string{
		"Id": s.Name, "Names": s.Name, "LoadState": "not-found", "ActiveState": "inactive",
		"SubState": "dead", "Transient": "no", "Description": s.Name, "FragmentPath": "",
		"Environment": "", "CollectMode": "inactive", "MainPID": "0", "ExecMainPID": "0",
		"Restart": "no", "NeedDaemonReload": "no", "TriggeredBy": "", "Upholds": "", "UpheldBy": "",
	}
}

func TestDependencyPropertyCapabilityDoesNotTreatMissingAsEmpty(t *testing.T) {
	spec := testUnitSpec(t)
	for _, properties := range []map[string]string{vacantProperties(spec), runningProperties(spec)} {
		if fallback, err := unitDependencyFallbackRequired(properties); err != nil || fallback {
			t.Fatalf("explicit empty dependency receipt rejected: fallback=%t err=%v", fallback, err)
		}
		for _, missing := range []string{"Upholds", "UpheldBy"} {
			changed := cloneProperties(properties)
			delete(changed, missing)
			fallback, err := unitDependencyFallbackRequired(changed)
			if err != nil || !fallback {
				t.Fatal("missing relationship was accepted without manager capability proof")
			}
			for _, modern := range []string{"Version=251\n", "Version=257.13-1~deb13u1\n", "Version=259\n"} {
				if _, err := legacyDependencyVersion([]byte(modern)); err == nil {
					t.Fatal("missing modern relationship was treated as legacy absence")
				}
			}
		}
		for _, key := range []string{"Upholds", "UpheldBy", "TriggeredBy", "Sockets"} {
			for _, foreign := range []string{"foreign.service", " "} {
				changed := cloneProperties(properties)
				changed[key] = foreign
				if _, err := unitDependencyFallbackRequired(changed); err == nil {
					t.Fatalf("foreign dependency %s was accepted", key)
				}
			}
		}
		changed := cloneProperties(properties)
		delete(changed, "TriggeredBy")
		if _, err := unitDependencyFallbackRequired(changed); err == nil {
			t.Fatal("missing activation relationship was accepted")
		}
		// Sockets is not a D-Bus property. The explicit TriggeredBy receipt,
		// not this omitted directive, proves no socket/path/timer activation.
		delete(properties, "Sockets")
		if fallback, err := unitDependencyFallbackRequired(properties); err != nil || fallback {
			t.Fatal("unexported Sockets directive defeated effective TriggeredBy evidence")
		}
	}
	for _, legacy := range []string{"Version=249.11-0ubuntu3.17\n", "Version=250.1\n"} {
		if _, err := legacyDependencyVersion([]byte(legacy)); err != nil {
			t.Fatal("supported legacy capability was rejected")
		}
	}
	for _, bad := range []string{"", "Version=248\n", "Version=249fake\n", "Version=249\nVersion=250\n", "Version=249"} {
		if _, err := legacyDependencyVersion([]byte(bad)); err == nil {
			t.Fatal("unproven legacy dependency capability accepted")
		}
	}
}

func TestNotFoundUnitWithForeignActivationIsNeverVacant(t *testing.T) {
	spec := testUnitSpec(t)
	if err := verifyUnitVacant(vacantProperties(spec), spec); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"Upholds", "UpheldBy", "TriggeredBy", "Sockets", "NeedDaemonReload"} {
		values := vacantProperties(spec)
		values[key] = "foreign.service"
		if key == "NeedDaemonReload" {
			values[key] = "yes"
		}
		if err := verifyUnitVacant(values, spec); err == nil {
			t.Fatalf("not-found unit with %s was accepted as vacant", key)
		}
	}
}

func legacyGraphFixture(spec unitSpec, vacant bool) string {
	load, active, transient := "loaded", "active", "yes"
	conditional := "\tFragment Path: /run/systemd/transient/" + spec.Name + "\n\tStopWhenUnneeded: no\n"
	if vacant {
		load, active, transient, conditional = "not-found", "inactive", "no", ""
	}
	return "Manager: systemd 249 (249.11-0ubuntu3.17)\nFeatures: +PAM +AUDIT\n" +
		"-> Unit unrelated.service:\n\tUnit Load State: loaded\n\tUnit Active State: active\n" +
		"\tUpholds: unrelated-child.service (origin-file)\n" +
		"-> Unit " + spec.Name + ":\n\tUnit Load State: " + load + "\n\tUnit Active State: " + active +
		"\n\tNeed Daemon Reload: no\n\tTransient: " + transient + "\n" + conditional +
		"-> Unit unrelated.target:\n\tUnit Load State: loaded\n\tUnit Active State: active\n"
}

func parseAndVerifyLegacyGraph(dump string, spec unitSpec, vacant bool) error {
	snapshot, err := systemdunit.ParseLegacyManagerDump(strings.NewReader(dump), 249, spec.Name)
	if err != nil {
		return err
	}
	return verifyLegacyUnitGraph(snapshot, spec, vacant)
}

func TestLegacyDependencyGraphBindsVacancyAndOriginalIdentity(t *testing.T) {
	spec := testUnitSpec(t)
	cleanVacant := legacyGraphFixture(spec, true)
	cleanLive := legacyGraphFixture(spec, false)
	for _, tc := range []struct {
		name, dump    string
		vacant, allow bool
	}{
		{"clean-not-found", cleanVacant, true, true},
		{"clean-loaded-original", cleanLive, false, true},
		{"incoming-while-not-found", strings.Replace(cleanVacant, "Upholds: unrelated-child.service", "Upholds: "+spec.Name, 1), true, false},
		{"selected-reverse-while-not-found", strings.Replace(cleanVacant, "\tTransient: no\n", "\tTransient: no\n\tUpheldBy: foreign.service (destination-file)\n", 1), true, false},
		{"outgoing-while-not-found", strings.Replace(cleanVacant, "\tTransient: no\n", "\tTransient: no\n\tUpholds: foreign.service (origin-file)\n", 1), true, false},
		{"incoming-live", strings.Replace(cleanLive, "Upholds: unrelated-child.service", "Upholds: "+spec.Name, 1), false, false},
		{"foreign-fragment", strings.Replace(cleanLive, "/run/systemd/transient/", "/etc/systemd/system/", 1), false, false},
		{"nontransient-live", strings.Replace(cleanLive, "\tTransient: yes", "\tTransient: no", 1), false, false},
		{"pending-reload", strings.Replace(cleanLive, "\tNeed Daemon Reload: no", "\tNeed Daemon Reload: yes", 1), false, false},
		{"missing-loaded-terminator", strings.Replace(cleanLive, "\tStopWhenUnneeded: no\n", "", 1), false, false},
		{"fragment-on-not-found", strings.Replace(cleanVacant, "\tTransient: no\n", "\tTransient: no\n\tFragment Path: \n", 1), true, false},
		{"loaded-field-on-not-found", strings.Replace(cleanVacant, "\tTransient: no\n", "\tTransient: no\n\tStopWhenUnneeded: no\n", 1), true, false},
		{"truncated-stream", strings.TrimSuffix(cleanVacant, "\n"), true, false},
		{"missing-manager-version", strings.Replace(cleanVacant, "systemd 249 (", "systemd 257 (", 1), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := parseAndVerifyLegacyGraph(tc.dump, spec, tc.vacant)
			if (err == nil) != tc.allow {
				t.Fatalf("legacy dependency result allowed=%t want=%t err=%v", err == nil, tc.allow, err)
			}
		})
	}
	// A collected empty stub is different from an absent original process.
	absent := strings.Replace(cleanVacant, "-> Unit "+spec.Name+":", "-> Unit different.service:", 1)
	if err := parseAndVerifyLegacyGraph(absent, spec, true); err != nil {
		t.Fatal("complete clean dump rejected a collected vacant stub")
	}
	if err := parseAndVerifyLegacyGraph(absent, spec, false); err == nil {
		t.Fatal("absent live unit was accepted as original")
	}
	for _, relation := range []string{"Upholds", "UpheldBy"} {
		foreign := strings.Replace(absent, "\tUpholds: unrelated-child.service (origin-file)", "\t"+relation+": "+spec.Name+" (origin-file)", 1)
		if err := parseAndVerifyLegacyGraph(foreign, spec, true); err == nil {
			t.Fatal("targeting edge hidden by absent selected block")
		}
	}
}

func TestForeignUpholderPreflightCannotPublishAttemptOrStart(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy-%t", legacy), func(t *testing.T) {
			fixture := newOriginFixture(t)
			prior := fixture.ops.preflight
			fixture.ops.preflight = func(ctx context.Context, spec unitSpec) (hostIdentity, error) {
				host, err := prior(ctx, spec)
				if err != nil {
					return host, err
				}
				if legacy {
					dump := strings.Replace(legacyGraphFixture(spec, true), "Upholds: unrelated-child.service", "Upholds: "+spec.Name, 1)
					return host, parseAndVerifyLegacyGraph(dump, spec, true)
				}
				values := vacantProperties(spec)
				values["UpheldBy"] = "foreign.service"
				return host, verifyUnitVacant(values, spec)
			}
			if _, err := startAdmitted(context.Background(), fixture.root, fixture.plan, fixture.op, fixture.ops); err == nil {
				t.Fatal("foreign upholder reached original activation")
			}
			if fixture.starts != 0 || markerExists(t, fixture, false) || markerExists(t, fixture, true) {
				t.Fatal("foreign upholder caused a dispatch or receipt publication")
			}
		})
	}
}

func inspectTestUnitDirectory(ctx context.Context, root, name string) error {
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return inspectUnitReferenceDirectory(ctx, directory, name, true, uint32(os.Geteuid()))
}

func TestInstalledReverseDependenciesAndAliasesBlockAbsentTarget(t *testing.T) {
	const selected = "stl-quic-1234567890.service"
	for _, kind := range []string{"wants", "requires", "upholds", "edge-alias", "unit-alias", "symlink-directory", "writable-directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			edge := filepath.Join(root, "foreign.target.upholds")
			if kind == "wants" || kind == "requires" || kind == "upholds" {
				edge = filepath.Join(root, "foreign.target."+kind)
			}
			if kind == "unit-alias" {
				if err := os.Symlink("/missing/"+selected, filepath.Join(root, "foreign-alias.service")); err != nil {
					t.Fatal(err)
				}
			} else if kind == "symlink-directory" {
				if err := os.Symlink(t.TempDir(), edge); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(edge, 0o700); err != nil {
					t.Fatal(err)
				}
				if kind == "writable-directory" {
					if err := os.Chmod(edge, 0o777); err != nil {
						t.Fatal(err)
					}
				} else {
					entry := selected
					if kind == "edge-alias" {
						entry = "foreign-alias.service"
					}
					if err := os.Symlink("/missing/"+selected, filepath.Join(edge, entry)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := inspectTestUnitDirectory(context.Background(), root, selected); err == nil {
				t.Fatal("dormant foreign dependency was accepted while its target was absent")
			}
		})
	}
}

type cancelAfterChecks struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (ctx *cancelAfterChecks) Err() error {
	ctx.remaining--
	if ctx.remaining == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestReverseDependencyInventoryUsesChunksAndCancellationNotUnitQuota(t *testing.T) {
	const selected = "stl-quic-1234567890.service"
	root := t.TempDir()
	// More than the old vendor inventory's 128-edge count and multiple
	// reader chunks must remain valid when all dependencies are unrelated.
	for i := 0; i < 137; i++ {
		edge := filepath.Join(root, fmt.Sprintf("unrelated-%03d.target.upholds", i))
		if err := os.Mkdir(edge, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/missing/unrelated.service", filepath.Join(edge, "different.service")); err != nil {
			t.Fatal(err)
		}
	}
	if err := inspectTestUnitDirectory(context.Background(), root, selected); err != nil {
		t.Fatalf("unrelated unit count became an admission quota: %v", err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	duringScan := &cancelAfterChecks{Context: base, cancel: cancel, remaining: 6}
	if err := inspectTestUnitDirectory(duringScan, root, selected); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("inventory ignored cancellation during traversal: %v", err)
	}
	if err := inspectTestUnitDirectory(base, root, selected); err == nil {
		t.Fatal("already-canceled inventory was admitted")
	}
	if err := os.Symlink("/missing/"+selected, filepath.Join(root, "unrelated-136.target.upholds", selected)); err != nil {
		t.Fatal(err)
	}
	if err := inspectTestUnitDirectory(context.Background(), root, selected); err == nil {
		t.Fatal("foreign edge past the first chunk was not inspected")
	}
}

func cloneProperties(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
