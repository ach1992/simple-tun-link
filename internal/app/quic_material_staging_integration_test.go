package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
)

// This deliberately opt-in integration test exercises the real PUBLIC Engine
// entry point, private FileStore, pinned official executable admission and
// protected-file publication together. It never runs the helper, touches a
// live Link, or changes Linux host networking. CI without an approved binary
// fixture keeps running the hermetic tests instead.
func TestPinnedHysteriaCanonicalEngineMaterialStagingWhenAvailable(t *testing.T) {
	binary := os.Getenv("STL_QUIC_HYSTERIA_BIN")
	if binary == "" {
		t.Skip("requires separately supplied official SHA-256-pinned Hysteria binary")
	}
	if _, err := quic.InspectPinnedHysteria(binary); err != nil {
		t.Fatalf("provided executable failed official pinned admission: %v", err)
	}

	for _, role := range []composition.Role{composition.Dial, composition.Listen} {
		t.Run(string(role), func(t *testing.T) {
			ctx := context.Background()
			backend := newFakeBackend()
			engine, store := newEngine(t, backend)
			intent := materialJournalForRole(role)

			listener, dialer, err := quic.GeneratePair(intent.Plan.Local.LinkID, intent.Plan.TLSName)
			if err != nil {
				t.Fatal("could not issue isolated role-specific credentials")
			}
			defer listener.Clear()
			defer dialer.Clear()
			bundle := listener
			if role == composition.Dial {
				bundle = dialer
			}

			local := intent.Plan.Local
			plan := quic.Plan{
				LinkID: local.LinkID, Role: quic.Role(local.Role),
				Underlay: intent.Plan.Physical, TLSName: intent.Plan.TLSName,
			}
			switch role {
			case composition.Dial:
				plan.LocalForwardUDPPort = local.LocalHelperUDPPort
				plan.PeerWGUDPPort = local.RemoteWGUDPPort
			case composition.Listen:
				plan.LocalWGUDPPort = local.LocalWGUDPPort
			}
			if roundTrip, err := plan.HostPlan(local.LocalWGUDPPort); err != nil || roundTrip != intent.Plan {
				t.Fatal("isolated canonical Plan fixture did not round-trip")
			}

			expected, err := quic.PreviewHelperConfig(store.RootDir(), plan,
				local.LocalWGUDPPort, binary, bundle)
			if err != nil {
				t.Fatalf("official protected-material preview refused isolated fixture: %v", err)
			}
			intent.CertificateSHA256 = expected.Credentials.CertificateSHA256
			intent.TrustCASHA256 = expected.Credentials.TrustCASHA256
			intent.AuthorizationSHA256 = expected.Credentials.AuthorizationSHA256
			intent.HelperConfigSHA256 = expected.ConfigSHA256
			intent.ExecutablePath = binary
			intent.ExecutableSHA256 = expected.Executable.SHA256
			intent.ExecutableDevice = expected.Executable.Device
			intent.ExecutableInode = expected.Executable.Inode

			prepared, err := engine.PrepareQUICCrash(ctx, intent, &quicVacancyProbe{})
			if err != nil {
				t.Fatalf("could not persist exact pre-effect journal: %v", err)
			}
			before, err := store.Load(ctx)
			if err != nil {
				t.Fatal("could not reload durable pre-effect journal")
			}
			privateDir := filepath.Join(store.RootDir(), "credentials", "quic", string(local.LinkID))
			if _, err := os.Lstat(privateDir); !os.IsNotExist(err) {
				t.Fatal("preview or journal preparation unexpectedly published private files")
			}

			if err := engine.StageQUICCrashMaterials(ctx, local.LinkID, bundle); err != nil {
				t.Fatalf("canonical public Engine staging failed: %v", err)
			}
			if err := engine.InspectQUICCrashMaterials(ctx, local.LinkID); err != nil {
				t.Fatalf("canonical public Engine material inspection failed: %v", err)
			}
			actual, err := quic.InspectHelperConfig(store.RootDir(), plan,
				local.LocalWGUDPPort, binary)
			if err != nil || actual != expected {
				t.Fatalf("protected readback does not equal all seven journal identities: %v", err)
			}

			expectedNames := map[string]bool{
				"authorization-token": true, "helper.json": true,
				"generation-owner.json": true,
			}
			if role == composition.Listen {
				expectedNames["server-cert.pem"] = true
				expectedNames["server-key.pem"] = true
				expectedNames["client-ca.pem"] = true
			} else {
				expectedNames["client-cert.pem"] = true
				expectedNames["client-key.pem"] = true
				expectedNames["server-ca.pem"] = true
			}
			dirInfo, err := os.Lstat(privateDir)
			if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0o700 {
				t.Fatal("protected QUIC directory is missing or not private")
			}
			entries, err := os.ReadDir(privateDir)
			if err != nil || len(entries) != len(expectedNames) {
				t.Fatal("protected QUIC directory has missing or unexpected artifacts")
			}
			original := make(map[string]os.FileInfo, len(expectedNames))
			for _, entry := range entries {
				if !expectedNames[entry.Name()] {
					t.Fatal("unexpected protected artifact published")
				}
				info, err := os.Lstat(filepath.Join(privateDir, entry.Name()))
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
					t.Fatal("published protected artifact is not a private regular file")
				}
				original[entry.Name()] = info
			}

			// Retrying the same exact generation must converge without
			// replacing private inodes or consuming the unresolved journal.
			if err := engine.StageQUICCrashMaterials(ctx, local.LinkID, bundle); err != nil {
				t.Fatalf("identical protected Engine staging did not converge: %v", err)
			}
			for name, old := range original {
				current, err := os.Lstat(filepath.Join(privateDir, name))
				if err != nil || !os.SameFile(old, current) {
					t.Fatal("identical staging replaced a protected inode")
				}
			}
			after, err := store.Load(ctx)
			if err != nil || !reflect.DeepEqual(before, after) || len(after.QUICCrashOperations) != 1 ||
				after.QUICCrashOperations[0].Nonce != prepared.Nonce ||
				backend.applyCount != 0 || len(backend.present) != 0 {
				t.Fatal("source-only Engine staging changed journal, committed Links or backend effects")
			}
		})
	}
}
