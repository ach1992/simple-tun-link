package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/version"
)

const (
	menuOfficialReleasesURL = "https://api.github.com/repos/ach1992/simple-tun-link/releases?per_page=15"
	menuUpdatedExecutable   = 106 // internal menu loop sentinel; never a CLI exit status
	menuReleaseBytesLimit   = 256 * 1024
)

var menuReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$`)
var menuRCVersion = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)-rc\.([0-9]+)$`)
var menuStableVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type menuOfficialRelease struct {
	ID          int64     `json:"id"`
	Immutable   *bool     `json:"immutable"`
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name  string `json:"name"`
		Size  int64  `json:"size"`
		State string `json:"state"`
	} `json:"assets"`
}

// A release's asset names alone are NOT source trust. GitHub guarantees
// tag/asset immutability only for explicitly immutable published releases;
// unknown or mutable releases remain visible but cannot run a root updater.
func menuReleaseImmutable(release menuOfficialRelease) bool {
	return release.ID > 0 && release.Immutable != nil && *release.Immutable
}

func menuReleaseComplete(release menuOfficialRelease) bool {
	if release.Draft || release.PublishedAt.IsZero() ||
		!menuReleaseTag.MatchString(release.TagName) {
		return false
	}
	names := make(map[string]bool, len(release.Assets))
	for _, asset := range release.Assets {
		if asset.Size > 0 && asset.State == "uploaded" {
			names[asset.Name] = true
		}
	}
	for _, want := range []string{
		"stl_" + release.TagName + "_linux_amd64",
		"stl_" + release.TagName + "_linux_arm64",
		"BUILD-MANIFEST.txt", "SHA256SUMS", "LICENSE",
	} {
		if !names[want] {
			return false
		}
	}
	return true
}

// The only remote input is GitHub's official releases API at a fixed
// HTTPS origin. Tag names become arguments/data, NEVER executable shell.
// No credentials, state, systemctl calls or kernel reads are sent.
func fetchMenuOfficialReleases(ctx context.Context, client *http.Client, endpoint string) ([]menuOfficialRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "simple-tun-link-operator")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release catalogue returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, menuReleaseBytesLimit+1))
	if err != nil || len(body) > menuReleaseBytesLimit {
		return nil, errors.New("release catalogue could not be read within size limit")
	}
	var raw []menuOfficialRelease
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("release catalogue is not valid JSON: %w", err)
	}
	got := make([]menuOfficialRelease, 0, len(raw))
	seen := map[string]bool{}
	for _, release := range raw {
		if !menuReleaseComplete(release) || seen[release.TagName] {
			continue
		}
		seen[release.TagName] = true
		got = append(got, release)
	}
	sort.SliceStable(got, func(i, j int) bool {
		return got[i].PublishedAt.After(got[j].PublishedAt)
	})
	if len(got) > 10 {
		got = got[:10]
	}
	if len(got) == 0 {
		return nil, errors.New("no verified complete public release was found")
	}
	return got, nil
}

func menuPublicReleases(ctx context.Context, options *runtimeOptions) ([]menuOfficialRelease, error) {
	if options != nil && options.menuReleases != nil {
		return options.menuReleases(ctx)
	}
	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || len(via) > 2 {
				return errors.New("release API redirected outside trusted origin")
			}
			return nil
		},
	}
	return fetchMenuOfficialReleases(ctx, client, menuOfficialReleasesURL)
}

// RC updates are limited to forward candidates on the same major/minor/patch
// release line. Stable patch updates have their own strictly forward gate.
// New major/minor lines need migration review, never a silent downgrade.
func menuRCUpgrade(current, target string) bool {
	a, b := menuRCVersion.FindStringSubmatch(current), menuRCVersion.FindStringSubmatch(target)
	if len(a) != 5 || len(b) != 5 {
		return false
	}
	for i := 1; i <= 3; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	oldRC, errOld := strconv.ParseUint(a[4], 10, 32)
	newRC, errNew := strconv.ParseUint(b[4], 10, 32)
	return errOld == nil && errNew == nil && newRC > oldRC
}

// Stable patches within the same major/minor line are eligible for the
// canonical updater. Reject cross-line migrations, prereleases, downgrades,
// ambiguous leading-zero components, and overflowing patch versions.
func menuStablePatchUpgrade(current, target string) bool {
	a, b := menuStableVersion.FindStringSubmatch(current), menuStableVersion.FindStringSubmatch(target)
	if len(a) != 4 || len(b) != 4 || a[1] != b[1] || a[2] != b[2] {
		return false
	}
	oldPatch, oldErr := strconv.ParseUint(a[3], 10, 64)
	newPatch, newErr := strconv.ParseUint(b[3], 10, 64)
	return oldErr == nil && newErr == nil && newPatch > oldPatch
}

// Release type is checked independently of the tag spelling; the official
// immutable-release and installed-root/TTY gates remain separate and required.
func menuForwardMenuUpgrade(current string, release menuOfficialRelease) bool {
	if release.Prerelease {
		return menuRCUpgrade(current, release.TagName)
	}
	return menuStablePatchUpgrade(current, release.TagName)
}

// Only verified same-line older Stable releases whose historical State
// reader is explicitly known may be selected for a controlled downgrade.
func menuStablePatchDowngrade(current, target string) bool {
	a, b := menuStableVersion.FindStringSubmatch(current), menuStableVersion.FindStringSubmatch(target)
	if len(a) != 4 || len(b) != 4 || a[1] != b[1] || a[2] != b[2] {
		return false
	}
	previous, e1 := strconv.ParseUint(a[3], 10, 64)
	selected, e2 := strconv.ParseUint(b[3], 10, 64)
	_, contract := publishedStateSchema(target)
	return e1 == nil && e2 == nil && contract == nil && selected < previous
}

func menuCanUpdateNow(input io.Reader, out io.Writer) bool {
	in, inOK := input.(*os.File)
	_, outOK := menuTerminal(out)
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	realExecutable, err := filepath.EvalSymlinks(executable)
	return inOK && input == os.Stdin && out == os.Stdout && terminalIsInteractive(in) &&
		outOK && err == nil && os.Geteuid() == 0 && realExecutable == "/usr/local/bin/stl"
}

// Check the installed program's version metadata after the canonical
// updater returns. It is not an independent supply-chain attestation.
func menuInstalledVersionMatches(raw []byte, tag string) bool {
	var found struct {
		SchemaVersion int    `json:"schema_version"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
	}
	if err := json.Unmarshal(raw, &found); err != nil {
		return false
	}
	return found.SchemaVersion == jsonSchemaVersion && found.Version == tag &&
		regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(found.Commit)
}

// The canonical installer remains the ONLY updater/rollback authority.
// No second install/rollback/State/network engine is implemented here.
func menuRunCanonicalUpdate(ctx context.Context, release menuOfficialRelease, out, errOut io.Writer) error {
	// Run the CURRENT installed, byte-identical embedded canonical installer,
	// never arbitrary older downloaded shell source during a downgrade.
	if !menuReleaseImmutable(release) {
		return errors.New("automatic update requires a confirmed immutable GitHub release")
	}
	if os.Geteuid() != 0 {
		return errors.New("canonical update requires root")
	}
	tag := release.TagName
	if !menuReleaseTag.MatchString(tag) ||
		(!menuForwardMenuUpgrade(version.Version, release) &&
			(release.Prerelease || !menuStablePatchDowngrade(version.Version, tag))) {
		return errors.New("invalid or incompatible official release selection")
	}
	var child menuInstallerOutput
	stdout, stderr := child.streams()
	menuNotice(out, "INFO", "Running embedded canonical installer with exact release verification and State ownership locks.")
	if err := runEmbeddedInstaller(ctx, stdout, stderr, "update", "--version", tag, "--backends", "native"); err != nil {
		child.failure(out, "update", err, ctx)
		return errors.New("canonical updater exited unsuccessfully or was interrupted")
	}
	// Process success alone is not delivery; verify installed binary identity.
	verified, err := exec.CommandContext(ctx, "/usr/local/bin/stl", "version", "--json").Output()
	if err != nil || !menuInstalledVersionMatches(verified, tag) {
		return errors.New("installer returned success but installed version/commit could not be verified")
	}
	return nil
}

// Execute only the previously selected installer; output is untrusted
// (Bash/APT/other subprocesses). Keep process status and operator recovery
// information without exposing raw child stdout/stderr to the terminal.
func menuRunCanonicalUpdateProcess(ctx context.Context, path, tag string, out io.Writer) error {
	var childOutput menuInstallerOutput
	childStdout, childStderr := childOutput.streams()
	command := exec.CommandContext(ctx, "/bin/bash", path, "update", "--version", tag, "--backends", "native")
	command.Stdout, command.Stderr, command.Stdin = childStdout, childStderr, os.Stdin
	// Do not let caller-controlled shell startup/loader environment execute
	// before the canonical root installer (also used by PREPARE).
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "HOME=/root"}
	menuNotice(out, "INFO", "Running canonical updater; raw child diagnostics are withheld from the menu.")
	if err := command.Run(); err != nil {
		childOutput.failure(out, "update", err, ctx)
		return errors.New("canonical updater exited unsuccessfully or was interrupted")
	}
	return nil
}

// Failure detail may include network/proxy or filesystem paths. Categorize
// only our own fixed messages; arbitrary wrapped errors are never displayed.
func menuUpdateFailureCategory(err error) string {
	if err == nil {
		return ""
	}
	switch message := err.Error(); {
	case strings.HasPrefix(message, "cannot download official tagged installer"):
		return "tagged_installer_download_unverified"
	case strings.HasPrefix(message, "official tagged installer HTTP status"):
		return "tagged_installer_http_failure"
	case message == "tagged installer incomplete or exceeds size limit":
		return "tagged_installer_incomplete"
	case message == "tagged installer failed Bash syntax check":
		return "tagged_installer_syntax_unverified"
	case message == "canonical updater exited unsuccessfully or was interrupted":
		return "canonical_updater_failed_or_interrupted"
	case message == "installer returned success but installed version/commit could not be verified":
		return "installed_identity_unverified"
	case strings.Contains(message, "private root staging directory"),
		message == "cannot stage verified installer privately":
		return "private_staging_unavailable"
	case message == "invalid official release tag",
		message == "automatic update requires a confirmed immutable GitHub release",
		message == "canonical update requires root":
		return "canonical_update_admission_blocked"
	default:
		return "canonical_update_completion_unverified"
	}
}

// Remote catalogue errors are data, never trusted diagnostic text.
// Only exact known public categories are shown; arbitrary network errors
// can contain tokens, proxies, or untrusted URL components.
func menuReleaseLookupGuidance(err error) (reason, next string) {
	if err == nil {
		return "", ""
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "release_lookup_timeout", "Check reachability of api.github.com, then retry the Update menu; no download or update was started."
	}
	message := err.Error()
	const httpPrefix = "release catalogue returned status "
	if strings.HasPrefix(message, httpPrefix) {
		status, convErr := strconv.Atoi(strings.TrimPrefix(message, httpPrefix))
		if convErr == nil && status >= 100 && status <= 599 {
			if status == 403 || status == 429 {
				return "github_release_api_limited", "GitHub returned an API access/rate-limit response. Check GitHub Releases in a browser and retry later."
			}
			return fmt.Sprintf("github_release_http_%d", status), "Check GitHub Releases availability and HTTPS access, then retry; no update started."
		}
	}
	switch {
	case strings.HasPrefix(message, "release catalogue is not valid JSON"),
		message == "release catalogue could not be read within size limit":
		return "release_catalogue_invalid", "The release response was incomplete or malformed. Check GitHub Releases and retry later; do not install an unverified tag."
	case message == "no verified complete public release was found":
		return "no_complete_public_release", "Open official GitHub Releases and check the required artifacts; only complete published releases may update automatically."
	case message == "release API redirected outside trusted origin":
		return "release_origin_untrusted", "GitHub release inspection redirected unexpectedly. Check HTTPS/proxy settings; do not override origin validation."
	default:
		return "release_lookup_unverified", "Check reachability of api.github.com and official GitHub Releases, then retry the read-only lookup."
	}
}

// The interface can choose an exact official release. Only a fresh owner
// confirmation on a real root-owned STL installation can run the canonical
// updater. Scripts/redirected sessions always receive copyable guidance.
func menuPrintManualUpdate(out io.Writer, selected string) {
	menuSection(out, "Manual update / independent verification")
	menuField(out, "Release", "https://github.com/ach1992/simple-tun-link/releases/tag/"+selected)
	menuField(out, "Runbook", "https://github.com/ach1992/simple-tun-link/blob/main/docs/INSTALL.md")
	menuProse(out, "Verify the intended source, tag and release artifact checksums independently before following the canonical installer runbook.")
	menuProse(out, "Do not pipe a mutable-tag download into a privileged shell.")
}

func menuUpdate(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	menuScreen(out, "Update / choose official release")
	menuField(out, "Installed", safeMenuText(version.Version))
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	releases, lookupErr := menuPublicReleases(ctx, options)
	cancel()
	if lookupErr != nil {
		reason, next := menuReleaseLookupGuidance(lookupErr)
		menuNotice(out, "WARNING", "Cannot verify the official release list right now. No update was started.")
		menuField(out, "Reason", reason)
		menuField(out, "NEXT ACTION", next)
		menuField(out, "Official releases", "https://github.com/ach1992/simple-tun-link/releases")
	} else {
		menuSection(out, "Latest complete public releases")
		for i, release := range releases {
			kind := "Stable"
			if release.Prerelease {
				kind = "Pre-release"
			}
			if menuReleaseImmutable(release) {
				kind += " / immutable"
				switch {
				case release.TagName == version.Version:
					kind += " / installed"
				case menuForwardMenuUpgrade(version.Version, release):
					kind += " / upgrade"
				case !release.Prerelease && menuStablePatchDowngrade(version.Version, release.TagName):
					kind += " / downgrade (requires empty Links)"
				default:
					kind += " / check compatibility"
				}
			} else {
				kind += " / manual only"
			}
			menuOption(out, strconv.Itoa(i+1), release.TagName, kind)
		}
	}
	menuOption(out, "m", "Exact tag guidance", "Manual recovery / offline only")
	menuOption(out, "0", "Back", "No changes")
	fmt.Fprint(out, "Release number or m (Enter cancels): ")
	choice, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || (err == nil && (choice == "" || choice == "0" || strings.EqualFold(choice, "q"))) {
		menuNotice(out, "INFO", "Update cancelled. Nothing changed.")
		return 0
	}
	if err != nil {
		menuNotice(out, "WARNING", "Invalid selection; no update started.")
		return 2
	}
	selected, official := "", false
	var selectedRelease menuOfficialRelease
	if n, e := strconv.Atoi(choice); e == nil && n >= 1 && n <= len(releases) {
		selectedRelease = releases[n-1]
		selected, official = selectedRelease.TagName, true
	} else if choice == "m" || menuReleaseTag.MatchString(choice) {
		if choice == "m" {
			fmt.Fprint(out, "Exact tag (Enter cancels): ")
			selected, err = readMenuAnswer(reader)
			if err != nil || selected == "" {
				menuNotice(out, "INFO", "Update cancelled. Nothing changed.")
				return 0
			}
		} else {
			selected = choice
		}
	}
	if !menuReleaseTag.MatchString(selected) {
		fmt.Fprintln(errOut, "Invalid release tag; no update attempted.")
		return 2
	}
	menuSection(out, "Selected release / before changing anything")
	menuField(out, "Version", selected)
	menuField(out, "Source", "https://github.com/ach1992/simple-tun-link/releases/tag/"+selected)
	if selected == version.Version {
		menuNotice(out, "INFO", "This release is already installed. No update needed.")
		return 0
	}
	if !official {
		// Exact manual entry is a selector, NOT permission to trust an
		// arbitrary tag. Validate the exact official API release and its
		// complete artifact set; offline/test catalogues never auto-adopt it.
		for _, listed := range releases {
			if listed.TagName == selected {
				selectedRelease, official = listed, true
				break
			}
		}
		if !official && (options == nil || options.menuReleases == nil) {
			ctx, stop := context.WithTimeout(context.Background(), 7*time.Second)
			exact, err := fetchMenuReleaseTag(ctx, selected)
			stop()
			if err == nil {
				selectedRelease, official = exact, true
			}
		}
		if !official {
			menuNotice(out, "WARNING", "Manually entered tag was NOT verified as a complete official immutable release. Nothing changed.")
			menuPrintManualUpdate(out, selected)
			return 0
		}
	}
	downgrade := !selectedRelease.Prerelease && menuStablePatchDowngrade(version.Version, selectedRelease.TagName)
	if !menuForwardMenuUpgrade(version.Version, selectedRelease) && !downgrade {
		menuNotice(out, "WARNING", "This release is not a verified compatible same-line upgrade/downgrade; no installer started.")
		menuField(out, "Reason", "release_version_contract_unsupported")
		menuField(out, "NEXT ACTION", "Choose another verified Stable from the list; switching major/minor or older unknown State readers requires a compatibility review.")
		return 0
	}
	if !menuReleaseImmutable(selectedRelease) {
		menuNotice(out, "WARNING", "GitHub release immutability is false or unverified. Automatic root update is disabled.")
		menuPrintManualUpdate(out, selected)
		return 0
	}
	if !menuCanUpdateNow(input, out) {
		menuNotice(out, "INFO", "Automatic update requires a real terminal, root and installer-owned /usr/local/bin/stl.")
		menuPrintManualUpdate(out, selected)
		return 0
	}
	token := "UPDATE"
	if downgrade {
		token = "DOWNGRADE"
		ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		err := inspectDowngradeReady(ctx, state.DefaultRoot,
			linux.SystemdPersistence{Runner: linux.ExecRunner{}}, trustedStatePath)
		stop()
		if err != nil {
			reason, next := uninstallGateGuidance(err)
			menuNotice(out, "WARNING", "Downgrade requires no saved Links, pending operations or STL restore unit. No change started.")
			menuField(out, "Reason", reason)
			menuField(out, "NEXT ACTION", next)
			return 0
		}
		menuNotice(out, "INFO", "The current Engine will preserve or safely convert an EMPTY State for the older verified schema under its maintenance lock.")
	}
	menuNotice(out, "WARNING", "The selected version replaces the installed binary. Back up State and protected credentials first; active Links must be quiesced.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Cannot obtain a fresh terminal confirmation; nothing changed.")
		return 2
	}
	fmt.Fprintf(out, "Type %s to run the canonical installer (Enter cancels): ", menuActionToken(out, token))
	confirm, err := readMenuAnswer(reader)
	if err != nil || confirm != token {
		menuNotice(out, "INFO", "Update cancelled. No installer started.")
		return 0
	}
	updateCtx, stop := context.WithTimeout(context.Background(), 30*time.Minute)
	defer stop()
	if err := menuRunCanonicalUpdate(updateCtx, selectedRelease, out, errOut); err != nil {
		menuNotice(out, "FAILED", "Canonical installer did not confirm completion. Inspect installed identity/recovery before retrying.")
		menuField(out, "Reason", menuUpdateFailureCategory(err))
		menuField(out, "NEXT ACTION", "Inspect official release reachability, stl version --json, installed ownership and retained recovery evidence read-only; no blind retry. Child diagnostics remain private.")
		// The executable might have been partially replaced or rolled back.
		// Never resume the old in-memory menu after any install attempt.
		return menuUpdatedExecutable
	}
	menuNotice(out, "OK", "Version change complete. Exit this process and reopen STL to use the selected executable.")
	return menuUpdatedExecutable
}
