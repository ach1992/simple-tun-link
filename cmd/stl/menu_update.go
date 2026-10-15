package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/version"
)

const (
	menuOfficialReleasesURL = "https://api.github.com/repos/ach1992/simple-tun-link/releases?per_page=15"
	menuUpdatedExecutable   = 106 // internal menu loop sentinel; never a CLI exit status
	menuReleaseBytesLimit   = 256 * 1024
)

var menuReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$`)
var menuRCVersion = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)-rc\.([0-9]+)$`)

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
		if release.Draft || release.PublishedAt.IsZero() ||
			!menuReleaseTag.MatchString(release.TagName) || seen[release.TagName] {
			continue
		}
		names := map[string]bool{}
		for _, asset := range release.Assets {
			if asset.Size > 0 && asset.State == "uploaded" {
				names[asset.Name] = true
			}
		}
		if !names["stl_"+release.TagName+"_linux_amd64"] ||
			!names["stl_"+release.TagName+"_linux_arm64"] ||
			!names["BUILD-MANIFEST.txt"] || !names["SHA256SUMS"] || !names["LICENSE"] {
			continue // incomplete/unpublished bundles cannot be selected
		}
		seen[release.TagName] = true
		got = append(got, release)
	}
	sort.SliceStable(got, func(i, j int) bool {
		return got[i].PublishedAt.After(got[j].PublishedAt)
	})
	if len(got) > 3 {
		got = got[:3]
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

// Automated updates are limited to a forward candidate on the same
// major/minor/patch release line. New public lines need migration review;
// selecting one still gives the manual runbook, never a silent downgrade.
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
	// Fail closed even if a future call site bypasses the menu's prompt:
	// no downloaded shell code may execute as root for a mutable release.
	if !menuReleaseImmutable(release) {
		return errors.New("automatic update requires a confirmed immutable GitHub release")
	}
	if os.Geteuid() != 0 {
		return errors.New("canonical update requires root")
	}
	tag := release.TagName
	if !menuReleaseTag.MatchString(tag) {
		return errors.New("invalid official release tag")
	}
	// Never execute a newly downloaded root script from user-controlled
	// TMPDIR or a shared writable directory. The supported distro's
	// root-private home is an isolated, non-symlink parent.
	parent, err := os.Lstat("/root")
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 ||
		parent.Mode().Perm()&0o077 != 0 {
		return errors.New("trusted private root staging directory is not available")
	}
	identity, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != 0 {
		return errors.New("private root staging directory has untrusted owner")
	}
	dir, err := os.MkdirTemp("/root", "stl-update-")
	if err != nil {
		return errors.New("cannot stage verified installer privately")
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "install.sh")
	raw := "https://raw.githubusercontent.com/ach1992/simple-tun-link/" + tag + "/scripts/install.sh"
	client := &http.Client{
		Timeout: 25 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.Host != "raw.githubusercontent.com" || len(via) > 2 {
				return errors.New("tagged installer redirected outside trusted HTTPS origin")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot download official tagged installer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("official tagged installer HTTP status %d", resp.StatusCode)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(file, io.LimitReader(resp.Body, menuReleaseBytesLimit+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || n == 0 || n > menuReleaseBytesLimit {
		return errors.New("tagged installer incomplete or exceeds size limit")
	}
	syntax := exec.CommandContext(ctx, "/bin/bash", "-n", path)
	if err := syntax.Run(); err != nil {
		return errors.New("tagged installer failed Bash syntax check")
	}
	menuNotice(out, "INFO", "Immutable official release selected; the canonical installer owns update and rollback.")
	command := exec.CommandContext(ctx, "/bin/bash", path, "update", "--version", tag, "--backends", "native")
	command.Stdout, command.Stderr, command.Stdin = out, errOut, os.Stdin
	if err := command.Run(); err != nil {
		return fmt.Errorf("canonical update unsuccessful: %w", err)
	}
	// Process success alone is not release delivery. Verify the newly
	// installed executable's immutable embedded identity before saying OK.
	verified, err := exec.CommandContext(ctx, "/usr/local/bin/stl", "version", "--json").Output()
	if err != nil || !menuInstalledVersionMatches(verified, tag) {
		return errors.New("installer returned success but installed version/commit could not be verified")
	}
	return nil
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
		menuNotice(out, "WARNING", "Cannot verify the official release list right now. No update was started.")
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
		menuNotice(out, "WARNING", "Manually entered tag was NOT verified by this menu. Inspect official release before running anything.")
		menuPrintManualUpdate(out, selected)
		return 0
	}
	if !menuRCUpgrade(version.Version, selected) {
		menuNotice(out, "WARNING", "This is not a confirmed forward RC upgrade. No in-place update command is recommended.")
		menuField(out, "Recovery runbook", "https://github.com/ach1992/simple-tun-link/blob/main/docs/INSTALL.md")
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
	menuNotice(out, "WARNING", "An update replaces the installed binary. Back up State and protected credentials first; active Links must be quiesced.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Cannot obtain a fresh terminal confirmation; nothing changed.")
		return 2
	}
	fmt.Fprintf(out, "Type %s to run the canonical installer (Enter cancels): ", menuPaint(out, menuRed, "UPDATE"))
	confirm, err := readMenuAnswer(reader)
	if err != nil || confirm != "UPDATE" {
		menuNotice(out, "INFO", "Update cancelled. No installer started.")
		return 0
	}
	updateCtx, stop := context.WithTimeout(context.Background(), 30*time.Minute)
	defer stop()
	if err := menuRunCanonicalUpdate(updateCtx, selectedRelease, out, errOut); err != nil {
		menuNotice(out, "FAILED", "Canonical installer did not confirm completion. Inspect installed identity/recovery before retrying.")
		fmt.Fprintln(errOut, safeMenuText(err.Error()))
		// The executable might have been partially replaced or rolled back.
		// Never resume the old in-memory menu after any install attempt.
		return menuUpdatedExecutable
	}
	menuNotice(out, "OK", "Update complete. Exit this process and reopen STL to use the new executable.")
	return menuUpdatedExecutable
}
