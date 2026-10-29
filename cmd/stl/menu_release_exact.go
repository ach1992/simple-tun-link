package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Exact-tag lookup uses the same official asset/immutability gates as the
// catalogue. A manually typed tag never becomes a trusted root instruction.
func fetchMenuReleaseTagAt(ctx context.Context, client *http.Client,
	endpoint, tag string) (menuOfficialRelease, error) {
	if !menuReleaseTag.MatchString(tag) {
		return menuOfficialRelease{}, errors.New("invalid release tag")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return menuOfficialRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "simple-tun-link-operator")
	resp, err := client.Do(req)
	if err != nil {
		return menuOfficialRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return menuOfficialRelease{}, fmt.Errorf("exact official release lookup HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, menuReleaseBytesLimit+1))
	if err != nil || len(body) > menuReleaseBytesLimit {
		return menuOfficialRelease{}, errors.New("exact official release response invalid or oversized")
	}
	var release menuOfficialRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return menuOfficialRelease{}, errors.New("exact official release response invalid")
	}
	if release.TagName != tag || !menuReleaseComplete(release) {
		return menuOfficialRelease{}, errors.New("exact official release is incomplete or mismatched")
	}
	return release, nil
}

func fetchMenuReleaseTag(ctx context.Context, tag string) (menuOfficialRelease, error) {
	if !menuReleaseTag.MatchString(tag) {
		return menuOfficialRelease{}, errors.New("invalid exact release tag")
	}
	endpoint := "https://api.github.com/repos/ach1992/simple-tun-link/releases/tags/" + url.PathEscape(tag)
	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || len(via) > 2 {
				return errors.New("release API redirected outside official origin")
			}
			return nil
		},
	}
	return fetchMenuReleaseTagAt(ctx, client, endpoint, tag)
}
