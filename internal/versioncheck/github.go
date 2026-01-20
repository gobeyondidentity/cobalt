package versioncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultGitHubAPI is the base URL for the GitHub API.
const DefaultGitHubAPI = "https://api.github.com"

// DefaultTimeout is the HTTP timeout for API requests.
const DefaultTimeout = 2 * time.Second

// GitHubRelease represents the relevant fields from a GitHub release.
type GitHubRelease struct {
	// TagName is the release tag (e.g., "v0.5.2").
	TagName string `json:"tag_name"`
	// HTMLURL is the URL to the release page.
	HTMLURL string `json:"html_url"`
	// Name is the human-readable release name.
	Name string `json:"name"`
}

// GitHubClient fetches release information from GitHub.
type GitHubClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewGitHubClient creates a new GitHub client with default timeout.
func NewGitHubClient(baseURL string) *GitHubClient {
	return NewGitHubClientWithTimeout(baseURL, DefaultTimeout)
}

// NewGitHubClientWithTimeout creates a new GitHub client with custom timeout.
func NewGitHubClientWithTimeout(baseURL string, timeout time.Duration) *GitHubClient {
	return &GitHubClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// FetchLatestRelease fetches the latest release from GitHub.
func (c *GitHubClient) FetchLatestRelease() (*GitHubRelease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)
	defer cancel()

	url := c.baseURL + "/repos/gobeyondidentity/secure-infra/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "secureinfra-cli")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &release, nil
}
