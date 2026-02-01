package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
)

// dpopClient is the DPoP-enabled HTTP client for keymaker.
// Set during initialization, nil if not enrolled.
var dpopClient *dpop.Client

// dpopInitialized tracks whether DPoP initialization was attempted.
var dpopInitialized bool

// StderrLogger implements dpop.Logger for warning output.
type StderrLogger struct{}

// Warn writes a warning message to stderr.
func (l StderrLogger) Warn(msg string) {
	fmt.Fprintln(os.Stderr, "Warning:", msg)
}

// initDPoP initializes the DPoP client for keymaker.
// Called during CLI initialization for commands that need authentication.
// Returns the DPoP client or nil if not enrolled yet (enrollment required first).
func initDPoP(serverURL string) (*dpop.Client, error) {
	if dpopInitialized && dpopClient != nil {
		return dpopClient, nil
	}
	dpopInitialized = true

	cfg := dpop.ClientConfig{
		ClientType: "km",
		ServerURL:  serverURL,
		Logger:     StderrLogger{},
	}

	client, _, _, err := dpop.NewClientFromConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DPoP client: %w", err)
	}

	// client is nil if not enrolled yet
	if client == nil {
		return nil, nil
	}

	dpopClient = client
	return client, nil
}

// getDPoPHTTPClient returns an HTTP client that adds DPoP headers to requests.
// If DPoP is not initialized or enrollment is required, returns the standard HTTP client.
// The serverURL is needed to initialize DPoP if not already done.
func getDPoPHTTPClient(serverURL string) HTTPClient {
	if dpopClient != nil {
		return &dpopHTTPClientWrapper{
			dpopClient: dpopClient,
			serverURL:  serverURL,
		}
	}

	// Try to initialize
	client, err := initDPoP(serverURL)
	if err != nil {
		// Log error but fall back to standard client
		fmt.Fprintf(os.Stderr, "Warning: DPoP initialization failed: %v\n", err)
		return http.DefaultClient
	}

	if client == nil {
		// Not enrolled yet, use standard client
		return http.DefaultClient
	}

	return &dpopHTTPClientWrapper{
		dpopClient: client,
		serverURL:  serverURL,
	}
}

// dpopHTTPClientWrapper wraps a dpop.Client to implement HTTPClient interface.
// This allows seamless integration with existing HTTP-based code.
type dpopHTTPClientWrapper struct {
	dpopClient *dpop.Client
	serverURL  string
}

// Do implements HTTPClient.Do by delegating to the dpop.Client.
func (w *dpopHTTPClientWrapper) Do(req *http.Request) (*http.Response, error) {
	resp, err := w.dpopClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Check for auth errors and provide user-friendly messages
	if authErr := dpop.ParseAuthError(resp); authErr != nil {
		// Return the response but also wrap the error for callers that check
		// Note: We return the response so callers can handle 401/403 themselves
		// The authErr provides user-friendly messaging
		return resp, nil
	}

	return resp, nil
}

// handleDPoPAuthError checks if a response is a DPoP authentication error
// and returns a user-friendly error if so.
func handleDPoPAuthError(resp *http.Response) error {
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return nil
	}

	// Try to parse as auth error
	// Note: ParseAuthError consumes the body, so we need to handle this carefully
	// For now, just return a generic auth error message based on status code
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: please run 'km init' to enroll")
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("access denied: you do not have permission for this operation")
	}
	return nil
}

// resetDPoPClient resets the DPoP client (for testing).
func resetDPoPClient() {
	dpopClient = nil
	dpopInitialized = false
}
