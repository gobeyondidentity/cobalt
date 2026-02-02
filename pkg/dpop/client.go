package dpop

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// ProofGenerator generates DPoP proofs for HTTP requests.
// This interface is implemented by the proof generator (si-d2y.1.6).
type ProofGenerator interface {
	// Generate creates a DPoP proof for the given HTTP method and URI.
	// The kid is the server-assigned key identifier.
	Generate(method, uri, kid string) (string, error)
}

// Client is an HTTP client that automatically adds DPoP authentication.
type Client struct {
	httpClient     *http.Client
	proofGenerator ProofGenerator
	kid            string
	baseURL        string
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets the underlying HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithKID sets the key ID for the client.
func WithKID(kid string) ClientOption {
	return func(c *Client) {
		c.kid = kid
	}
}

// NewClient creates a new DPoP-enabled HTTP client.
func NewClient(baseURL string, proofGen ProofGenerator, opts ...ClientOption) *Client {
	c := &Client{
		httpClient:     http.DefaultClient,
		proofGenerator: proofGen,
		baseURL:        strings.TrimSuffix(baseURL, "/"),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// SetKID sets the key ID (used after enrollment).
func (c *Client) SetKID(kid string) {
	c.kid = kid
}

// Do sends an HTTP request with DPoP authentication.
// A fresh proof is generated for each request to prevent replay.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// Generate fresh proof for this request
	uri := c.baseURL + req.URL.Path
	proof, err := c.proofGenerator.Generate(req.Method, uri, c.kid)
	if err != nil {
		return nil, fmt.Errorf("generate dpop proof: %w", err)
	}

	// Add DPoP header
	req.Header.Set("DPoP", proof)

	// Send request
	return c.httpClient.Do(req)
}

// Get performs a GET request with DPoP authentication.
func (c *Client) Get(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post performs a POST request with DPoP authentication.
func (c *Client) Post(path string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// PostJSON performs a POST request with JSON body and DPoP authentication.
func (c *Client) PostJSON(path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}
	return c.Post(path, "application/json", strings.NewReader(string(data)))
}

// Delete performs a DELETE request with DPoP authentication.
func (c *Client) Delete(path string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// AuthError represents an authentication error from the server.
type AuthError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authentication error: %s", e.Code)
}

// UserFriendlyMessage returns a user-friendly error message.
func (e *AuthError) UserFriendlyMessage() string {
	switch e.Code {
	case "dpop.missing_proof":
		return "Authentication failed: DPoP proof required"
	case "dpop.invalid_proof":
		return "Authentication failed: invalid proof format"
	case "dpop.unknown_key":
		return "Authentication failed: key not recognized (re-enrollment may be required)"
	case "dpop.invalid_signature":
		return "Authentication failed: signature verification failed"
	case "dpop.invalid_iat":
		return clockSyncErrorMessage()
	case "dpop.method_mismatch":
		return "Authentication failed: request method mismatch"
	case "dpop.uri_mismatch":
		return "Authentication failed: request URI mismatch"
	case "dpop.replay":
		return "Authentication failed: token replay detected"
	case "auth.revoked":
		return "Access has been revoked. Contact your administrator."
	case "auth.suspended":
		return "Access has been suspended. Contact your administrator."
	case "auth.decommissioned":
		return "This device has been decommissioned."
	default:
		return fmt.Sprintf("Authentication failed: %s", e.Code)
	}
}

// IsClockError returns true if the error suggests clock synchronization issues.
func (e *AuthError) IsClockError() bool {
	return e.Code == "dpop.invalid_iat"
}

// clockSyncErrorMessage returns a user-friendly error message with platform-specific fix commands.
func clockSyncErrorMessage() string {
	base := "Authentication failed: system clock is out of sync"
	switch runtime.GOOS {
	case "linux":
		return base + "\nFix: sudo timedatectl set-ntp true"
	case "darwin":
		return base + "\nFix: sudo sntp -sS time.apple.com"
	case "windows":
		return base + "\nFix: w32tm /resync"
	default:
		return base + " (check NTP settings)"
	}
}

// IsRevoked returns true if the identity has been revoked.
func (e *AuthError) IsRevoked() bool {
	return e.Code == "auth.revoked"
}

// IsSuspended returns true if the identity has been suspended.
func (e *AuthError) IsSuspended() bool {
	return e.Code == "auth.suspended"
}

// ParseAuthError parses an authentication error from an HTTP response.
// Returns nil if the response is not a 401/403.
func ParseAuthError(resp *http.Response) *AuthError {
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return nil
	}

	var errorResp struct {
		Error string `json:"error"`
	}

	// Try to parse JSON error body
	if resp.Body != nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			json.Unmarshal(body, &errorResp)
		}
	}

	code := errorResp.Error
	if code == "" {
		code = "unknown"
	}

	return &AuthError{
		StatusCode: resp.StatusCode,
		Code:       code,
	}
}

// IdentityConfig holds the configuration for a DPoP identity.
type IdentityConfig struct {
	KeyStore  KeyStore
	KIDStore  KIDStore
	ServerURL string
}

// LoadIdentity loads an existing identity (key + kid) from storage.
// Returns the private key and kid, or an error if not enrolled.
func LoadIdentity(cfg IdentityConfig) (ed25519.PrivateKey, string, error) {
	// Load private key
	key, err := cfg.KeyStore.Load()
	if err != nil {
		return nil, "", fmt.Errorf("load key: %w", err)
	}

	// Load kid
	kid, err := cfg.KIDStore.Load()
	if err != nil {
		return nil, "", fmt.Errorf("load kid: %w", err)
	}

	return key, kid, nil
}

// SaveIdentity saves an identity (key + kid) to storage.
func SaveIdentity(cfg IdentityConfig, key ed25519.PrivateKey, kid string) error {
	// Save private key first
	if err := cfg.KeyStore.Save(key); err != nil {
		return fmt.Errorf("save key: %w", err)
	}

	// Save kid
	if err := cfg.KIDStore.Save(kid); err != nil {
		return fmt.Errorf("save kid: %w", err)
	}

	return nil
}

// IsEnrolled returns true if the identity has been enrolled (key + kid exist).
func IsEnrolled(cfg IdentityConfig) bool {
	return cfg.KeyStore.Exists() && cfg.KIDStore.Exists()
}

// MVPWarning returns the warning message for file-based key storage.
// CLI clients should log this at startup when using FileKeyStore.
const MVPWarning = "Using file-based key storage (MVP mode). Hardware binding required for production."

// mvpWarningOnce ensures the MVP warning is logged only once per process.
var mvpWarningOnce sync.Once

// sessionMarkerPath returns the path for the MVP warning session marker file.
func sessionMarkerPath(clientType string) string {
	keyPath, _ := DefaultKeyPaths(clientType)
	if keyPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(keyPath), ".mvp-session")
}

// getSessionPPID returns the parent process ID for session tracking.
// Can be overridden via MVP_TEST_PPID environment variable for testing.
func getSessionPPID() string {
	if testPPID := os.Getenv("MVP_TEST_PPID"); testPPID != "" {
		return testPPID
	}
	return strconv.Itoa(os.Getppid())
}

// shouldShowMVPWarning checks if the MVP warning should be shown for this session.
// Returns true if the warning hasn't been shown in the current terminal session.
func shouldShowMVPWarning(clientType string) bool {
	markerPath := sessionMarkerPath(clientType)
	if markerPath == "" {
		return true // Unknown client type, show warning
	}

	currentPPID := getSessionPPID()

	// Read existing marker
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return true // File doesn't exist or error reading, show warning
	}

	// Check if PPID matches current session
	return strings.TrimSpace(string(data)) != currentPPID
}

// markMVPWarningShown records that the MVP warning was shown for this session.
func markMVPWarningShown(clientType string) {
	markerPath := sessionMarkerPath(clientType)
	if markerPath == "" {
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(markerPath)
	os.MkdirAll(dir, 0700)

	// Write current PPID to marker file
	currentPPID := getSessionPPID()
	os.WriteFile(markerPath, []byte(currentPPID), 0600)
}

// logMVPWarning logs the MVP warning once per terminal session using a file-based marker.
// The warning is shown on the first km command in a terminal session, then suppressed
// for subsequent commands in the same session (identified by parent shell PID).
func logMVPWarning(logger Logger, clientType string) {
	if logger == nil {
		return
	}
	mvpWarningOnce.Do(func() {
		if shouldShowMVPWarning(clientType) {
			logger.Warn(MVPWarning)
			markMVPWarningShown(clientType)
		}
	})
}

// ResetMVPWarning resets the warning state, allowing it to be logged again.
// This is only intended for use in tests.
func ResetMVPWarning() {
	mvpWarningOnce = sync.Once{}
}

// ResetMVPWarningWithMarker resets both the in-memory state and removes the marker file.
// This is only intended for use in tests.
func ResetMVPWarningWithMarker(clientType string) {
	mvpWarningOnce = sync.Once{}
	markerPath := sessionMarkerPath(clientType)
	if markerPath != "" {
		os.Remove(markerPath)
	}
}

// Logger is a simple logging interface for DPoP warnings.
type Logger interface {
	Warn(msg string)
}

// ClientConfig holds configuration for creating a DPoP client.
type ClientConfig struct {
	// ClientType is one of: "km", "bluectl", "aegis"
	ClientType string
	// ServerURL is the nexus API base URL
	ServerURL string
	// Logger for warnings (optional, uses default if nil)
	Logger Logger
	// HTTPClient is the underlying HTTP client (optional)
	HTTPClient *http.Client
}

// NewClientFromConfig creates a DPoP client from configuration.
// Loads existing identity if enrolled, returns nil key if not enrolled.
// Logs MVP warning for file-based key storage.
func NewClientFromConfig(cfg ClientConfig) (*Client, ed25519.PrivateKey, string, error) {
	// Get default paths for client type
	keyPath, kidPath := DefaultKeyPaths(cfg.ClientType)
	if keyPath == "" {
		return nil, nil, "", fmt.Errorf("unknown client type: %s", cfg.ClientType)
	}

	// Create stores
	keyStore := NewFileKeyStore(keyPath)
	kidStore := NewFileKIDStore(kidPath)

	// Log MVP warning for file-based keys (once per terminal session)
	logMVPWarning(cfg.Logger, cfg.ClientType)

	idCfg := IdentityConfig{
		KeyStore:  keyStore,
		KIDStore:  kidStore,
		ServerURL: cfg.ServerURL,
	}

	// Check if enrolled
	if !IsEnrolled(idCfg) {
		// Not enrolled yet, caller must handle enrollment
		return nil, nil, "", nil
	}

	// Load identity
	privKey, kid, err := LoadIdentity(idCfg)
	if err != nil {
		return nil, nil, "", fmt.Errorf("load identity: %w", err)
	}

	// Create proof generator
	proofGen := NewEd25519Generator(privKey)

	// Create client options
	var opts []ClientOption
	opts = append(opts, WithKID(kid))
	if cfg.HTTPClient != nil {
		opts = append(opts, WithHTTPClient(cfg.HTTPClient))
	}

	// Create client
	client := NewClient(cfg.ServerURL, proofGen, opts...)

	return client, privKey, kid, nil
}

// NewEnrollmentClient creates a DPoP client for enrollment (no existing identity).
// Generates a new keypair and returns the client, private key, and public key.
// Logs MVP warning for file-based key storage.
func NewEnrollmentClient(cfg ClientConfig) (*Client, ed25519.PrivateKey, ed25519.PublicKey, error) {
	// Log MVP warning for file-based keys (once per terminal session)
	logMVPWarning(cfg.Logger, cfg.ClientType)

	// Generate new keypair
	pubKey, privKey, err := GenerateKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	// Create proof generator (no kid during enrollment)
	proofGen := NewEd25519Generator(privKey)

	// Create client options
	var opts []ClientOption
	if cfg.HTTPClient != nil {
		opts = append(opts, WithHTTPClient(cfg.HTTPClient))
	}

	// Create client (no kid yet)
	client := NewClient(cfg.ServerURL, proofGen, opts...)

	return client, privKey, pubKey, nil
}

// CompleteEnrollment saves the identity after successful enrollment.
func CompleteEnrollment(clientType string, privKey ed25519.PrivateKey, kid string) error {
	keyPath, kidPath := DefaultKeyPaths(clientType)
	if keyPath == "" {
		return fmt.Errorf("unknown client type: %s", clientType)
	}

	cfg := IdentityConfig{
		KeyStore: NewFileKeyStore(keyPath),
		KIDStore: NewFileKIDStore(kidPath),
	}

	return SaveIdentity(cfg, privKey, kid)
}
