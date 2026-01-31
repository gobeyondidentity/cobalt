package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/nmelo/secure-infra/pkg/dpop"
	"github.com/nmelo/secure-infra/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupAuthTestServer creates a test server with DPoP middleware wired in.
// This mimics the real nexus server setup.
func setupAuthTestServer(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store.SetInsecureMode(true)
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}

	t.Cleanup(func() {
		s.Close()
		os.Remove(dbPath)
	})

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// Wire up DPoP middleware like nexus main.go does
	jtiCache := dpop.NewMemoryJTICache(
		dpop.WithTTL(5*time.Minute),
		dpop.WithCleanupInterval(0), // Disable cleanup for tests
	)
	t.Cleanup(func() { jtiCache.Close() })

	validator := dpop.NewValidator(dpop.DefaultValidatorConfig())
	proofValidator := NewStoreProofValidator(validator, s)
	identityLookup := NewStoreIdentityLookup(s)
	authMiddleware := dpop.NewAuthMiddleware(proofValidator, identityLookup, jtiCache)

	// Apply CORS and auth middleware
	// CORS wraps auth so OPTIONS preflight gets CORS headers and bypasses auth
	handler := loggingMiddleware(corsMiddleware(authMiddleware.Wrap(mux)))

	return server, handler, s
}

// corsMiddleware is copied from nexus main.go for test consistency
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, DPoP")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simplified logging middleware for tests
		next.ServeHTTP(w, r)
	})
}

// generateTestKeyPair generates an Ed25519 key pair for testing.
func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return pub, priv
}

// generateDPoPProof creates a valid DPoP proof for testing.
// The uri should match what the test server sees (httptest uses example.com).
func generateDPoPProof(t *testing.T, priv ed25519.PrivateKey, kid, method, uri string) string {
	t.Helper()

	// Create signer with EdDSA
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).
			WithType("dpop+jwt").
			WithHeader("kid", kid),
	)
	require.NoError(t, err)

	// Create claims
	claims := map[string]interface{}{
		"jti": uuid.New().String(),
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
	}

	// Sign
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}

// testHTU builds the expected htu claim for httptest.
// httptest.NewRequest uses "example.com" as the host.
func testHTU(path string) string {
	return "http://example.com" + path
}

// TestProtectedEndpointRejectsMissingProof tests that protected endpoints
// reject requests without a DPoP proof header.
func TestProtectedEndpointRejectsMissingProof(t *testing.T) {
	t.Log("Testing protected endpoint rejects request without DPoP proof")

	_, handler, _ := setupAuthTestServer(t)

	t.Log("Making request to /api/v1/operators without DPoP header")
	req := httptest.NewRequest("GET", "/api/v1/operators", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Log("Verifying response is 401 Unauthorized")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "expected 401 for missing proof")

	t.Log("Verifying error code is dpop.missing_proof")
	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "dpop.missing_proof", resp["error"], "expected dpop.missing_proof error code")

	t.Log("Protected endpoint correctly rejected missing proof")
}

// TestProtectedEndpointAcceptsValidProof tests that protected endpoints
// accept requests with a valid DPoP proof from an enrolled keymaker.
func TestProtectedEndpointAcceptsValidProof(t *testing.T) {
	t.Log("Testing protected endpoint accepts valid DPoP proof from enrolled keymaker")

	_, handler, s := setupAuthTestServer(t)

	// Create operator and keymaker with DPoP binding
	t.Log("Creating operator for keymaker enrollment")
	err := s.CreateOperator("op_test1", "operator@example.com", "Test Operator")
	require.NoError(t, err)

	// Generate key pair
	t.Log("Generating Ed25519 key pair for keymaker")
	pub, priv := generateTestKeyPair(t)

	// Create keymaker with DPoP kid
	kid := "km_" + uuid.New().String()[:8]
	t.Logf("Creating keymaker with kid: %s", kid)
	km := &store.KeyMaker{
		ID:             kid,
		OperatorID:     "op_test1",
		Name:           "Test Device",
		Platform:       "darwin",
		SecureElement:  "tpm",
		PublicKey:      base64.StdEncoding.EncodeToString(pub),
		Status:         "active",
		Kid:            kid,
		KeyFingerprint: "test-fingerprint-123",
		BoundAt:        time.Now(),
	}
	err = s.CreateKeyMaker(km)
	require.NoError(t, err)

	// Generate valid DPoP proof
	t.Log("Generating DPoP proof for request")
	proof := generateDPoPProof(t, priv, kid, "GET", testHTU("/api/v1/operators"))

	// Make request with proof
	t.Log("Making request to /api/v1/operators with DPoP header")
	req := httptest.NewRequest("GET", "/api/v1/operators", nil)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	t.Logf("Response body: %s", w.Body.String())

	t.Log("Verifying response is 200 OK")
	assert.Equal(t, http.StatusOK, w.Code, "expected 200 for valid proof")

	t.Log("Protected endpoint correctly accepted valid DPoP proof")
}

// TestProtectedEndpointAcceptsAdminProof tests that protected endpoints
// accept requests with a valid DPoP proof from an enrolled admin.
func TestProtectedEndpointAcceptsAdminProof(t *testing.T) {
	t.Log("Testing protected endpoint accepts valid DPoP proof from enrolled admin")

	_, handler, s := setupAuthTestServer(t)

	// Create operator and admin key
	t.Log("Creating operator for admin key")
	err := s.CreateOperator("op_admin1", "admin@example.com", "Admin Operator")
	require.NoError(t, err)

	// Generate key pair
	t.Log("Generating Ed25519 key pair for admin")
	pub, priv := generateTestKeyPair(t)

	// Create admin key with DPoP kid
	kid := "adm_" + uuid.New().String()[:8]
	t.Logf("Creating admin key with kid: %s", kid)
	ak := &store.AdminKey{
		ID:             kid,
		OperatorID:     "op_admin1",
		Name:           "Admin Laptop",
		PublicKey:      pub,
		Kid:            kid,
		KeyFingerprint: "admin-fingerprint-456",
		Status:         "active",
		BoundAt:        time.Now(),
	}
	err = s.CreateAdminKey(ak)
	require.NoError(t, err)

	// Generate valid DPoP proof
	t.Log("Generating DPoP proof for request")
	proof := generateDPoPProof(t, priv, kid, "GET", testHTU("/api/v1/operators"))

	// Make request with proof
	t.Log("Making request to /api/v1/operators with DPoP header")
	req := httptest.NewRequest("GET", "/api/v1/operators", nil)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)

	t.Log("Verifying response is 200 OK")
	assert.Equal(t, http.StatusOK, w.Code, "expected 200 for valid admin proof")

	t.Log("Protected endpoint correctly accepted valid admin DPoP proof")
}

// TestPublicHealthEndpointAccessibleWithoutAuth tests that /health
// is accessible without DPoP authentication.
func TestPublicHealthEndpointAccessibleWithoutAuth(t *testing.T) {
	t.Log("Testing /health endpoint is accessible without DPoP authentication")

	_, handler, _ := setupAuthTestServer(t)

	t.Log("Making request to /health without DPoP header")
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Log("Verifying response is 200 OK")
	assert.Equal(t, http.StatusOK, w.Code, "expected 200 for public health endpoint")

	t.Log("Verifying response contains status: ok")
	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp["status"])

	t.Log("/health endpoint correctly accessible without auth")
}

// TestBootstrapEndpointAccessibleWithoutAuth tests that /api/v1/admin/bootstrap
// is accessible without DPoP authentication (during bootstrap window).
func TestBootstrapEndpointAccessibleWithoutAuth(t *testing.T) {
	t.Log("Testing /api/v1/admin/bootstrap endpoint is accessible without DPoP authentication")

	_, handler, s := setupAuthTestServer(t)

	// Initialize bootstrap window
	t.Log("Initializing bootstrap window")
	err := s.InitBootstrapWindow()
	require.NoError(t, err)

	// Generate a test key for bootstrap
	pub, _ := generateTestKeyPair(t)

	t.Log("Making POST request to /api/v1/admin/bootstrap without DPoP header")
	body := map[string]interface{}{
		"name":       "Test Admin",
		"public_key": base64.StdEncoding.EncodeToString(pub),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", nil)
	req.Body = &readCloser{data: bodyBytes}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	t.Logf("Response body: %s", w.Body.String())

	// Should either succeed (201) or fail for business reasons (not 401)
	t.Log("Verifying response is NOT 401 Unauthorized")
	assert.NotEqual(t, http.StatusUnauthorized, w.Code, "bootstrap should not require auth")

	t.Log("/api/v1/admin/bootstrap endpoint correctly accessible without auth")
}

// TestEnrollmentEndpointsAccessibleWithoutAuth tests that enrollment
// endpoints are accessible without DPoP authentication.
func TestEnrollmentEndpointsAccessibleWithoutAuth(t *testing.T) {
	t.Log("Testing enrollment endpoints are accessible without DPoP authentication")

	_, handler, _ := setupAuthTestServer(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{"POST", "/enroll/complete"},
		{"POST", "/enroll/dpu/init"},
	}

	for _, ep := range endpoints {
		t.Logf("Testing %s %s without DPoP header", ep.method, ep.path)
		req := httptest.NewRequest(ep.method, ep.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		t.Logf("Response status: %d", w.Code)

		// Should not be 401 (auth should be bypassed)
		assert.NotEqual(t, http.StatusUnauthorized, w.Code,
			"%s %s should not require auth", ep.method, ep.path)
	}

	t.Log("Enrollment endpoints correctly accessible without auth")
}

// TestSuspendedKeymakerRejected tests that suspended keymakers are rejected
// with 403 Forbidden.
func TestSuspendedKeymakerRejected(t *testing.T) {
	t.Log("Testing suspended keymaker is rejected with 403")

	_, handler, s := setupAuthTestServer(t)

	// Create operator and keymaker
	t.Log("Creating operator and suspended keymaker")
	err := s.CreateOperator("op_suspended", "suspended@example.com", "Suspended Op")
	require.NoError(t, err)

	pub, priv := generateTestKeyPair(t)
	kid := "km_" + uuid.New().String()[:8]
	km := &store.KeyMaker{
		ID:             kid,
		OperatorID:     "op_suspended",
		Name:           "Suspended Device",
		Platform:       "linux",
		SecureElement:  "tpm",
		PublicKey:      base64.StdEncoding.EncodeToString(pub),
		Status:         "suspended", // Suspended status
		Kid:            kid,
		KeyFingerprint: "suspended-fingerprint",
		BoundAt:        time.Now(),
	}
	err = s.CreateKeyMaker(km)
	require.NoError(t, err)

	// Generate proof
	proof := generateDPoPProof(t, priv, kid, "GET", testHTU("/api/v1/operators"))

	// Make request
	t.Log("Making request with suspended keymaker proof")
	req := httptest.NewRequest("GET", "/api/v1/operators", nil)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Log("Verifying response is 403 Forbidden")
	assert.Equal(t, http.StatusForbidden, w.Code, "expected 403 for suspended keymaker")

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "auth.suspended", resp["error"])

	t.Log("Suspended keymaker correctly rejected with 403")
}

// TestRevokedKeymakerRejected tests that revoked keymakers are rejected
// with 401 Unauthorized.
func TestRevokedKeymakerRejected(t *testing.T) {
	t.Log("Testing revoked keymaker is rejected with 401")

	_, handler, s := setupAuthTestServer(t)

	// Create operator and keymaker
	t.Log("Creating operator and revoked keymaker")
	err := s.CreateOperator("op_revoked", "revoked@example.com", "Revoked Op")
	require.NoError(t, err)

	pub, priv := generateTestKeyPair(t)
	kid := "km_" + uuid.New().String()[:8]
	km := &store.KeyMaker{
		ID:             kid,
		OperatorID:     "op_revoked",
		Name:           "Revoked Device",
		Platform:       "windows",
		SecureElement:  "software",
		PublicKey:      base64.StdEncoding.EncodeToString(pub),
		Status:         "revoked", // Revoked status
		Kid:            kid,
		KeyFingerprint: "revoked-fingerprint",
		BoundAt:        time.Now(),
	}
	err = s.CreateKeyMaker(km)
	require.NoError(t, err)

	// Generate proof
	proof := generateDPoPProof(t, priv, kid, "GET", testHTU("/api/v1/operators"))

	// Make request
	t.Log("Making request with revoked keymaker proof")
	req := httptest.NewRequest("GET", "/api/v1/operators", nil)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Log("Verifying response is 401 Unauthorized")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "expected 401 for revoked keymaker")

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "auth.revoked", resp["error"])

	t.Log("Revoked keymaker correctly rejected with 401")
}

// TestUnknownKidRejected tests that requests with unknown kid are rejected.
func TestUnknownKidRejected(t *testing.T) {
	t.Log("Testing unknown kid is rejected with 401")

	_, handler, _ := setupAuthTestServer(t)

	// Generate proof with unknown kid
	_, priv := generateTestKeyPair(t)
	kid := "km_unknown_kid"
	proof := generateDPoPProof(t, priv, kid, "GET", testHTU("/api/v1/operators"))

	t.Log("Making request with unknown kid")
	req := httptest.NewRequest("GET", "/api/v1/operators", nil)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Log("Verifying response is 401 Unauthorized")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "expected 401 for unknown kid")

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "dpop.unknown_key", resp["error"])

	t.Log("Unknown kid correctly rejected with 401")
}

// TestCORSIncludesDPoPHeader tests that CORS headers include DPoP.
func TestCORSIncludesDPoPHeader(t *testing.T) {
	t.Log("Testing CORS headers include DPoP in Allow-Headers")

	_, handler, _ := setupAuthTestServer(t)

	t.Log("Making OPTIONS preflight request")
	req := httptest.NewRequest("OPTIONS", "/api/v1/operators", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "DPoP")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	t.Log("Verifying Access-Control-Allow-Headers includes DPoP")
	allowHeaders := w.Header().Get("Access-Control-Allow-Headers")
	assert.Contains(t, allowHeaders, "DPoP", "CORS should allow DPoP header")

	t.Log("CORS correctly includes DPoP in allowed headers")
}

// readCloser is a simple io.ReadCloser wrapper for test request bodies.
type readCloser struct {
	data   []byte
	offset int
}

func (r *readCloser) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, context.DeadlineExceeded // EOF
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *readCloser) Close() error {
	return nil
}
