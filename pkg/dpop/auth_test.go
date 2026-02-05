package dpop

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// mockValidator is a mock ProofValidator for testing.
type mockValidator struct {
	result ProofValidationResult
}

func (m *mockValidator) Validate(proof, method, uri string) ProofValidationResult {
	return m.result
}

// mockIdentityLookup is a mock IdentityLookup for testing.
type mockIdentityLookup struct {
	identity *Identity
	err      error
}

func (m *mockIdentityLookup) LookupByKID(ctx context.Context, kid string) (*Identity, error) {
	return m.identity, m.err
}

// mockJTICache is a mock JTICache for testing.
type mockJTICache struct {
	isReplay bool
	err      error
}

func (m *mockJTICache) Record(jti string) (bool, error) {
	return m.isReplay, m.err
}

func (m *mockJTICache) Close() error {
	return nil
}

func newTestMiddleware(
	validator ProofValidator,
	identityLookup IdentityLookup,
	jtiCache JTICache,
	opts ...AuthMiddlewareOption,
) *AuthMiddleware {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	// Prepend logger option, then add any custom options
	allOpts := append([]AuthMiddlewareOption{WithLogger(logger)}, opts...)
	return NewAuthMiddleware(validator, identityLookup, jtiCache, allOpts...)
}

// newDebugTestMiddleware creates a test middleware with debug mode enabled.
// Use this for tests that verify detailed error codes.
func newDebugTestMiddleware(
	validator ProofValidator,
	identityLookup IdentityLookup,
	jtiCache JTICache,
) *AuthMiddleware {
	return newTestMiddleware(validator, identityLookup, jtiCache, WithDebugMode(true))
}

func TestValidProofToProtectedEndpoint(t *testing.T) {
	t.Parallel()
	t.Log("Testing valid proof to protected endpoint returns 200 with identity in context")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_abc123",
		JTI:   "test-jti-001",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:        "km_abc123",
		CallerType: CallerTypeKeyMaker,
		Status:     IdentityStatusActive,
		OperatorID: "op_xyz",
	}}
	cache := &mockJTICache{isReplay: false}

	middleware := newTestMiddleware(validator, lookup, cache)

	var capturedIdentity *Identity
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIdentity = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/operators/me", nil)
	req.Header.Set("DPoP", "valid.proof.here")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if capturedIdentity == nil {
		t.Error("identity not set in context")
	} else if capturedIdentity.KID != "km_abc123" {
		t.Errorf("expected kid km_abc123, got %s", capturedIdentity.KID)
	}
	t.Log("Valid proof to protected endpoint succeeded with identity in context")
}

func TestMissingProofToProtectedEndpoint(t *testing.T) {
	t.Parallel()
	t.Log("Testing missing proof to protected endpoint returns 401 dpop.missing_proof")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest("GET", "/api/v1/operators/me", nil)
	// No DPoP header
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
	if handlerCalled {
		t.Error("handler should not have been called")
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "dpop.missing_proof" {
		t.Errorf("expected error dpop.missing_proof, got %s", resp["error"])
	}
	t.Log("Missing proof correctly rejected with dpop.missing_proof")
}

func TestInvalidProofToProtectedEndpoint(t *testing.T) {
	t.Parallel()
	t.Log("Testing invalid proof to protected endpoint returns 401 with appropriate error")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: false,
		Code:  "dpop.invalid_proof",
		Error: "malformed JWT",
	}}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/operators/me", nil)
	req.Header.Set("DPoP", "invalid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "dpop.invalid_proof" {
		t.Errorf("expected error dpop.invalid_proof, got %s", resp["error"])
	}
	t.Log("Invalid proof correctly rejected with dpop.invalid_proof")
}

func TestReplayedJTI(t *testing.T) {
	t.Parallel()
	t.Log("Testing replayed jti returns 401 dpop.replay")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_abc123",
		JTI:   "replayed-jti-001",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_abc123",
		Status: IdentityStatusActive,
	}}
	cache := &mockJTICache{isReplay: true} // Replay detected

	middleware := newTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/operators/me", nil)
	req.Header.Set("DPoP", "replayed.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "dpop.replay" {
		t.Errorf("expected error dpop.replay, got %s", resp["error"])
	}
	t.Log("Replayed jti correctly rejected with dpop.replay")
}

func TestIdentitySuspended(t *testing.T) {
	t.Parallel()
	t.Log("Testing suspended identity returns 403 auth.suspended (debug mode)")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_suspended",
		JTI:   "test-jti-suspended",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_suspended",
		Status: IdentityStatusSuspended,
	}}
	cache := &mockJTICache{isReplay: false}

	// Use debug mode to get detailed error codes
	middleware := newDebugTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/operators/me", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Suspended returns 403, not 401
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "auth.suspended" {
		t.Errorf("expected error auth.suspended, got %s", resp["error"])
	}
	t.Log("Suspended identity correctly rejected with 403 auth.suspended")
}

func TestIdentityRevoked(t *testing.T) {
	t.Parallel()
	t.Log("Testing revoked identity returns 401 auth.revoked (debug mode)")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_revoked",
		JTI:   "test-jti-revoked",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_revoked",
		Status: IdentityStatusRevoked,
	}}
	cache := &mockJTICache{isReplay: false}

	// Use debug mode to get detailed error codes
	middleware := newDebugTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/operators/me", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "auth.revoked" {
		t.Errorf("expected error auth.revoked, got %s", resp["error"])
	}
	t.Log("Revoked identity correctly rejected with auth.revoked")
}

func TestBypassEndpointHealth(t *testing.T) {
	t.Parallel()
	t.Log("Testing /health without proof returns 200 (bypassed)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	// No DPoP header
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for bypass endpoint")
	}
	t.Log("/health correctly bypassed authentication")
}

func TestBypassEndpointReady(t *testing.T) {
	t.Parallel()
	t.Log("Testing /ready without proof returns 200 (bypassed)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/ready", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for bypass endpoint")
	}
	t.Log("/ready correctly bypassed authentication")
}

func TestBypassEndpointEnrollInit(t *testing.T) {
	t.Parallel()
	t.Log("Testing /api/v1/enroll/init without proof returns 200 (bypassed)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/enroll/init", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for bypass endpoint")
	}
	t.Log("/api/v1/enroll/init correctly bypassed authentication")
}

func TestBypassEndpointEnrollComplete(t *testing.T) {
	t.Parallel()
	t.Log("Testing /api/v1/enroll/complete without proof returns 200 (bypassed)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/enroll/complete", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for bypass endpoint")
	}
	t.Log("/api/v1/enroll/complete correctly bypassed authentication")
}

func TestBypassEndpointBootstrap(t *testing.T) {
	t.Parallel()
	t.Log("Testing /api/v1/admin/bootstrap without proof returns 200 (bypassed)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for bypass endpoint")
	}
	t.Log("/api/v1/admin/bootstrap correctly bypassed authentication")
}

func TestBypassEndpointEnrollDPUInit(t *testing.T) {
	t.Parallel()
	t.Log("Testing /api/v1/enroll/dpu/init without proof returns 200 (bypassed)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/enroll/dpu/init", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for bypass endpoint")
	}
	t.Log("/api/v1/enroll/dpu/init correctly bypassed authentication")
}

func TestOldEnrollPathsNotBypassed(t *testing.T) {
	t.Parallel()
	t.Log("Testing old /enroll/* paths are NOT bypassed (require auth)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	testCases := []struct {
		path string
	}{
		{"/enroll/init"},
		{"/enroll/complete"},
		{"/enroll/dpu/init"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			handlerCalled := false
			handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("POST", tc.path, nil)
			// No DPoP header
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d for path %s (old paths should require auth)", rec.Code, tc.path)
			}
			if handlerCalled {
				t.Errorf("handler should NOT have been called for old path %s", tc.path)
			}

			var resp map[string]string
			json.NewDecoder(rec.Body).Decode(&resp)
			if resp["error"] != "dpop.missing_proof" {
				t.Errorf("expected error dpop.missing_proof, got %s for path %s", resp["error"], tc.path)
			}
		})
	}
	t.Log("Old /enroll/* paths correctly require authentication")
}

func TestPathTraversalBlocked(t *testing.T) {
	t.Parallel()
	t.Log("Testing path traversal /health/../api/protected requires auth (not bypassed)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest("GET", "/health/../api/protected", nil)
	// No DPoP header
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Path normalizes to /api/protected which requires auth
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d (path traversal should not bypass auth)", rec.Code)
	}
	if handlerCalled {
		t.Error("handler should not have been called for path traversal attack")
	}
	t.Log("Path traversal correctly blocked")
}

func TestCaseInsensitiveBypass(t *testing.T) {
	t.Parallel()
	t.Log("Testing /HEALTH (uppercase) is bypassed consistently")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/HEALTH", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for bypass endpoint")
	}
	t.Log("/HEALTH (uppercase) correctly bypassed")
}

func TestURLEncodedBypass(t *testing.T) {
	t.Parallel()
	t.Log("Testing URL-encoded /health (%2Fhealth) is handled consistently")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	// URL-encoded path
	req := httptest.NewRequest("GET", "/%68%65%61%6c%74%68", nil) // /health URL-encoded
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for bypass endpoint")
	}
	t.Log("URL-encoded /health correctly bypassed")
}

func TestMiddlewarePanicRecovery(t *testing.T) {
	t.Parallel()
	t.Log("Testing middleware panic returns 500, does not call handler, and logs stack trace")

	// Create a validator that panics
	panicValidator := &panicValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	// Create middleware with a logger that captures output
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))
	middleware := NewAuthMiddleware(panicValidator, lookup, cache, WithLogger(logger))

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "trigger-panic")
	rec := httptest.NewRecorder()

	t.Log("Triggering panic in validator")
	handler.ServeHTTP(rec, req)

	t.Log("Verifying response status is 500")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 after panic, got %d", rec.Code)
	}

	t.Log("Verifying handler was not called after panic")
	if handlerCalled {
		t.Error("handler should not have been called after panic")
	}

	t.Log("Verifying stack trace was logged")
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "panic in auth middleware") {
		t.Error("expected panic error message in logs")
	}
	if !strings.Contains(logOutput, "stack=") {
		t.Error("expected stack trace in logs")
	}
	// Stack trace should contain the panic source function
	if !strings.Contains(logOutput, "panicValidator") {
		t.Error("expected stack trace to contain panic source (panicValidator)")
	}

	t.Log("Middleware panic correctly recovered with 500 and logged stack trace")
}

type panicValidator struct{}

func (p *panicValidator) Validate(proof, method, uri string) ProofValidationResult {
	panic("intentional panic for testing")
}

func TestErrorResponseContainsOnlyErrorCode(t *testing.T) {
	t.Parallel()
	t.Log("Testing error responses contain only error code, no sensitive details")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: false,
		Code:  "dpop.invalid_proof",
		Error: "internal error details that should not leak", // This should not appear in response
	}}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}

	middleware := newTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "invalid")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	body := rec.Body.String()

	// Response should only contain error code
	var resp map[string]string
	json.NewDecoder(strings.NewReader(body)).Decode(&resp)

	if resp["error"] != "dpop.invalid_proof" {
		t.Errorf("expected error code dpop.invalid_proof, got %s", resp["error"])
	}

	// Check no sensitive details leaked
	if strings.Contains(body, "internal error details") {
		t.Error("error response should not contain internal details")
	}

	t.Log("Error response correctly contains only error code")
}

func TestSanitizeForLog(t *testing.T) {
	t.Parallel()
	t.Log("Testing log sanitization prevents injection")

	tests := []struct {
		input    string
		expected string
	}{
		{"normal_kid", "normal_kid"},
		{"kid_with\nnewline", "kid_withnewline"},
		{"kid_with\ttab", "kid_withtab"},
		{"kid_with\rcarriage", "kid_withcarriage"},
		{strings.Repeat("a", 300), strings.Repeat("a", 256) + "..."},
	}

	for _, tc := range tests {
		result := sanitizeForLog(tc.input)
		if result != tc.expected {
			t.Errorf("sanitizeForLog(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
	t.Log("Log sanitization correctly handles injection attempts")
}

func TestIdentityContextNotFromHeader(t *testing.T) {
	t.Parallel()
	t.Log("Testing identity context cannot be spoofed via headers")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_real",
		JTI:   "test-jti-context",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_real",
		Status: IdentityStatusActive,
	}}
	cache := &mockJTICache{isReplay: false}

	middleware := newTestMiddleware(validator, lookup, cache)

	var capturedIdentity *Identity
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIdentity = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	// Attacker tries to inject identity via header
	req.Header.Set("X-Identity-KID", "km_attacker")
	req.Header.Set("X-Authenticated", "true")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Identity should come from middleware, not headers
	if capturedIdentity == nil {
		t.Fatal("identity not set in context")
	}
	if capturedIdentity.KID != "km_real" {
		t.Errorf("expected kid km_real from middleware, got %s (possible header injection)", capturedIdentity.KID)
	}
	t.Log("Identity context correctly comes from middleware, not headers")
}

func TestDecommissionedDPU(t *testing.T) {
	t.Parallel()
	t.Log("Testing decommissioned DPU returns 401 auth.decommissioned (debug mode)")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "dpu_decom",
		JTI:   "test-jti-decom",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:        "dpu_decom",
		CallerType: CallerTypeDPU,
		Status:     IdentityStatusDecommissioned,
	}}
	cache := &mockJTICache{isReplay: false}

	// Use debug mode to get detailed error codes
	middleware := newDebugTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "auth.decommissioned" {
		t.Errorf("expected error auth.decommissioned, got %s", resp["error"])
	}
	t.Log("Decommissioned DPU correctly rejected with auth.decommissioned")
}

func TestUnknownKID(t *testing.T) {
	t.Parallel()
	t.Log("Testing unknown kid returns 401 dpop.unknown_key (debug mode)")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_unknown",
		JTI:   "test-jti-unknown",
	}}
	lookup := &mockIdentityLookup{identity: nil} // KID not found
	cache := &mockJTICache{isReplay: false}

	// Use debug mode to get detailed error codes
	middleware := newDebugTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "dpop.unknown_key" {
		t.Errorf("expected error dpop.unknown_key, got %s", resp["error"])
	}
	t.Log("Unknown kid correctly rejected with dpop.unknown_key")
}

func TestNormalizePath(t *testing.T) {
	t.Parallel()
	t.Log("Testing path normalization")

	middleware := &AuthMiddleware{}

	tests := []struct {
		input    string
		expected string
	}{
		{"/health", "/health"},
		{"/HEALTH", "/health"},
		{"/Health", "/health"},
		{"/health/", "/health"},
		{"/health/../api", "/api"},
		{"/%68%65%61%6c%74%68", "/health"}, // URL-encoded /health
		{"/api/../health", "/health"},
		{"/api/./protected", "/api/protected"},
		{"/api//protected", "/api/protected"}, // Double slash
		{"/", "/"},
	}

	for _, tc := range tests {
		result := middleware.normalizePath(tc.input)
		if result != tc.expected {
			t.Errorf("normalizePath(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
	t.Log("Path normalization working correctly")
}

// capturingJTICache captures the JTI passed to Record for verification.
type capturingJTICache struct {
	capturedJTI string
	isReplay    bool
	err         error
}

func (c *capturingJTICache) Record(jti string) (bool, error) {
	c.capturedJTI = jti
	return c.isReplay, c.err
}

func (c *capturingJTICache) Close() error {
	return nil
}

func TestJTICacheReceivesActualJTI(t *testing.T) {
	t.Parallel()
	t.Log("Testing JTI cache receives the actual JTI claim, not the full proof string")

	// The expected JTI is a UUID (36 chars), not a full JWT (hundreds of chars)
	expectedJTI := "550e8400-e29b-41d4-a716-446655440000"

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_abc123",
		JTI:   expectedJTI, // Validator returns extracted JTI
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:        "km_abc123",
		CallerType: CallerTypeKeyMaker,
		Status:     IdentityStatusActive,
	}}
	cache := &capturingJTICache{isReplay: false}

	middleware := newTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create a fake proof that's much longer than a UUID to verify we don't use it
	longFakeProof := "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0In0.eyJqdGkiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJodG0iOiJHRVQiLCJodHUiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbS9hcGkvdjEvb3BlcmF0b3JzL21lIiwiaWF0IjoxNzA2NzA0MDAwfQ.signature_bytes_here_would_be_64_bytes_for_ed25519"

	req := httptest.NewRequest("GET", "/api/v1/operators/me", nil)
	req.Header.Set("DPoP", longFakeProof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	t.Logf("Captured JTI passed to cache: %q (length: %d)", cache.capturedJTI, len(cache.capturedJTI))

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Verify the cache received the actual JTI, not the full proof
	if cache.capturedJTI != expectedJTI {
		t.Errorf("JTI cache received %q, expected %q", cache.capturedJTI, expectedJTI)
	}

	// Sanity check: JTI should be UUID length (36 chars), not JWT length (hundreds)
	if len(cache.capturedJTI) > 100 {
		t.Errorf("JTI cache received full proof string (length %d), should receive UUID (36 chars)", len(cache.capturedJTI))
	}

	t.Log("JTI cache correctly receives the actual JTI claim, not the full proof")
}

// ============================================================================
// Production Mode Error Masking Tests
// Per security-architecture.md §5: In production mode (default), return generic
// "auth.failed" for lifecycle errors to prevent identity enumeration attacks.
// ============================================================================

func TestProductionModeRevokedMasked(t *testing.T) {
	t.Parallel()
	t.Log("Testing production mode masks auth.revoked as auth.failed")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_revoked",
		JTI:   "test-jti-prod-revoked",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_revoked",
		Status: IdentityStatusRevoked,
	}}
	cache := &mockJTICache{isReplay: false}

	// Production mode (no debug flag) should mask error codes
	middleware := newTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	// Production mode should return generic auth.failed
	if resp["error"] != "auth.failed" {
		t.Errorf("production mode should mask as auth.failed, got %s", resp["error"])
	}
	t.Log("Production mode correctly masks revoked as auth.failed")
}

func TestProductionModeSuspendedMasked(t *testing.T) {
	t.Parallel()
	t.Log("Testing production mode masks auth.suspended as auth.failed")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_suspended",
		JTI:   "test-jti-prod-suspended",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_suspended",
		Status: IdentityStatusSuspended,
	}}
	cache := &mockJTICache{isReplay: false}

	// Production mode should mask suspended as 401 (not 403) to prevent enumeration
	middleware := newTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Production mode: 401 to prevent status enumeration (not 403)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("production mode should return 401 (not 403), got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "auth.failed" {
		t.Errorf("production mode should mask as auth.failed, got %s", resp["error"])
	}
	t.Log("Production mode correctly masks suspended as 401 auth.failed")
}

func TestProductionModeDecommissionedMasked(t *testing.T) {
	t.Parallel()
	t.Log("Testing production mode masks auth.decommissioned as auth.failed")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "dpu_decom",
		JTI:   "test-jti-prod-decom",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:        "dpu_decom",
		CallerType: CallerTypeDPU,
		Status:     IdentityStatusDecommissioned,
	}}
	cache := &mockJTICache{isReplay: false}

	middleware := newTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "auth.failed" {
		t.Errorf("production mode should mask as auth.failed, got %s", resp["error"])
	}
	t.Log("Production mode correctly masks decommissioned as auth.failed")
}

func TestProductionModeUnknownKeyMasked(t *testing.T) {
	t.Parallel()
	t.Log("Testing production mode masks dpop.unknown_key as auth.failed")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_unknown",
		JTI:   "test-jti-prod-unknown",
	}}
	lookup := &mockIdentityLookup{identity: nil} // KID not found
	cache := &mockJTICache{isReplay: false}

	middleware := newTestMiddleware(validator, lookup, cache)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	// Production mode should mask unknown_key to prevent key enumeration
	if resp["error"] != "auth.failed" {
		t.Errorf("production mode should mask as auth.failed, got %s", resp["error"])
	}
	t.Log("Production mode correctly masks unknown_key as auth.failed")
}

// ============================================================================
// Audit Event Emission Tests
// Verify that auth.success and auth.failure events are emitted with correct fields.
// ============================================================================

// recordingAuditEmitter captures emitted events for test verification.
type recordingAuditEmitter struct {
	successEvents []auditSuccessEvent
	failureEvents []auditFailureEvent
}

type auditSuccessEvent struct {
	KID       string
	IP        string
	Method    string
	Path      string
	LatencyMS int64
}

type auditFailureEvent struct {
	KID    string
	IP     string
	Reason string
	Method string
	Path   string
}

func (r *recordingAuditEmitter) EmitAuthSuccess(kid, ip, method, path string, latencyMS int64) {
	r.successEvents = append(r.successEvents, auditSuccessEvent{
		KID: kid, IP: ip, Method: method, Path: path, LatencyMS: latencyMS,
	})
}

func (r *recordingAuditEmitter) EmitAuthFailure(kid, ip, reason, method, path string) {
	r.failureEvents = append(r.failureEvents, auditFailureEvent{
		KID: kid, IP: ip, Reason: reason, Method: method, Path: path,
	})
}

func TestAuditSuccessEvent(t *testing.T) {
	t.Parallel()
	t.Log("Testing auth.success audit event emitted with correct fields on valid authentication")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_audit_test",
		JTI:   "test-jti-audit-success",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:        "km_audit_test",
		CallerType: CallerTypeKeyMaker,
		Status:     IdentityStatusActive,
	}}
	cache := &mockJTICache{isReplay: false}
	recorder := &recordingAuditEmitter{}

	middleware := newTestMiddleware(validator, lookup, cache, WithAuditEmitter(recorder))

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/credentials/push", nil)
	req.Header.Set("DPoP", "valid.proof.here")
	req.RemoteAddr = "10.0.0.42:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	t.Log("Verifying response is 200 OK")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	t.Log("Verifying exactly one auth.success event emitted")
	if len(recorder.successEvents) != 1 {
		t.Fatalf("expected 1 success event, got %d", len(recorder.successEvents))
	}

	ev := recorder.successEvents[0]

	t.Logf("  kid=%s method=%s path=%s ip=%s latency_ms=%d",
		ev.KID, ev.Method, ev.Path, ev.IP, ev.LatencyMS)

	if ev.KID != "km_audit_test" {
		t.Errorf("kid = %q, want %q", ev.KID, "km_audit_test")
	}
	if ev.Method != "POST" {
		t.Errorf("method = %q, want %q", ev.Method, "POST")
	}
	if ev.Path != "/api/v1/credentials/push" {
		t.Errorf("path = %q, want %q", ev.Path, "/api/v1/credentials/push")
	}
	if ev.IP != "10.0.0.42" {
		t.Errorf("ip = %q, want %q", ev.IP, "10.0.0.42")
	}
	if ev.LatencyMS < 0 {
		t.Errorf("latency_ms = %d, expected >= 0", ev.LatencyMS)
	}

	t.Log("Verifying no failure events emitted")
	if len(recorder.failureEvents) != 0 {
		t.Errorf("expected 0 failure events, got %d", len(recorder.failureEvents))
	}

	t.Log("auth.success audit event correctly emitted with all required fields")
}

func TestAuditFailureEvent_MissingProof(t *testing.T) {
	t.Parallel()
	t.Log("Testing auth.failure audit event emitted when DPoP proof is missing")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}
	recorder := &recordingAuditEmitter{}

	middleware := newTestMiddleware(validator, lookup, cache, WithAuditEmitter(recorder))

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/operators/me", nil)
	// No DPoP header
	req.RemoteAddr = "192.168.1.50:8080"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	t.Log("Verifying exactly one auth.failure event emitted")
	if len(recorder.failureEvents) != 1 {
		t.Fatalf("expected 1 failure event, got %d", len(recorder.failureEvents))
	}

	ev := recorder.failureEvents[0]
	t.Logf("  kid=%q reason=%s method=%s path=%s ip=%s",
		ev.KID, ev.Reason, ev.Method, ev.Path, ev.IP)

	if ev.KID != "" {
		t.Errorf("kid = %q, want empty (no proof to extract kid from)", ev.KID)
	}
	if ev.Reason != "dpop.missing_proof" {
		t.Errorf("reason = %q, want %q", ev.Reason, "dpop.missing_proof")
	}
	if ev.Method != "GET" {
		t.Errorf("method = %q, want %q", ev.Method, "GET")
	}
	if ev.Path != "/api/v1/operators/me" {
		t.Errorf("path = %q, want %q", ev.Path, "/api/v1/operators/me")
	}
	if ev.IP != "192.168.1.50" {
		t.Errorf("ip = %q, want %q", ev.IP, "192.168.1.50")
	}

	t.Log("Verifying no success events emitted")
	if len(recorder.successEvents) != 0 {
		t.Errorf("expected 0 success events, got %d", len(recorder.successEvents))
	}

	t.Log("auth.failure audit event correctly emitted for missing proof")
}

func TestAuditFailureEvent_InvalidProof(t *testing.T) {
	t.Parallel()
	t.Log("Testing auth.failure audit event emitted for invalid proof with correct reason")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: false,
		KID:   "km_bad_proof",
		Code:  "dpop.invalid_proof",
		Error: "malformed JWT",
	}}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}
	recorder := &recordingAuditEmitter{}

	middleware := newTestMiddleware(validator, lookup, cache, WithAuditEmitter(recorder))

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("DELETE", "/api/v1/operators/op_123", nil)
	req.Header.Set("DPoP", "bad.proof.value")
	req.RemoteAddr = "172.16.0.1:9999"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if len(recorder.failureEvents) != 1 {
		t.Fatalf("expected 1 failure event, got %d", len(recorder.failureEvents))
	}

	ev := recorder.failureEvents[0]
	t.Logf("  kid=%s reason=%s method=%s path=%s", ev.KID, ev.Reason, ev.Method, ev.Path)

	if ev.KID != "km_bad_proof" {
		t.Errorf("kid = %q, want %q", ev.KID, "km_bad_proof")
	}
	if ev.Reason != "dpop.invalid_proof" {
		t.Errorf("reason = %q, want %q", ev.Reason, "dpop.invalid_proof")
	}
	if ev.Method != "DELETE" {
		t.Errorf("method = %q, want %q", ev.Method, "DELETE")
	}
	if ev.Path != "/api/v1/operators/op_123" {
		t.Errorf("path = %q, want %q", ev.Path, "/api/v1/operators/op_123")
	}

	t.Log("auth.failure audit event correctly emitted for invalid proof")
}

func TestAuditFailureEvent_RevokedIdentity(t *testing.T) {
	t.Parallel()
	t.Log("Testing auth.failure audit event emitted for revoked identity")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_revoked_audit",
		JTI:   "test-jti-audit-revoked",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_revoked_audit",
		Status: IdentityStatusRevoked,
	}}
	cache := &mockJTICache{isReplay: false}
	recorder := &recordingAuditEmitter{}

	middleware := newTestMiddleware(validator, lookup, cache, WithAuditEmitter(recorder))

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not have been called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if len(recorder.failureEvents) != 1 {
		t.Fatalf("expected 1 failure event, got %d", len(recorder.failureEvents))
	}

	ev := recorder.failureEvents[0]

	if ev.KID != "km_revoked_audit" {
		t.Errorf("kid = %q, want %q", ev.KID, "km_revoked_audit")
	}
	// Server-side audit always gets the detailed reason, regardless of debug mode
	if ev.Reason != "auth.revoked" {
		t.Errorf("reason = %q, want %q", ev.Reason, "auth.revoked")
	}

	t.Log("auth.failure audit event correctly emitted for revoked identity")
}

func TestAuditBypassNoEvent(t *testing.T) {
	t.Parallel()
	t.Log("Testing no audit events emitted for bypass paths (e.g., /health)")

	validator := &mockValidator{}
	lookup := &mockIdentityLookup{}
	cache := &mockJTICache{}
	recorder := &recordingAuditEmitter{}

	middleware := newTestMiddleware(validator, lookup, cache, WithAuditEmitter(recorder))

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	if len(recorder.successEvents) != 0 {
		t.Errorf("expected 0 success events for bypass path, got %d", len(recorder.successEvents))
	}
	if len(recorder.failureEvents) != 0 {
		t.Errorf("expected 0 failure events for bypass path, got %d", len(recorder.failureEvents))
	}

	t.Log("No audit events emitted for bypass paths")
}

func TestAuditNoProofContentInEvent(t *testing.T) {
	t.Parallel()
	t.Log("Testing that DPoP proof content never appears in audit events (no secrets logged)")

	// Use a distinctive proof string that we can search for in events
	secretProof := "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0In0.SECRET_PAYLOAD.SECRET_SIGNATURE"

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_no_secrets",
		JTI:   "test-jti-no-secrets",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_no_secrets",
		Status: IdentityStatusActive,
	}}
	cache := &mockJTICache{isReplay: false}
	recorder := &recordingAuditEmitter{}

	middleware := newTestMiddleware(validator, lookup, cache, WithAuditEmitter(recorder))

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", secretProof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if len(recorder.successEvents) != 1 {
		t.Fatalf("expected 1 success event, got %d", len(recorder.successEvents))
	}

	ev := recorder.successEvents[0]

	// Verify none of the event fields contain the proof content
	if strings.Contains(ev.KID, "SECRET") {
		t.Error("kid field contains proof content")
	}
	if strings.Contains(ev.IP, "SECRET") {
		t.Error("ip field contains proof content")
	}
	if strings.Contains(ev.Method, "SECRET") {
		t.Error("method field contains proof content")
	}
	if strings.Contains(ev.Path, "SECRET") {
		t.Error("path field contains proof content")
	}

	t.Log("Confirmed: proof content does not appear in audit events")
}

func TestAuditSuccessWithXForwardedFor(t *testing.T) {
	t.Parallel()
	t.Log("Testing audit event captures client IP from X-Forwarded-For header")

	validator := &mockValidator{result: ProofValidationResult{
		Valid: true,
		KID:   "km_xff",
		JTI:   "test-jti-xff",
	}}
	lookup := &mockIdentityLookup{identity: &Identity{
		KID:    "km_xff",
		Status: IdentityStatusActive,
	}}
	cache := &mockJTICache{isReplay: false}
	recorder := &recordingAuditEmitter{}

	middleware := newTestMiddleware(validator, lookup, cache, WithAuditEmitter(recorder))

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("DPoP", "valid.proof")
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	req.RemoteAddr = "10.0.0.1:9999"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if len(recorder.successEvents) != 1 {
		t.Fatalf("expected 1 success event, got %d", len(recorder.successEvents))
	}

	ev := recorder.successEvents[0]
	// X-Forwarded-For should take precedence, using the first IP
	if ev.IP != "203.0.113.50" {
		t.Errorf("ip = %q, want %q (first IP from X-Forwarded-For)", ev.IP, "203.0.113.50")
	}

	t.Log("Audit event correctly extracts client IP from X-Forwarded-For")
}
