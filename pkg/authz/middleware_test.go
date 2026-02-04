package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
)

// mockPrincipalLookup implements PrincipalLookup for testing.
type mockPrincipalLookup struct {
	principal *Principal
	err       error
}

func (m *mockPrincipalLookup) LookupPrincipal(ctx context.Context, identity *dpop.Identity) (*Principal, error) {
	return m.principal, m.err
}

// mockResourceExtractor implements ResourceExtractor for testing.
type mockResourceExtractor struct {
	resource *Resource
	err      error
}

func (m *mockResourceExtractor) ExtractResource(r *http.Request, action Action, principal *Principal) (*Resource, error) {
	return m.resource, m.err
}

// mockAttestationLookup implements AttestationLookup for testing.
type mockAttestationLookup struct {
	status AttestationStatus
	err    error
}

func (m *mockAttestationLookup) GetAttestationStatus(ctx context.Context, dpuID string) (AttestationStatus, error) {
	return m.status, m.err
}

func TestMiddleware_PreAuthBypass(t *testing.T) {
	t.Log("Testing that pre-auth endpoints bypass authorization")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{},
		&mockResourceExtractor{},
	)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	t.Log("Requesting GET /health (pre-auth endpoint)")
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for pre-auth endpoint")
	}

	t.Log("Pre-auth endpoint correctly bypassed authorization")
}

func TestMiddleware_UnknownRouteBlocked(t *testing.T) {
	t.Log("Testing that unknown routes return 404 (fail-secure)")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	principal := &Principal{
		UID:       "km_test123",
		Type:      PrincipalOperator,
		Role:      RoleOperator,
		TenantIDs: []string{"tenant1"},
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: &Resource{UID: "res1", Type: "Unknown", TenantID: "tenant1"}},
	)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	t.Log("Requesting GET /unknown/route (not in registry)")
	req := httptest.NewRequest("GET", "/unknown/route", nil)
	// Add identity to context to simulate authenticated request
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_test123",
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_123",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
	if handlerCalled {
		t.Error("handler should NOT have been called for unknown route")
	}

	// Verify error response
	var errResp map[string]string
	json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["error"] != ErrCodeUnknownRoute {
		t.Errorf("expected error code %q, got %q", ErrCodeUnknownRoute, errResp["error"])
	}

	t.Log("Unknown route correctly returned 404 with authz.unknown_route error")
}

func TestMiddleware_NoIdentityReturns401(t *testing.T) {
	t.Log("Testing that missing identity returns 401")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{},
		&mockResourceExtractor{},
	)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without identity")
	}))

	t.Log("Requesting authenticated endpoint without identity in context")
	req := httptest.NewRequest("GET", "/api/v1/dpus", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	t.Log("Missing identity correctly returned 401")
}

func TestMiddleware_PolicyPermit(t *testing.T) {
	t.Log("Testing that permitted requests pass through to handler")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	// Super admin should be permitted for all actions
	principal := &Principal{
		UID:       "km_admin123",
		Type:      PrincipalOperator,
		Role:      RoleSuperAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_test",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
	)

	handlerCalled := false
	var capturedDecision *AuthzDecision
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		capturedDecision = DecisionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	t.Log("Super admin requesting GET /api/v1/dpus (dpu:list)")
	req := httptest.NewRequest("GET", "/api/v1/dpus", nil)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_admin123",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_admin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for permitted request")
	}
	if capturedDecision == nil {
		t.Error("decision should be in context")
	} else if !capturedDecision.Allowed {
		t.Error("decision should be allowed")
	}

	t.Log("Permitted request correctly passed through with decision in context")
}

func TestMiddleware_PolicyDeny(t *testing.T) {
	t.Log("Testing that denied requests return 403")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	// Operator without explicit authorization
	principal := &Principal{
		UID:       "km_user123",
		Type:      PrincipalOperator,
		Role:      RoleOperator,
		TenantIDs: []string{"tenant1"},
	}

	// Resource in a different tenant
	resource := &Resource{
		UID:      "dpu_other",
		Type:     "DPU",
		TenantID: "tenant2",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
	)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	t.Log("Operator requesting DPU in different tenant")
	req := httptest.NewRequest("GET", "/api/v1/dpus/dpu_other", nil)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_user123",
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_user",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
	if handlerCalled {
		t.Error("handler should NOT have been called for denied request")
	}

	// Verify error response
	var errResp map[string]string
	json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["error"] != ErrCodeForbidden {
		t.Errorf("expected error code %q, got %q", ErrCodeForbidden, errResp["error"])
	}

	t.Log("Denied request correctly returned 403 with authz.forbidden error")
}

func TestMiddleware_AttestationStale_Operator(t *testing.T) {
	t.Log("Testing that stale attestation blocks operators with 412")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	// Operator (not super admin)
	principal := &Principal{
		UID:       "km_user123",
		Type:      PrincipalOperator,
		Role:      RoleOperator,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_stale",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
		WithAttestationLookup(&mockAttestationLookup{status: AttestationStale}),
	)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for stale attestation")
	}))

	t.Log("Operator requesting credential:push with stale attestation")
	req := httptest.NewRequest("POST", "/api/v1/push", nil)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_user123",
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_user",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("expected status 412, got %d", rec.Code)
	}

	// Verify error response contains attestation error
	var errResp map[string]string
	json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["error"] != ErrCodeAttestationStale {
		t.Errorf("expected error code %q, got %q", ErrCodeAttestationStale, errResp["error"])
	}

	t.Log("Stale attestation correctly returned 412 for operator")
}

func TestMiddleware_AttestationStale_SuperAdminWithBypass(t *testing.T) {
	t.Log("Testing that super:admin can bypass stale attestation with X-Force-Bypass header")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	// Super admin
	principal := &Principal{
		UID:       "km_admin123",
		Type:      PrincipalOperator,
		Role:      RoleSuperAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_stale",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
		WithAttestationLookup(&mockAttestationLookup{status: AttestationStale}),
	)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	t.Log("Super admin requesting credential:push with stale attestation and X-Force-Bypass")
	req := httptest.NewRequest("POST", "/api/v1/push", nil)
	req.Header.Set("X-Force-Bypass", "emergency maintenance")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_admin123",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_admin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called with force bypass")
	}

	t.Log("Super admin successfully bypassed stale attestation with X-Force-Bypass")
}

func TestMiddleware_AttestationFailed_NoBypass(t *testing.T) {
	t.Log("Testing that failed attestation cannot be bypassed even by super:admin")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	// Super admin (highest privilege)
	principal := &Principal{
		UID:       "km_admin123",
		Type:      PrincipalOperator,
		Role:      RoleSuperAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_failed",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
		WithAttestationLookup(&mockAttestationLookup{status: AttestationFailed}),
	)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called for failed attestation")
	}))

	t.Log("Super admin requesting credential:push with failed attestation and X-Force-Bypass")
	req := httptest.NewRequest("POST", "/api/v1/push", nil)
	req.Header.Set("X-Force-Bypass", "emergency maintenance") // Even with bypass header, should be rejected
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_admin123",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_admin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("expected status 412, got %d", rec.Code)
	}

	// Verify error response
	var errResp map[string]string
	json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["error"] != ErrCodeAttestationFailed {
		t.Errorf("expected error code %q, got %q", ErrCodeAttestationFailed, errResp["error"])
	}

	t.Log("Failed attestation correctly blocked even with force bypass (hard deny)")
}

func TestMiddleware_DecisionInContext(t *testing.T) {
	t.Log("Testing that authorization decision is available in handler context")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	principal := &Principal{
		UID:       "km_admin123",
		Type:      PrincipalOperator,
		Role:      RoleSuperAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_test",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
	)

	var capturedDecision *AuthzDecision
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedDecision = DecisionFromContext(r.Context())
		t.Logf("Decision in handler: Allowed=%v, PolicyID=%s", capturedDecision.Allowed, capturedDecision.PolicyID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/dpus", nil)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_admin123",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_admin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedDecision == nil {
		t.Fatal("decision should be available in context")
	}
	if !capturedDecision.Allowed {
		t.Error("decision should be allowed for super:admin")
	}
	if capturedDecision.Duration == 0 {
		t.Error("decision should have a duration")
	}

	t.Log("Authorization decision correctly passed to handler in context")
}

func TestMiddleware_DPUSelfAccess(t *testing.T) {
	t.Log("Testing that DPU can access its own config (self-referential)")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	// DPU principal
	principal := &Principal{
		UID:       "dpu_test123",
		Type:      PrincipalDPU,
		Role:      RoleOperator,
		TenantIDs: []string{"tenant1"},
	}

	// Resource is the DPU itself
	resource := &Resource{
		UID:      "dpu_test123",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
		WithAttestationLookup(&mockAttestationLookup{status: AttestationVerified}),
	)

	handlerCalled := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	t.Log("DPU requesting its own config")
	req := httptest.NewRequest("GET", "/api/v1/dpus/dpu_test123/config", nil)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "dpu_test123",
		CallerType: dpop.CallerTypeDPU,
		Status:     dpop.IdentityStatusActive,
		TenantID:   "tenant1",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Error("handler should have been called for DPU self-access")
	}

	t.Log("DPU self-access correctly permitted")
}

func TestMiddleware_ForceBypass_EmptyReason(t *testing.T) {
	t.Log("Testing that X-Force-Bypass with empty reason is rejected")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	principal := &Principal{
		UID:       "km_admin123",
		Type:      PrincipalOperator,
		Role:      RoleSuperAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_stale",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
		WithAttestationLookup(&mockAttestationLookup{status: AttestationStale}),
	)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called with empty bypass reason")
	}))

	t.Log("Super admin requesting with X-Force-Bypass set to empty string")
	req := httptest.NewRequest("POST", "/api/v1/push", nil)
	req.Header.Set("X-Force-Bypass", "") // Empty reason
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_admin123",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_admin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("expected status 412, got %d", rec.Code)
	}

	t.Log("Empty bypass reason correctly rejected")
}

func TestMiddleware_ForceBypass_NoHeader_BypassAvailable(t *testing.T) {
	t.Log("Testing that super:admin without X-Force-Bypass gets 412 with bypass_available=true")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	principal := &Principal{
		UID:       "km_admin123",
		Type:      PrincipalOperator,
		Role:      RoleSuperAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_stale",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
		WithAttestationLookup(&mockAttestationLookup{status: AttestationStale}),
	)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called without bypass header")
	}))

	t.Log("Super admin requesting with stale attestation but no X-Force-Bypass header")
	req := httptest.NewRequest("POST", "/api/v1/push", nil)
	// No X-Force-Bypass header
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_admin123",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_admin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("expected status 412, got %d", rec.Code)
	}

	// Verify response indicates bypass is available
	var errResp map[string]any
	json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["bypass_available"] != true {
		t.Errorf("expected bypass_available=true in response, got %v", errResp["bypass_available"])
	}

	t.Log("Super admin correctly received 412 with bypass_available=true")
}

func TestMiddleware_ForceBypass_TenantAdmin_Rejected(t *testing.T) {
	t.Log("Testing that tenant:admin cannot use force bypass (only super:admin)")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	// Tenant admin (not super admin)
	principal := &Principal{
		UID:       "km_tadmin123",
		Type:      PrincipalOperator,
		Role:      RoleTenantAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_stale",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
		WithAttestationLookup(&mockAttestationLookup{status: AttestationStale}),
	)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should NOT be called for tenant:admin with force bypass")
	}))

	t.Log("Tenant admin requesting with stale attestation and X-Force-Bypass header")
	req := httptest.NewRequest("POST", "/api/v1/push", nil)
	req.Header.Set("X-Force-Bypass", "emergency maintenance")
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_tadmin123",
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_tadmin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Tenant admin should be blocked regardless of bypass header
	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("expected status 412, got %d", rec.Code)
	}

	// Verify bypass is NOT available for tenant:admin
	var errResp map[string]any
	json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["bypass_available"] == true {
		t.Errorf("bypass_available should NOT be true for tenant:admin")
	}

	t.Log("Tenant admin correctly rejected, force bypass not available")
}

func TestMiddleware_RequestIDGeneration(t *testing.T) {
	t.Log("Testing that request ID is generated and available in context")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	principal := &Principal{
		UID:       "km_admin123",
		Type:      PrincipalOperator,
		Role:      RoleSuperAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_test",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
	)

	var capturedRequestID string
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequestID = RequestIDFromContext(r.Context())
		t.Logf("Request ID in handler: %s", capturedRequestID)
		w.WriteHeader(http.StatusOK)
	}))

	t.Log("Making request without X-Request-ID header")
	req := httptest.NewRequest("GET", "/api/v1/dpus", nil)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_admin123",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_admin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRequestID == "" {
		t.Error("request ID should be generated when not provided")
	}

	t.Logf("Request ID was generated: %s", capturedRequestID)
}

func TestMiddleware_RequestIDPassthrough(t *testing.T) {
	t.Log("Testing that provided X-Request-ID header is preserved")

	registry := NewActionRegistry()
	authorizer, _ := NewAuthorizer(Config{})

	principal := &Principal{
		UID:       "km_admin123",
		Type:      PrincipalOperator,
		Role:      RoleSuperAdmin,
		TenantIDs: []string{"tenant1"},
	}

	resource := &Resource{
		UID:      "dpu_test",
		Type:     "DPU",
		TenantID: "tenant1",
	}

	middleware := NewAuthzMiddleware(
		authorizer,
		registry,
		&mockPrincipalLookup{principal: principal},
		&mockResourceExtractor{resource: resource},
	)

	var capturedRequestID string
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequestID = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	providedID := "custom-request-id-12345"
	t.Logf("Making request with X-Request-ID: %s", providedID)
	req := httptest.NewRequest("GET", "/api/v1/dpus", nil)
	req.Header.Set("X-Request-ID", providedID)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID:        "km_admin123",
		CallerType: dpop.CallerTypeAdmin,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op_admin",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRequestID != providedID {
		t.Errorf("expected request ID %q, got %q", providedID, capturedRequestID)
	}

	t.Log("Provided X-Request-ID correctly passed through")
}
