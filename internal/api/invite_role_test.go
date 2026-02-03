package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
	"github.com/google/uuid"
)

// TestInviteOperator_ValidRoles tests that all valid role values are accepted.
func TestInviteOperator_ValidRoles(t *testing.T) {
	t.Log("Testing invite with all valid role values: operator, tenant:admin, super:admin")

	validRoles := []string{"operator", "tenant:admin", "super:admin"}

	for _, role := range validRoles {
		t.Run("role_"+role, func(t *testing.T) {
			server, mux := setupTestServer(t)

			// Create tenant
			tenantID := uuid.New().String()[:8]
			if err := server.store.AddTenant(tenantID, "TestCorp", "Test", "admin@test.com", []string{}); err != nil {
				t.Fatalf("failed to create tenant: %v", err)
			}

			// Create invite request
			body := InviteOperatorRequest{
				Email:      "user-" + role + "@test.com",
				TenantName: "TestCorp",
				Role:       role,
			}
			bodyBytes, _ := json.Marshal(body)

			req := httptest.NewRequest("POST", "/api/v1/operators/invite", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusCreated {
				t.Errorf("expected status 201 for role '%s', got %d: %s", role, w.Code, w.Body.String())
			}

			var resp InviteOperatorResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.InviteCode == "" {
				t.Errorf("expected non-empty invite code for role '%s'", role)
			}

			t.Logf("Successfully created invite for role '%s': code=%s", role, resp.InviteCode)
		})
	}
}

// TestInviteOperator_InvalidRole tests that invalid role values are rejected.
func TestInviteOperator_InvalidRole(t *testing.T) {
	t.Log("Testing invite with invalid role values")

	invalidRoles := []string{"admin", "user", "superadmin", "tenant-admin", "OPERATOR", "Admin"}

	for _, role := range invalidRoles {
		t.Run("invalid_role_"+role, func(t *testing.T) {
			server, mux := setupTestServer(t)

			// Create tenant
			tenantID := uuid.New().String()[:8]
			if err := server.store.AddTenant(tenantID, "TestCorp", "Test", "admin@test.com", []string{}); err != nil {
				t.Fatalf("failed to create tenant: %v", err)
			}

			body := InviteOperatorRequest{
				Email:      "user@test.com",
				TenantName: "TestCorp",
				Role:       role,
			}
			bodyBytes, _ := json.Marshal(body)

			req := httptest.NewRequest("POST", "/api/v1/operators/invite", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected status 400 for invalid role '%s', got %d: %s", role, w.Code, w.Body.String())
			}

			var result map[string]string
			json.NewDecoder(w.Body).Decode(&result)
			if result["error"] == "" {
				t.Errorf("expected error message for invalid role '%s'", role)
			}
			t.Logf("Correctly rejected invalid role '%s': %s", role, result["error"])
		})
	}
}

// TestInviteOperator_DefaultRole tests that role defaults to 'operator' when not specified.
func TestInviteOperator_DefaultRole(t *testing.T) {
	t.Log("Testing invite defaults to 'operator' role when not specified")

	server, mux := setupTestServer(t)

	// Create tenant
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "TestCorp", "Test", "admin@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create invite without role
	body := InviteOperatorRequest{
		Email:      "user@test.com",
		TenantName: "TestCorp",
		// Role intentionally omitted
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/operators/invite", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the operator was added with 'operator' role
	op, err := server.store.GetOperatorByEmail("user@test.com")
	if err != nil {
		t.Fatalf("failed to get operator: %v", err)
	}

	tenant, _ := server.store.GetTenant("TestCorp")
	role, err := server.store.GetOperatorRole(op.ID, tenant.ID)
	if err != nil {
		t.Fatalf("failed to get operator role: %v", err)
	}

	if role != "operator" {
		t.Errorf("expected default role 'operator', got '%s'", role)
	}

	t.Logf("Verified default role is 'operator': %s", role)
}

// TestInviteOperator_RoleAuthorizationCheck tests that callers cannot invite with role higher than their own.
func TestInviteOperator_RoleAuthorizationCheck(t *testing.T) {
	t.Log("Testing role authorization: caller cannot invite with role higher than their own")

	tests := []struct {
		name           string
		callerRole     string
		requestedRole  string
		shouldSucceed  bool
		expectedStatus int
	}{
		// Operator can only invite operators
		{"operator_invites_operator", "operator", "operator", true, http.StatusCreated},
		{"operator_invites_tenant_admin", "operator", "tenant:admin", false, http.StatusForbidden},
		{"operator_invites_super_admin", "operator", "super:admin", false, http.StatusForbidden},

		// Tenant admin can invite operator or tenant admin
		{"tenant_admin_invites_operator", "tenant:admin", "operator", true, http.StatusCreated},
		{"tenant_admin_invites_tenant_admin", "tenant:admin", "tenant:admin", true, http.StatusCreated},
		{"tenant_admin_invites_super_admin", "tenant:admin", "super:admin", false, http.StatusForbidden},

		// Super admin can invite anyone
		{"super_admin_invites_operator", "super:admin", "operator", true, http.StatusCreated},
		{"super_admin_invites_tenant_admin", "super:admin", "tenant:admin", true, http.StatusCreated},
		{"super_admin_invites_super_admin", "super:admin", "super:admin", true, http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, mux := setupTestServer(t)

			// Create tenant
			tenantID := uuid.New().String()[:8]
			if err := server.store.AddTenant(tenantID, "TestCorp", "Test", "admin@test.com", []string{}); err != nil {
				t.Fatalf("failed to create tenant: %v", err)
			}

			// Create caller operator with specified role
			callerID := "op_" + uuid.New().String()[:8]
			if err := server.store.CreateOperator(callerID, "caller@test.com", "Caller"); err != nil {
				t.Fatalf("failed to create caller operator: %v", err)
			}
			if err := server.store.AddOperatorToTenant(callerID, tenantID, tt.callerRole); err != nil {
				t.Fatalf("failed to add caller to tenant: %v", err)
			}

			// Create a keymaker for the caller
			kmID := "km_" + uuid.New().String()[:8]
			km := &store.KeyMaker{
				ID:         kmID,
				OperatorID: callerID,
				Name:       "caller-km",
				Platform:   "darwin",
				PublicKey:  "test-key",
				Status:     "active",
			}
			if err := server.store.CreateKeyMaker(km); err != nil {
				t.Fatalf("failed to create keymaker: %v", err)
			}

			// Create invite request
			body := InviteOperatorRequest{
				Email:      "newuser-" + uuid.New().String()[:4] + "@test.com",
				TenantName: "TestCorp",
				Role:       tt.requestedRole,
			}
			bodyBytes, _ := json.Marshal(body)

			req := httptest.NewRequest("POST", "/api/v1/operators/invite", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			// Set caller identity in context
			identity := &dpop.Identity{
				KID:        kmID,
				CallerType: dpop.CallerTypeKeyMaker,
				Status:     dpop.IdentityStatusActive,
				OperatorID: callerID,
			}
			ctx := dpop.ContextWithIdentity(req.Context(), identity)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.shouldSucceed {
				t.Logf("Caller with role '%s' successfully invited with role '%s'", tt.callerRole, tt.requestedRole)
			} else {
				t.Logf("Caller with role '%s' correctly blocked from inviting with role '%s'", tt.callerRole, tt.requestedRole)
			}
		})
	}
}

// TestInviteOperator_SuperAdminGlobalAccess tests that super:admin in any tenant has global access.
func TestInviteOperator_SuperAdminGlobalAccess(t *testing.T) {
	t.Log("Testing super:admin global access: can invite to any tenant")

	server, mux := setupTestServer(t)

	// Create two tenants
	tenant1ID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenant1ID, "Tenant1", "First tenant", "admin@t1.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant1: %v", err)
	}

	tenant2ID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenant2ID, "Tenant2", "Second tenant", "admin@t2.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant2: %v", err)
	}

	// Create super:admin in tenant1
	superAdminID := "op_" + uuid.New().String()[:8]
	if err := server.store.CreateOperator(superAdminID, "superadmin@test.com", "Super Admin"); err != nil {
		t.Fatalf("failed to create super admin: %v", err)
	}
	if err := server.store.AddOperatorToTenant(superAdminID, tenant1ID, "super:admin"); err != nil {
		t.Fatalf("failed to add super admin to tenant1: %v", err)
	}

	// Create keymaker for super admin
	kmID := "km_" + uuid.New().String()[:8]
	km := &store.KeyMaker{
		ID:         kmID,
		OperatorID: superAdminID,
		Name:       "superadmin-km",
		Platform:   "darwin",
		PublicKey:  "test-key",
		Status:     "active",
	}
	if err := server.store.CreateKeyMaker(km); err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}

	// Super admin should be able to invite super:admin to tenant2 (different tenant)
	body := InviteOperatorRequest{
		Email:      "newadmin@test.com",
		TenantName: "Tenant2",
		Role:       "super:admin",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/operators/invite", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	identity := &dpop.Identity{
		KID:        kmID,
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: superAdminID,
	}
	ctx := dpop.ContextWithIdentity(req.Context(), identity)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("super:admin should have global access, expected 201, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verified super:admin in tenant1 can invite super:admin to tenant2")
}

// TestIsSuperAdmin tests the IsSuperAdmin store function.
func TestIsSuperAdmin(t *testing.T) {
	t.Log("Testing IsSuperAdmin store function")

	server, _ := setupTestServer(t)

	// Create tenant
	tenantID := uuid.New().String()[:8]
	if err := server.store.AddTenant(tenantID, "TestCorp", "Test", "admin@test.com", []string{}); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	tests := []struct {
		name     string
		role     string
		expected bool
	}{
		{"operator_not_super_admin", "operator", false},
		{"tenant_admin_not_super_admin", "tenant:admin", false},
		{"super_admin_is_super_admin", "super:admin", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opID := "op_" + uuid.New().String()[:8]
			if err := server.store.CreateOperator(opID, tt.name+"@test.com", "Test"); err != nil {
				t.Fatalf("failed to create operator: %v", err)
			}
			if err := server.store.AddOperatorToTenant(opID, tenantID, tt.role); err != nil {
				t.Fatalf("failed to add operator to tenant: %v", err)
			}

			isSuperAdmin, err := server.store.IsSuperAdmin(opID)
			if err != nil {
				t.Fatalf("IsSuperAdmin failed: %v", err)
			}

			if isSuperAdmin != tt.expected {
				t.Errorf("IsSuperAdmin for role '%s': expected %v, got %v", tt.role, tt.expected, isSuperAdmin)
			}

			t.Logf("Role '%s' -> IsSuperAdmin: %v (expected %v)", tt.role, isSuperAdmin, tt.expected)
		})
	}
}

// TestServerConfig_AttestationStaleness tests the attestation staleness configuration.
func TestServerConfig_AttestationStaleness(t *testing.T) {
	t.Log("Testing attestation staleness configuration")

	tests := []struct {
		name           string
		staleAfter     time.Duration
		expectedWindow time.Duration
	}{
		{"default_1hour", 0, time.Hour},                          // 0 means use default
		{"custom_30min", 30 * time.Minute, 30 * time.Minute},
		{"custom_2hours", 2 * time.Hour, 2 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpStore := setupTempStore(t)
			defer tmpStore.Close()

			var server *Server
			if tt.staleAfter == 0 {
				server = NewServer(tmpStore)
			} else {
				server = NewServerWithConfig(tmpStore, ServerConfig{
					AttestationStaleAfter: tt.staleAfter,
				})
			}

			gate := server.Gate()
			if gate.FreshnessWindow != tt.expectedWindow {
				t.Errorf("expected FreshnessWindow %v, got %v", tt.expectedWindow, gate.FreshnessWindow)
			}

			t.Logf("Config staleAfter=%v -> Gate.FreshnessWindow=%v", tt.staleAfter, gate.FreshnessWindow)
		})
	}
}

// setupTempStore creates a temporary store for testing.
func setupTempStore(t *testing.T) *store.Store {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store.SetInsecureMode(true)
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}

	return s
}
