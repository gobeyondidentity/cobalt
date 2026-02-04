package authz

import (
	"testing"
)

func TestActionRegistry_OperatorEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Operator endpoints map to correct actions")

	r := NewActionRegistry()

	tests := []struct {
		method string
		path   string
		expect Action
	}{
		{"GET", "/api/v1/operators/me", Action(ActionOperatorReadSelf)},
		{"POST", "/api/v1/operators/invite", Action(ActionOperatorInvite)},
		{"GET", "/api/v1/operators", Action(ActionOperatorList)},
		{"GET", "/api/v1/operators/km_alice", Action(ActionOperatorRead)},
		{"DELETE", "/api/v1/operators/km_bob", Action(ActionOperatorRevoke)},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			action, err := r.Lookup(tc.method, tc.path)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if action != tc.expect {
				t.Errorf("got %v, want %v", action, tc.expect)
			}
		})
	}
}

func TestActionRegistry_RoleEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Role management endpoints map to correct actions")

	r := NewActionRegistry()

	tests := []struct {
		method string
		path   string
		expect Action
	}{
		{"POST", "/api/v1/operators/km_alice/roles", Action(ActionRoleAssign)},
		{"DELETE", "/api/v1/operators/km_alice/roles/tnt_acme", Action(ActionRoleRemove)},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			action, err := r.Lookup(tc.method, tc.path)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if action != tc.expect {
				t.Errorf("got %v, want %v", action, tc.expect)
			}
		})
	}
}

func TestActionRegistry_DPUEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: DPU management endpoints map to correct actions")

	r := NewActionRegistry()

	tests := []struct {
		method string
		path   string
		expect Action
	}{
		{"GET", "/api/v1/dpus", Action(ActionDPUList)},
		{"GET", "/api/v1/dpus/dpu_xyz", Action(ActionDPURead)},
		{"POST", "/api/v1/dpus", Action(ActionDPURegister)},
		{"DELETE", "/api/v1/dpus/dpu_abc", Action(ActionDPUDelete)},
		{"GET", "/api/v1/dpus/dpu_xyz/attestation", Action(ActionDPUReadAttestation)},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			action, err := r.Lookup(tc.method, tc.path)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if action != tc.expect {
				t.Errorf("got %v, want %v", action, tc.expect)
			}
		})
	}
}

func TestActionRegistry_DPUAgentEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: DPU agent (Aegis) endpoints map to correct actions")

	r := NewActionRegistry()

	tests := []struct {
		method string
		path   string
		expect Action
	}{
		{"GET", "/api/v1/dpus/dpu_xyz/credentials", Action(ActionCredentialPull)},
		{"POST", "/api/v1/dpus/dpu_xyz/attestation", Action(ActionDPUReportAttestation)},
		{"GET", "/api/v1/dpus/dpu_xyz/config", Action(ActionDPUReadOwnConfig)},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			action, err := r.Lookup(tc.method, tc.path)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if action != tc.expect {
				t.Errorf("got %v, want %v", action, tc.expect)
			}
		})
	}
}

func TestActionRegistry_CredentialEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Credential distribution endpoints map to correct actions")

	r := NewActionRegistry()

	tests := []struct {
		method string
		path   string
		expect Action
	}{
		{"POST", "/api/v1/push", Action(ActionCredentialPush)},
		{"GET", "/api/v1/distributions", Action(ActionDistributionList)},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			action, err := r.Lookup(tc.method, tc.path)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if action != tc.expect {
				t.Errorf("got %v, want %v", action, tc.expect)
			}
		})
	}
}

func TestActionRegistry_AuthorizationEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Authorization management endpoints map to correct actions")

	r := NewActionRegistry()

	tests := []struct {
		method string
		path   string
		expect Action
	}{
		{"GET", "/api/v1/authorizations", Action(ActionAuthorizationList)},
		{"POST", "/api/v1/authorizations", Action(ActionAuthorizationCreate)},
		{"DELETE", "/api/v1/authorizations/auth_123", Action(ActionAuthorizationDelete)},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			action, err := r.Lookup(tc.method, tc.path)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if action != tc.expect {
				t.Errorf("got %v, want %v", action, tc.expect)
			}
		})
	}
}

func TestActionRegistry_TenantEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Tenant management endpoints map to correct actions")

	r := NewActionRegistry()

	tests := []struct {
		method string
		path   string
		expect Action
	}{
		{"POST", "/api/v1/tenants", Action(ActionTenantCreate)},
		{"GET", "/api/v1/tenants", Action(ActionTenantList)},
		{"DELETE", "/api/v1/tenants/tnt_acme", Action(ActionTenantDelete)},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			action, err := r.Lookup(tc.method, tc.path)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if action != tc.expect {
				t.Errorf("got %v, want %v", action, tc.expect)
			}
		})
	}
}

func TestActionRegistry_AuditEndpoint(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Audit endpoint maps to correct action")

	r := NewActionRegistry()

	action, err := r.Lookup("GET", "/api/v1/audit")
	if err != nil {
		t.Fatalf("Lookup error: %v", err)
	}
	if action != Action(ActionAuditExport) {
		t.Errorf("got %v, want %v", action, ActionAuditExport)
	}
}

func TestActionRegistry_PreAuthEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Pre-authentication endpoints return NoAuthRequired marker")

	r := NewActionRegistry()

	preAuthEndpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/health"},
		{"POST", "/api/v1/admin/bootstrap"},
		{"POST", "/api/v1/enroll/init"},
		{"POST", "/api/v1/enroll/dpu/init"},
		{"POST", "/api/v1/enroll/complete"},
	}

	for _, ep := range preAuthEndpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			action, err := r.Lookup(ep.method, ep.path)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if action != NoAuthRequired {
				t.Errorf("Expected NoAuthRequired for pre-auth endpoint, got %v", action)
			}
		})
	}

	t.Log("Verifying IsPreAuthEndpoint returns true for pre-auth endpoints")
	for _, ep := range preAuthEndpoints {
		if !r.IsPreAuthEndpoint(ep.method, ep.path) {
			t.Errorf("IsPreAuthEndpoint returned false for %s %s", ep.method, ep.path)
		}
	}
}

func TestActionRegistry_UnknownRoute_ReturnsError(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Unknown routes return error (fail-secure)")
	t.Log("SEC NOTE: This is critical - unknown routes MUST NOT pass silently")

	r := NewActionRegistry()

	unknownRoutes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/unknown"},
		{"POST", "/api/v1/nonexistent"},
		{"DELETE", "/api/v2/dpus"},           // Wrong version
		{"PUT", "/api/v1/dpus/dpu_xyz"},      // Wrong method
		{"GET", "/api/v1/dpus/a/b/c/d"},      // Too many segments
		{"POST", "/malicious/path"},          // Random path
		{"GET", ""},                          // Empty path
		{"GET", "/"},                         // Root path
		{"GET", "/api/v1/operators/me/evil"}, // Extra path segment
	}

	for _, ur := range unknownRoutes {
		t.Run(ur.method+" "+ur.path, func(t *testing.T) {
			action, err := r.Lookup(ur.method, ur.path)
			if err == nil {
				t.Errorf("Expected error for unknown route, got action %v", action)
			}
			if ErrorCode(err) != ErrCodeUnknownRoute {
				t.Errorf("Expected ErrCodeUnknownRoute, got %v", ErrorCode(err))
			}
			t.Logf("Correctly rejected unknown route with error: %v", err)
		})
	}
}

func TestActionRegistry_UnknownRoute_NotPreAuth(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Unknown routes do NOT return IsPreAuthEndpoint=true (fail-secure)")
	t.Log("SEC NOTE: Middleware ONLY bypasses auth for explicit NoAuthRequired marker")

	r := NewActionRegistry()

	// Unknown routes must NOT be treated as pre-auth
	if r.IsPreAuthEndpoint("GET", "/api/v1/unknown") {
		t.Error("SECURITY VIOLATION: Unknown route treated as pre-auth endpoint")
	}

	if r.IsPreAuthEndpoint("POST", "/evil/path") {
		t.Error("SECURITY VIOLATION: Malicious path treated as pre-auth endpoint")
	}

	t.Log("PASS: Unknown routes correctly require authentication")
}

func TestActionRegistry_ParameterizedPaths(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Parameterized paths match correctly")

	r := NewActionRegistry()

	// Various ID formats should match {id} parameter
	testIDs := []string{
		"dpu_xyz",
		"dpu_123",
		"abc",
		"a-b-c",
		"uuid-12345-67890",
	}

	for _, id := range testIDs {
		t.Run("GET /api/v1/dpus/"+id, func(t *testing.T) {
			action, err := r.Lookup("GET", "/api/v1/dpus/"+id)
			if err != nil {
				t.Fatalf("Lookup error for ID %q: %v", id, err)
			}
			if action != Action(ActionDPURead) {
				t.Errorf("got %v, want %v", action, ActionDPURead)
			}
		})
	}
}

func TestActionRegistry_AllRoutes(t *testing.T) {
	t.Parallel()
	t.Log("Testing: AllRoutes returns all registered routes")

	r := NewActionRegistry()
	routes := r.AllRoutes()

	t.Logf("Registry contains %d routes", len(routes))

	// Should have at least 25 routes per ADR-011
	if len(routes) < 25 {
		t.Errorf("Expected at least 25 routes, got %d", len(routes))
	}

	// Verify some expected routes are present
	expectedRoutes := []string{
		"GET /api/v1/operators/me",
		"POST /api/v1/dpus",
		"GET /health",
		"POST /api/v1/push",
	}

	for _, expected := range expectedRoutes {
		found := false
		for _, r := range routes {
			if r == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected route %q not found in registry", expected)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Pattern matching for parameterized routes")

	tests := []struct {
		pattern string
		path    string
		expect  bool
	}{
		// Exact matches
		{"/api/v1/dpus", "/api/v1/dpus", true},
		{"/health", "/health", true},

		// Parameter matches
		{"/api/v1/dpus/{id}", "/api/v1/dpus/dpu_xyz", true},
		{"/api/v1/dpus/{id}", "/api/v1/dpus/123", true},
		{"/api/v1/operators/{id}/roles/{tenant_id}", "/api/v1/operators/km_alice/roles/tnt_acme", true},

		// Non-matches
		{"/api/v1/dpus/{id}", "/api/v1/dpus", false},              // Missing param
		{"/api/v1/dpus/{id}", "/api/v1/dpus/a/b", false},          // Extra segment
		{"/api/v1/dpus", "/api/v1/dpus/extra", false},             // Extra segment
		{"/api/v1/dpus/{id}", "/api/v2/dpus/xyz", false},          // Wrong prefix
		{"/api/v1/dpus/{id}", "/api/v1/operators/xyz", false},     // Wrong path
		{"/api/v1/dpus/{id}", "/api/v1/dpus/", false},             // Empty param
		{"/api/v1/dpus/{id}/attestation", "/api/v1/dpus/x", false}, // Missing suffix
	}

	for _, tc := range tests {
		t.Run(tc.pattern+" vs "+tc.path, func(t *testing.T) {
			result := matchPattern(tc.pattern, tc.path)
			if result != tc.expect {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.pattern, tc.path, result, tc.expect)
			}
		})
	}
}

func TestActionRegistry_AllActionsHaveEndpoints(t *testing.T) {
	t.Parallel()
	t.Log("Testing: All Cedar actions are mapped to at least one endpoint")

	r := NewActionRegistry()
	routes := r.AllRoutes()

	// Build set of actions that have endpoints
	mappedActions := make(map[Action]bool)
	for key := range r.routes {
		action := r.routes[key]
		if action != NoAuthRequired {
			mappedActions[action] = true
		}
	}

	// Check each action has at least one endpoint
	allActions := AllActions()
	t.Logf("Checking %d actions have endpoints", len(allActions))

	for _, actionStr := range allActions {
		action := Action(actionStr)
		if !mappedActions[action] {
			t.Errorf("Action %q has no endpoint mapping", actionStr)
		}
	}

	t.Logf("Registry routes: %d, Mapped actions: %d", len(routes), len(mappedActions))
}
