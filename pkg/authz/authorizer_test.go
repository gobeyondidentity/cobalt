package authz

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
)

func TestAuthorizer_OperatorWithAuthorization(t *testing.T) {
	t.Parallel()
	t.Log("Testing: authorized operator pushing credentials to verified DPU")

	authz := newTestAuthorizer(t)

	t.Log("Constructing request with operator role and verified attestation")
	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_alice",
			Type:      PrincipalOperator,
			Role:      RoleOperator,
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_xyz",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status":  "verified",
			"operator_authorized": true,
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q, policy=%s, duration=%v",
		decision.Allowed, decision.Reason, decision.PolicyID, decision.Duration)

	if !decision.Allowed {
		t.Errorf("Expected permit for authorized operator with verified attestation, got deny: %s", decision.Reason)
	}
	if decision.RequiresForceBypass {
		t.Error("Expected RequiresForceBypass=false for verified attestation")
	}
}

func TestAuthorizer_OperatorWithoutAuthorization(t *testing.T) {
	t.Parallel()
	t.Log("Testing: operator WITHOUT authorization for CA/device gets denied")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_bob",
			Type:      PrincipalOperator,
			Role:      RoleOperator,
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_restricted",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status":  "verified",
			"operator_authorized": false, // No authorization
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q", decision.Allowed, decision.Reason)

	if decision.Allowed {
		t.Error("Expected deny for operator without authorization")
	}
}

func TestAuthorizer_TenantAdminOwnTenant(t *testing.T) {
	t.Parallel()
	t.Log("Testing: tenant:admin accessing resource in their own tenant")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_admin_alice",
			Type:      PrincipalOperator,
			Role:      RoleTenantAdmin,
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionDPURead,
		Resource: Resource{
			UID:      "dpu_acme_01",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status": "verified",
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q", decision.Allowed, decision.Reason)

	if !decision.Allowed {
		t.Errorf("Expected permit for tenant:admin in own tenant, got deny: %s", decision.Reason)
	}
}

func TestAuthorizer_SuperAdminGlobalAccess(t *testing.T) {
	t.Parallel()
	t.Log("Testing: super:admin accessing any resource globally")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_root",
			Type:      PrincipalOperator,
			Role:      RoleSuperAdmin,
			TenantIDs: []string{"tnt_system"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_any",
			Type:     "DPU",
			TenantID: "tnt_other", // Different tenant
		},
		Context: map[string]any{
			"attestation_status": "verified",
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q", decision.Allowed, decision.Reason)

	if !decision.Allowed {
		t.Errorf("Expected permit for super:admin, got deny: %s", decision.Reason)
	}
}

func TestAuthorizer_AttestationFailed_HardBlock(t *testing.T) {
	t.Parallel()
	t.Log("Testing: failed attestation blocks ALL principals including super:admin")

	authz := newTestAuthorizer(t)

	// Even super:admin cannot bypass failed attestation
	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_root",
			Type:      PrincipalOperator,
			Role:      RoleSuperAdmin,
			TenantIDs: []string{"tnt_system"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_compromised",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status": "failed",
		},
	}

	t.Log("Evaluating authorization decision for super:admin with failed attestation")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q, bypass=%v", decision.Allowed, decision.Reason, decision.RequiresForceBypass)

	if decision.Allowed {
		t.Error("Expected deny for failed attestation (even for super:admin)")
	}
	if decision.RequiresForceBypass {
		t.Error("Expected RequiresForceBypass=false for failed attestation (cannot bypass)")
	}
}

func TestAuthorizer_AttestationStale_OperatorDenied(t *testing.T) {
	t.Parallel()
	t.Log("Testing: stale attestation denies operators")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_alice",
			Type:      PrincipalOperator,
			Role:      RoleOperator,
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_stale",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status":  "stale",
			"operator_authorized": true,
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q, bypass=%v", decision.Allowed, decision.Reason, decision.RequiresForceBypass)

	if decision.Allowed {
		t.Error("Expected deny for operator with stale attestation")
	}
	if decision.RequiresForceBypass {
		t.Error("Expected RequiresForceBypass=false for operator (only super:admin can bypass)")
	}
}

func TestAuthorizer_AttestationStale_SuperAdminBypass(t *testing.T) {
	t.Parallel()
	t.Log("Testing: stale attestation allows super:admin bypass")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_root",
			Type:      PrincipalOperator,
			Role:      RoleSuperAdmin,
			TenantIDs: []string{"tnt_system"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_stale",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status": "stale",
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q, bypass=%v", decision.Allowed, decision.Reason, decision.RequiresForceBypass)

	// Cedar denies, but we should signal that force bypass is available
	if decision.Allowed {
		// Policy allows super:admin with stale (they're not blocked by forbid)
		t.Log("Super:admin permitted with stale attestation (policy allows it)")
	} else {
		// If denied, RequiresForceBypass should be true for super:admin
		if !decision.RequiresForceBypass {
			t.Error("Expected RequiresForceBypass=true for super:admin with stale attestation")
		}
	}
}

func TestAuthorizer_AttestationUnavailable_SuperAdminBypass(t *testing.T) {
	t.Parallel()
	t.Log("Testing: unavailable attestation allows super:admin bypass")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_root",
			Type:      PrincipalOperator,
			Role:      RoleSuperAdmin,
			TenantIDs: []string{"tnt_system"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_new",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status": "unavailable",
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q, bypass=%v", decision.Allowed, decision.Reason, decision.RequiresForceBypass)

	// Cedar should permit super:admin (no forbid rule for them with unavailable)
	// But if policy did deny, RequiresForceBypass should be true
	if !decision.Allowed && !decision.RequiresForceBypass {
		t.Error("Expected RequiresForceBypass=true if super:admin denied with unavailable attestation")
	}
}

func TestAuthorizer_DPUSelfAccess_Pull(t *testing.T) {
	t.Parallel()
	t.Log("Testing: DPU can pull its own credentials")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "dpu_xyz",
			Type:      PrincipalDPU,
			Role:      "", // DPUs don't have roles
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionCredentialPull,
		Resource: Resource{
			UID:      "dpu_xyz", // Same as principal
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status": "verified",
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q", decision.Allowed, decision.Reason)

	if !decision.Allowed {
		t.Errorf("Expected permit for DPU pulling own credentials, got deny: %s", decision.Reason)
	}
}

func TestAuthorizer_DPUCrossAccess_Denied(t *testing.T) {
	t.Parallel()
	t.Log("Testing: DPU cannot pull another DPU's credentials")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "dpu_xyz",
			Type:      PrincipalDPU,
			Role:      "",
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionCredentialPull,
		Resource: Resource{
			UID:      "dpu_other", // Different DPU
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status": "verified",
		},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q", decision.Allowed, decision.Reason)

	if decision.Allowed {
		t.Error("Expected deny for DPU accessing another DPU's credentials")
	}
}

func TestAuthorizer_DPUReportOwnAttestation(t *testing.T) {
	t.Parallel()
	t.Log("Testing: DPU can report its own attestation status")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "dpu_xyz",
			Type:      PrincipalDPU,
			Role:      "",
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionDPUReportAttestation,
		Resource: Resource{
			UID:      "dpu_xyz", // Same as principal
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{},
	}

	t.Log("Evaluating authorization decision")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q", decision.Allowed, decision.Reason)

	if !decision.Allowed {
		t.Errorf("Expected permit for DPU reporting own attestation, got deny: %s", decision.Reason)
	}
}

func TestAuthorizer_PolicyCount(t *testing.T) {
	t.Parallel()
	t.Log("Testing: PolicyCount returns expected number of policies")

	authz := newTestAuthorizer(t)
	count := authz.PolicyCount()

	t.Logf("Policy count: %d", count)

	if count == 0 {
		t.Error("Expected at least 1 policy, got 0")
	}
	// We have ~15 policies in policies.cedar
	if count < 10 {
		t.Errorf("Expected at least 10 policies (sanity check), got %d", count)
	}
}

func TestAuthorizer_PolicyParseError(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Invalid policy syntax returns error")

	invalidPolicy := []byte(`
		// Invalid Cedar syntax
		permit(
			principal,
			action,
			resource
		) when {
			context.foo ==   // Missing right side
		};
	`)

	cfg := DefaultConfig()
	cfg.PolicyBytes = invalidPolicy

	_, err := NewAuthorizer(cfg)

	if err == nil {
		t.Error("Expected error for invalid policy syntax, got nil")
	}
	t.Logf("Got expected error: %v", err)
}

func TestAuthorizer_DecisionLogging(t *testing.T) {
	t.Parallel()
	t.Log("Testing: Authorization decisions are logged with structured fields")

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := DefaultConfig()
	cfg.Logger = logger
	authz, err := NewAuthorizer(cfg)
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_alice",
			Type:      PrincipalOperator,
			Role:      RoleOperator,
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_xyz",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status":  "verified",
			"operator_authorized": true,
		},
	}

	_ = authz.Authorize(context.Background(), req)

	logOutput := logBuf.String()
	t.Log("Log output:", logOutput)

	// Verify key fields are present in log
	expectedFields := []string{"principal", "action", "resource", "decision", "duration_us"}
	for _, field := range expectedFields {
		if !bytes.Contains(logBuf.Bytes(), []byte(field)) {
			t.Errorf("Expected log to contain field %q", field)
		}
	}
}

func TestActions_ValidateAction(t *testing.T) {
	t.Parallel()
	t.Log("Testing: ValidateAction correctly identifies valid and invalid actions")

	tests := []struct {
		action string
		valid  bool
	}{
		{ActionCredentialPush, true},
		{ActionDPURead, true},
		{ActionOperatorInvite, true},
		{"unknown:action", false},
		{"", false},
		{"credential:pushx", false},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			result := ValidateAction(tc.action)
			if result != tc.valid {
				t.Errorf("ValidateAction(%q) = %v, want %v", tc.action, result, tc.valid)
			}
		})
	}
}

func TestActions_RequiresAttestationGate(t *testing.T) {
	t.Parallel()
	t.Log("Testing: RequiresAttestationGate identifies attestation-gated actions")

	tests := []struct {
		action string
		gated  bool
	}{
		{ActionCredentialPush, true},
		{ActionCredentialPull, true},
		{ActionDPURead, false},
		{ActionOperatorList, false},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			result := RequiresAttestationGate(tc.action)
			if result != tc.gated {
				t.Errorf("RequiresAttestationGate(%q) = %v, want %v", tc.action, result, tc.gated)
			}
		})
	}
}

func TestErrors_ErrorCode(t *testing.T) {
	t.Parallel()
	t.Log("Testing: ErrorCode extracts code from AuthzError")

	err := ErrForbidden("access denied")
	code := ErrorCode(err)

	if code != ErrCodeForbidden {
		t.Errorf("ErrorCode returned %q, want %q", code, ErrCodeForbidden)
	}

	// Test with nil
	if ErrorCode(nil) != "" {
		t.Error("ErrorCode(nil) should return empty string")
	}
}

func TestErrors_HTTPStatus(t *testing.T) {
	t.Parallel()
	t.Log("Testing: AuthzError HTTPStatus returns correct status codes")

	tests := []struct {
		err    *AuthzError
		status int
	}{
		{ErrForbidden("denied"), 403},
		{ErrAttestationStale("dpu_xyz"), 412},
		{ErrAttestationFailed("dpu_xyz"), 412},
		{ErrUnknownAction("bad:action"), 400},
		{ErrPolicyError("parse failed"), 500},
	}

	for _, tc := range tests {
		t.Run(tc.err.Code, func(t *testing.T) {
			if tc.err.HTTPStatus() != tc.status {
				t.Errorf("%s HTTPStatus = %d, want %d", tc.err.Code, tc.err.HTTPStatus(), tc.status)
			}
		})
	}
}

// BenchmarkAuthorize measures authorization decision latency.
func BenchmarkAuthorize(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)) // Discard logs
	authz, err := NewAuthorizer(cfg)
	if err != nil {
		b.Fatalf("Failed to create authorizer: %v", err)
	}

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_alice",
			Type:      PrincipalOperator,
			Role:      RoleOperator,
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionCredentialPush,
		Resource: Resource{
			UID:      "dpu_xyz",
			Type:     "DPU",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{
			"attestation_status":  "verified",
			"operator_authorized": true,
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		authz.Authorize(ctx, req)
	}
}

func TestAuthorizer_OperatorAuthorizationList(t *testing.T) {
	t.Parallel()
	t.Log("Testing: plain operator can list their own authorizations (km whoami)")

	authz := newTestAuthorizer(t)

	req := AuthzRequest{
		Principal: Principal{
			UID:       "km_bob",
			Type:      PrincipalOperator,
			Role:      RoleOperator,
			TenantIDs: []string{"tnt_acme"},
		},
		Action: ActionAuthorizationList,
		Resource: Resource{
			UID:      "",
			Type:     "Authorization",
			TenantID: "tnt_acme",
		},
		Context: map[string]any{},
	}

	t.Log("Evaluating authorization decision for authorization:list without operator_authorized")
	decision := authz.Authorize(context.Background(), req)

	t.Logf("Decision: allowed=%v, reason=%q", decision.Allowed, decision.Reason)

	if !decision.Allowed {
		t.Errorf("Expected permit for operator listing own authorizations, got deny: %s", decision.Reason)
	}
}

// newTestAuthorizer creates an authorizer with a discarding logger for tests.
func newTestAuthorizer(t *testing.T) *Authorizer {
	t.Helper()

	cfg := DefaultConfig()
	cfg.Logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	authz, err := NewAuthorizer(cfg)
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	return authz
}
