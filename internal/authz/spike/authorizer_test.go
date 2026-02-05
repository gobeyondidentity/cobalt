package spike

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestCedarGoIntegration(t *testing.T) {
	// Create logger that captures output
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Log("Creating authorizer with embedded Cedar policies")
	authz, err := NewAuthorizer(logger)
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	t.Logf("Loaded %d policies from policies.cedar", authz.PolicyCount())

	// =========================================================================
	// Acceptance Criteria Tests
	// =========================================================================

	t.Run("AC1: Operator pushes to verified DPU -> permit", func(t *testing.T) {
		t.Log("Testing: authorized operator pushing to DPU with verified attestation")

		req := AuthzRequest{
			PrincipalID:        "op_alice",
			PrincipalRole:      RoleOperator,
			Action:             "push_credential",
			ResourceID:         "dpu_prod_01",
			AttestationStatus:  AttestationVerified,
			OperatorAuthorized: true,
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if !decision.Allowed {
			t.Errorf("Expected permit for operator with verified attestation, got deny")
		}
	})

	t.Run("AC2: Operator pushes to failed DPU -> deny", func(t *testing.T) {
		t.Log("Testing: operator pushing to DPU with FAILED attestation (always blocked)")

		req := AuthzRequest{
			PrincipalID:        "op_alice",
			PrincipalRole:      RoleOperator,
			Action:             "push_credential",
			ResourceID:         "dpu_compromised",
			AttestationStatus:  AttestationFailed,
			OperatorAuthorized: true, // Even with authorization, failed attestation blocks
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if decision.Allowed {
			t.Errorf("Expected deny for failed attestation, got permit")
		}
	})

	t.Run("AC3: Super-admin bypasses stale attestation -> permit", func(t *testing.T) {
		t.Log("Testing: super-admin pushing to DPU with stale attestation (bypass allowed)")

		req := AuthzRequest{
			PrincipalID:        "adm_root",
			PrincipalRole:      RoleSuperAdmin,
			Action:             "push_credential",
			ResourceID:         "dpu_stale_01",
			AttestationStatus:  AttestationStale,
			OperatorAuthorized: false, // Super-admin doesn't need explicit authorization
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if !decision.Allowed {
			t.Errorf("Expected permit for super-admin with stale attestation, got deny")
		}
	})

	// =========================================================================
	// Additional Edge Cases
	// =========================================================================

	t.Run("Operator without authorization -> deny", func(t *testing.T) {
		t.Log("Testing: operator WITHOUT authorization for CA/device")

		req := AuthzRequest{
			PrincipalID:        "op_bob",
			PrincipalRole:      RoleOperator,
			Action:             "push_credential",
			ResourceID:         "dpu_restricted",
			AttestationStatus:  AttestationVerified,
			OperatorAuthorized: false, // No authorization for this CA/device combo
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if decision.Allowed {
			t.Errorf("Expected deny for operator without authorization, got permit")
		}
	})

	t.Run("Operator with stale attestation -> deny", func(t *testing.T) {
		t.Log("Testing: operator pushing to DPU with stale attestation")

		req := AuthzRequest{
			PrincipalID:        "op_charlie",
			PrincipalRole:      RoleOperator,
			Action:             "push_credential",
			ResourceID:         "dpu_stale_02",
			AttestationStatus:  AttestationStale,
			OperatorAuthorized: true,
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if decision.Allowed {
			t.Errorf("Expected deny for operator with stale attestation, got permit")
		}
	})

	t.Run("TenantAdmin with verified attestation -> permit", func(t *testing.T) {
		t.Log("Testing: tenant admin pushing to DPU with verified attestation")

		req := AuthzRequest{
			PrincipalID:        "ta_acme",
			PrincipalRole:      RoleTenantAdmin,
			Action:             "push_credential",
			ResourceID:         "dpu_tenant_01",
			AttestationStatus:  AttestationVerified,
			OperatorAuthorized: true,
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if !decision.Allowed {
			t.Errorf("Expected permit for tenant admin with verified attestation, got deny")
		}
	})

	t.Run("Super-admin blocked by failed attestation -> deny", func(t *testing.T) {
		t.Log("Testing: even super-admin cannot bypass FAILED attestation")

		req := AuthzRequest{
			PrincipalID:        "adm_root",
			PrincipalRole:      RoleSuperAdmin,
			Action:             "push_credential",
			ResourceID:         "dpu_pwned",
			AttestationStatus:  AttestationFailed,
			OperatorAuthorized: false,
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if decision.Allowed {
			t.Errorf("Expected deny for super-admin with failed attestation, got permit")
		}
	})

	t.Run("Operator with unavailable attestation -> deny", func(t *testing.T) {
		t.Log("Testing: operator pushing to DPU with unavailable attestation")

		req := AuthzRequest{
			PrincipalID:        "op_dave",
			PrincipalRole:      RoleOperator,
			Action:             "push_credential",
			ResourceID:         "dpu_new",
			AttestationStatus:  AttestationUnavailable,
			OperatorAuthorized: true,
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if decision.Allowed {
			t.Errorf("Expected deny for operator with unavailable attestation, got permit")
		}
	})

	t.Run("Super-admin bypasses unavailable attestation -> permit", func(t *testing.T) {
		t.Log("Testing: super-admin can bypass unavailable attestation")

		req := AuthzRequest{
			PrincipalID:        "adm_root",
			PrincipalRole:      RoleSuperAdmin,
			Action:             "push_credential",
			ResourceID:         "dpu_new",
			AttestationStatus:  AttestationUnavailable,
			OperatorAuthorized: false,
		}

		decision := authz.Authorize(req)
		t.Logf("Decision: allowed=%v, reasons=%v, duration=%v", decision.Allowed, decision.Reasons, decision.Duration)

		if !decision.Allowed {
			t.Errorf("Expected permit for super-admin with unavailable attestation, got deny")
		}
	})

	// Print captured log output for inspection
	t.Log("--- Authorization Decision Log ---")
	t.Log(buf.String())
}

func TestPolicyParsingErrors(t *testing.T) {
	t.Log("Testing policy parsing with invalid Cedar syntax")

	invalidPolicy := []byte(`
		// Invalid Cedar syntax
		permit(
			principal,
			action,
			resource
		) when {
			context.foo ==   // Missing right side of comparison
		};
	`)

	_, err := NewAuthorizerFromBytes(invalidPolicy, nil)
	if err == nil {
		t.Errorf("Expected error parsing invalid policy, got nil")
	}
	t.Logf("Got expected parse error: %v", err)
}

func BenchmarkAuthorize(b *testing.B) {
	authz, err := NewAuthorizer(nil)
	if err != nil {
		b.Fatalf("Failed to create authorizer: %v", err)
	}

	req := AuthzRequest{
		PrincipalID:        "op_bench",
		PrincipalRole:      RoleOperator,
		Action:             "push_credential",
		ResourceID:         "dpu_bench",
		AttestationStatus:  AttestationVerified,
		OperatorAuthorized: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		authz.Authorize(req)
	}
}
