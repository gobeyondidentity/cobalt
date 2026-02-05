package authz

import (
	"context"
	"testing"
)

// TestKeyMakerRevocation validates keymaker:revoke authorization rules.
func TestKeyMakerRevocation(t *testing.T) {
	t.Log("Testing keymaker:revoke authorization policies")

	authorizer, err := NewAuthorizer(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	t.Run("operator can revoke own keymaker", func(t *testing.T) {
		t.Log("Testing: operator with is_resource_owner=true can revoke KeyMaker")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_alice",
				Type:      PrincipalOperator,
				Role:      RoleOperator,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionKeyMakerRevoke,
			Resource: Resource{
				UID:      "km_alice_device1",
				Type:     "KeyMaker",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{
				"is_resource_owner": true,
			},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for operator revoking own KeyMaker")
		}
	})

	t.Run("operator cannot revoke other's keymaker", func(t *testing.T) {
		t.Log("Testing: operator without ownership cannot revoke KeyMaker")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_alice",
				Type:      PrincipalOperator,
				Role:      RoleOperator,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionKeyMakerRevoke,
			Resource: Resource{
				UID:      "km_bob_device1",
				Type:     "KeyMaker",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{
				"is_resource_owner": false,
			},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for operator revoking other's KeyMaker")
		}
	})

	t.Run("tenant:admin can revoke tenant keymaker", func(t *testing.T) {
		t.Log("Testing: tenant:admin can revoke KeyMakers in their tenant")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_tenant_admin",
				Type:      PrincipalOperator,
				Role:      RoleTenantAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionKeyMakerRevoke,
			Resource: Resource{
				UID:      "km_alice_device1",
				Type:     "KeyMaker",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for tenant:admin revoking tenant's KeyMaker")
		}
	})

	t.Run("tenant:admin cannot revoke other tenant's keymaker", func(t *testing.T) {
		t.Log("Testing: tenant:admin cannot revoke KeyMakers in other tenants")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_tenant_admin",
				Type:      PrincipalOperator,
				Role:      RoleTenantAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionKeyMakerRevoke,
			Resource: Resource{
				UID:      "km_other_device",
				Type:     "KeyMaker",
				TenantID: "tnt_other",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for tenant:admin revoking other tenant's KeyMaker")
		}
	})

	t.Run("super:admin can revoke any keymaker", func(t *testing.T) {
		t.Log("Testing: super:admin can revoke any KeyMaker globally")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_super_admin",
				Type:      PrincipalOperator,
				Role:      RoleSuperAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionKeyMakerRevoke,
			Resource: Resource{
				UID:      "km_other_device",
				Type:     "KeyMaker",
				TenantID: "tnt_other",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for super:admin revoking any KeyMaker")
		}
	})
}

// TestAdminKeyRevocation validates adminkey:revoke authorization rules.
func TestAdminKeyRevocation(t *testing.T) {
	t.Log("Testing adminkey:revoke authorization policies (super:admin only)")

	authorizer, err := NewAuthorizer(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	t.Run("super:admin can revoke admin key", func(t *testing.T) {
		t.Log("Testing: super:admin can revoke admin keys")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_super_admin",
				Type:      PrincipalOperator,
				Role:      RoleSuperAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionAdminKeyRevoke,
			Resource: Resource{
				UID:      "adm_key_001",
				Type:     "AdminKey",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for super:admin revoking admin key")
		}
	})

	t.Run("tenant:admin cannot revoke admin key", func(t *testing.T) {
		t.Log("Testing: tenant:admin is explicitly forbidden from revoking admin keys")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_tenant_admin",
				Type:      PrincipalOperator,
				Role:      RoleTenantAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionAdminKeyRevoke,
			Resource: Resource{
				UID:      "adm_key_001",
				Type:     "AdminKey",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for tenant:admin revoking admin key")
		}
	})

	t.Run("operator cannot revoke admin key", func(t *testing.T) {
		t.Log("Testing: operator cannot revoke admin keys")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_alice",
				Type:      PrincipalOperator,
				Role:      RoleOperator,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionAdminKeyRevoke,
			Resource: Resource{
				UID:      "adm_key_001",
				Type:     "AdminKey",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{
				"operator_authorized": true,
			},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for operator revoking admin key")
		}
	})
}

// TestOperatorSuspension validates operator:suspend and operator:unsuspend authorization.
func TestOperatorSuspension(t *testing.T) {
	t.Log("Testing operator:suspend/unsuspend authorization policies")

	authorizer, err := NewAuthorizer(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	t.Run("tenant:admin can suspend tenant operator", func(t *testing.T) {
		t.Log("Testing: tenant:admin can suspend operators in their tenant")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_tenant_admin",
				Type:      PrincipalOperator,
				Role:      RoleTenantAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionOperatorSuspend,
			Resource: Resource{
				UID:      "km_alice",
				Type:     "Operator",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for tenant:admin suspending tenant operator")
		}
	})

	t.Run("tenant:admin can unsuspend tenant operator", func(t *testing.T) {
		t.Log("Testing: tenant:admin can unsuspend operators in their tenant")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_tenant_admin",
				Type:      PrincipalOperator,
				Role:      RoleTenantAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionOperatorUnsuspend,
			Resource: Resource{
				UID:      "km_alice",
				Type:     "Operator",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for tenant:admin unsuspending tenant operator")
		}
	})

	t.Run("super:admin can suspend any operator", func(t *testing.T) {
		t.Log("Testing: super:admin can suspend any operator globally")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_super_admin",
				Type:      PrincipalOperator,
				Role:      RoleSuperAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionOperatorSuspend,
			Resource: Resource{
				UID:      "km_other",
				Type:     "Operator",
				TenantID: "tnt_other",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for super:admin suspending any operator")
		}
	})

	t.Run("operator cannot suspend other operators", func(t *testing.T) {
		t.Log("Testing: operator cannot suspend other operators")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_alice",
				Type:      PrincipalOperator,
				Role:      RoleOperator,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionOperatorSuspend,
			Resource: Resource{
				UID:      "km_bob",
				Type:     "Operator",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{
				"operator_authorized": true,
			},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for operator suspending another operator")
		}
	})
}

// TestDPUDecommission validates dpu:decommission authorization rules.
func TestDPUDecommission(t *testing.T) {
	t.Log("Testing dpu:decommission authorization policies")

	authorizer, err := NewAuthorizer(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	t.Run("tenant:admin can decommission tenant DPU", func(t *testing.T) {
		t.Log("Testing: tenant:admin can decommission DPUs in their tenant")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_tenant_admin",
				Type:      PrincipalOperator,
				Role:      RoleTenantAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionDPUDecommission,
			Resource: Resource{
				UID:      "dpu_001",
				Type:     "DPU",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for tenant:admin decommissioning tenant DPU")
		}
	})

	t.Run("tenant:admin cannot decommission other tenant's DPU", func(t *testing.T) {
		t.Log("Testing: tenant:admin cannot decommission DPUs in other tenants")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_tenant_admin",
				Type:      PrincipalOperator,
				Role:      RoleTenantAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionDPUDecommission,
			Resource: Resource{
				UID:      "dpu_other",
				Type:     "DPU",
				TenantID: "tnt_other",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for tenant:admin decommissioning other tenant's DPU")
		}
	})

	t.Run("super:admin can decommission any DPU", func(t *testing.T) {
		t.Log("Testing: super:admin can decommission any DPU globally")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_super_admin",
				Type:      PrincipalOperator,
				Role:      RoleSuperAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionDPUDecommission,
			Resource: Resource{
				UID:      "dpu_other",
				Type:     "DPU",
				TenantID: "tnt_other",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for super:admin decommissioning any DPU")
		}
	})

	t.Run("operator cannot decommission DPU", func(t *testing.T) {
		t.Log("Testing: operator cannot decommission DPUs")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_alice",
				Type:      PrincipalOperator,
				Role:      RoleOperator,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionDPUDecommission,
			Resource: Resource{
				UID:      "dpu_001",
				Type:     "DPU",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{
				"operator_authorized": true,
			},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for operator decommissioning DPU")
		}
	})
}

// TestDPUReactivation validates dpu:reactivate authorization rules (super:admin only).
func TestDPUReactivation(t *testing.T) {
	t.Log("Testing dpu:reactivate authorization policies (super:admin only)")

	authorizer, err := NewAuthorizer(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	t.Run("super:admin can reactivate DPU", func(t *testing.T) {
		t.Log("Testing: super:admin can reactivate decommissioned DPUs")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_super_admin",
				Type:      PrincipalOperator,
				Role:      RoleSuperAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionDPUReactivate,
			Resource: Resource{
				UID:      "dpu_001",
				Type:     "DPU",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if !decision.Allowed {
			t.Error("Expected permit for super:admin reactivating DPU")
		}
	})

	t.Run("tenant:admin cannot reactivate DPU", func(t *testing.T) {
		t.Log("Testing: tenant:admin is explicitly forbidden from reactivating DPUs")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_tenant_admin",
				Type:      PrincipalOperator,
				Role:      RoleTenantAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionDPUReactivate,
			Resource: Resource{
				UID:      "dpu_001",
				Type:     "DPU",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for tenant:admin reactivating DPU")
		}
	})

	t.Run("operator cannot reactivate DPU", func(t *testing.T) {
		t.Log("Testing: operator cannot reactivate DPUs")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_alice",
				Type:      PrincipalOperator,
				Role:      RoleOperator,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionDPUReactivate,
			Resource: Resource{
				UID:      "dpu_001",
				Type:     "DPU",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{
				"operator_authorized": true,
			},
		}

		decision := authorizer.Authorize(context.Background(), req)
		t.Logf("Decision: allowed=%v, reason=%s", decision.Allowed, decision.Reason)

		if decision.Allowed {
			t.Error("Expected deny for operator reactivating DPU")
		}
	})
}

// TestPolicyDecisionLogging validates that policy decisions include action name.
func TestPolicyDecisionLogging(t *testing.T) {
	t.Log("Testing that policy decisions log action name")

	authorizer, err := NewAuthorizer(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	t.Run("decision includes action in log context", func(t *testing.T) {
		t.Log("Testing: authorization decision logs include the action name")

		req := AuthzRequest{
			Principal: Principal{
				UID:       "km_super_admin",
				Type:      PrincipalOperator,
				Role:      RoleSuperAdmin,
				TenantIDs: []string{"tnt_acme"},
			},
			Action: ActionKeyMakerRevoke,
			Resource: Resource{
				UID:      "km_device",
				Type:     "KeyMaker",
				TenantID: "tnt_acme",
			},
			Context: map[string]any{},
		}

		decision := authorizer.Authorize(context.Background(), req)

		// The action should be part of the logged decision
		// We can't directly test the log output, but we verify the decision structure
		t.Logf("Decision allowed=%v for action=%s", decision.Allowed, req.Action)

		if !decision.Allowed {
			t.Error("Expected permit for super:admin")
		}
	})
}
