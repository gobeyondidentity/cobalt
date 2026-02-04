package policies

import (
	"context"
	_ "embed"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

//go:embed roles.cedar
var rolesPolicies []byte

// TestRoleBasedAccess validates the three-tier role model.
func TestRoleBasedAccess(t *testing.T) {
	ps, err := cedar.NewPolicySetFromBytes("roles.cedar", rolesPolicies)
	if err != nil {
		t.Fatalf("Failed to parse roles.cedar: %v", err)
	}

	t.Run("operator with authorization permits", func(t *testing.T) {
		t.Log("Testing: operator with explicit authorization can access resource")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"operator_authorized": cedar.Boolean(true),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v, Errors: %v", decision, diag.Reasons, diag.Errors)

		if decision != cedar.Allow {
			t.Error("Expected permit for operator with authorization")
		}
	})

	t.Run("operator without authorization denies", func(t *testing.T) {
		t.Log("Testing: operator without authorization is denied")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"operator_authorized": cedar.Boolean(false),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for operator without authorization")
		}
	})

	t.Run("tenant:admin own tenant permits", func(t *testing.T) {
		t.Log("Testing: tenant:admin can access resources in their tenant")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_tenant_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "dpu:read"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for tenant:admin in own tenant")
		}
	})

	t.Run("tenant:admin other tenant denies", func(t *testing.T) {
		t.Log("Testing: tenant:admin cannot access resources in other tenants")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_tenant_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "dpu:read"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_other"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for tenant:admin accessing other tenant")
		}
	})

	t.Run("super:admin global access permits", func(t *testing.T) {
		t.Log("Testing: super:admin can access any resource globally")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_super_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "dpu:read"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_other"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for super:admin (global access)")
		}
	})

	t.Run("operator self read permits", func(t *testing.T) {
		t.Log("Testing: operator can read their own profile")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "operator:read_self"),
			Resource:  cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for operator reading own profile")
		}
	})
}

// TestRoleAssignmentConstraints validates role escalation prevention.
func TestRoleAssignmentConstraints(t *testing.T) {
	ps, err := cedar.NewPolicySetFromBytes("roles.cedar", rolesPolicies)
	if err != nil {
		t.Fatalf("Failed to parse roles.cedar: %v", err)
	}

	t.Run("tenant:admin cannot grant super:admin", func(t *testing.T) {
		t.Log("Testing: tenant:admin cannot assign super:admin role")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_tenant_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "role:assign"),
			Resource:  cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"target_role":   cedar.String("super:admin"),
				"target_tenant": cedar.String("tnt_acme"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny: tenant:admin should not grant super:admin")
		}
	})

	t.Run("tenant:admin can grant tenant:admin", func(t *testing.T) {
		t.Log("Testing: tenant:admin can assign tenant:admin role")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_tenant_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "role:assign"),
			Resource:  cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"target_role":   cedar.String("tenant:admin"),
				"target_tenant": cedar.String("tnt_acme"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit: tenant:admin should grant tenant:admin")
		}
	})

	t.Run("tenant:admin can grant operator", func(t *testing.T) {
		t.Log("Testing: tenant:admin can assign operator role")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_tenant_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "role:assign"),
			Resource:  cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"target_role":   cedar.String("operator"),
				"target_tenant": cedar.String("tnt_acme"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit: tenant:admin should grant operator role")
		}
	})

	t.Run("operator cannot assign any role", func(t *testing.T) {
		t.Log("Testing: operator cannot assign any roles")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "role:assign"),
			Resource:  cedar.NewEntityUID("Cobalt::Operator", "km_bob"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"target_role":       cedar.String("operator"),
				"target_tenant":     cedar.String("tnt_acme"),
				"operator_authorized": cedar.Boolean(true), // Even with auth
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny: operator should not assign roles")
		}
	})

	t.Run("super:admin can grant super:admin", func(t *testing.T) {
		t.Log("Testing: super:admin can assign super:admin role")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_super_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "role:assign"),
			Resource:  cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"target_role":   cedar.String("super:admin"),
				"target_tenant": cedar.String("tnt_acme"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit: super:admin should grant super:admin")
		}
	})
}

// TestNoImplicitPermits validates deny-by-default behavior.
func TestNoImplicitPermits(t *testing.T) {
	ps, err := cedar.NewPolicySetFromBytes("roles.cedar", rolesPolicies)
	if err != nil {
		t.Fatalf("Failed to parse roles.cedar: %v", err)
	}

	t.Run("unknown principal denies", func(t *testing.T) {
		t.Log("Testing: unknown/unauthenticated principal is denied")

		// Empty entity map - principal doesn't exist
		entities := cedar.EntityMap{}
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_unknown"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "dpu:read"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for unknown principal (no implicit permits)")
		}
	})

	t.Run("missing context denies operator", func(t *testing.T) {
		t.Log("Testing: operator without operator_authorized context is denied")

		entities := buildTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context:   cedar.NewRecord(cedar.RecordMap{}), // No operator_authorized
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for operator without authorization context")
		}
	})
}

// buildTestEntities creates entity map for role-based policy testing.
func buildTestEntities() cedar.EntityMap {
	acmeTenant := cedar.NewEntityUID("Cobalt::Tenant", "tnt_acme")
	otherTenant := cedar.NewEntityUID("Cobalt::Tenant", "tnt_other")

	// Operator role (needs explicit authorization)
	operatorAlice := cedar.NewEntityUID("Cobalt::Operator", "km_alice")
	operatorBob := cedar.NewEntityUID("Cobalt::Operator", "km_bob")

	// Tenant admin (full access to tnt_acme)
	tenantAdmin := cedar.NewEntityUID("Cobalt::Operator", "km_tenant_admin")

	// Super admin (global access)
	superAdmin := cedar.NewEntityUID("Cobalt::Operator", "km_super_admin")

	// DPUs in different tenants
	dpu001 := cedar.NewEntityUID("Cobalt::DPU", "dpu_001")
	dpuOther := cedar.NewEntityUID("Cobalt::DPU", "dpu_other")

	return cedar.EntityMap{
		// Tenants
		acmeTenant: cedar.Entity{
			UID:        acmeTenant,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: cedar.NewRecord(cedar.RecordMap{"name": cedar.String("Acme Corp")}),
		},
		otherTenant: cedar.Entity{
			UID:        otherTenant,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: cedar.NewRecord(cedar.RecordMap{"name": cedar.String("Other Corp")}),
		},
		// Operators
		operatorAlice: cedar.Entity{
			UID:     operatorAlice,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"role":       cedar.String("operator"),
				"tenant_ids": cedar.NewSet(cedar.String("tnt_acme")),
				"tenant":     cedar.String("tnt_acme"), // Primary tenant for resource checks
			}),
		},
		operatorBob: cedar.Entity{
			UID:     operatorBob,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"role":       cedar.String("operator"),
				"tenant_ids": cedar.NewSet(cedar.String("tnt_acme")),
				"tenant":     cedar.String("tnt_acme"),
			}),
		},
		tenantAdmin: cedar.Entity{
			UID:     tenantAdmin,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"role":       cedar.String("tenant:admin"),
				"tenant_ids": cedar.NewSet(cedar.String("tnt_acme")),
				"tenant":     cedar.String("tnt_acme"),
			}),
		},
		superAdmin: cedar.Entity{
			UID:     superAdmin,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"role":       cedar.String("super:admin"),
				"tenant_ids": cedar.NewSet(cedar.String("tnt_acme")),
				"tenant":     cedar.String("tnt_acme"),
			}),
		},
		// DPUs
		dpu001: cedar.Entity{
			UID:     dpu001,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"tenant":             cedar.String("tnt_acme"),
				"attestation_status": cedar.String("verified"),
			}),
		},
		dpuOther: cedar.Entity{
			UID:     dpuOther,
			Parents: cedar.NewEntityUIDSet(otherTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"tenant":             cedar.String("tnt_other"),
				"attestation_status": cedar.String("verified"),
			}),
		},
	}
}

// Ensure test context is passed through
var _ context.Context = context.Background()
