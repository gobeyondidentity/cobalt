package spike

import (
	"testing"

	"github.com/cedar-policy/cedar-go"
)

// TestEntityRelationships validates cedar-go support for entity hierarchies,
// attribute access, membership tests, and equality checks.
//
// This is a mini-spike to determine if we can use Cedar's entity model
// or if we need to flatten everything into context attributes.
func TestEntityRelationships(t *testing.T) {
	// =========================================================================
	// Test 1: Entity Hierarchy (principal in parent)
	// Cedar supports "principal in Resource" to check if principal is a member
	// of (or equal to) the resource via the Parents relationship.
	// =========================================================================
	t.Run("Entity hierarchy with 'in' operator", func(t *testing.T) {
		t.Log("Testing: Can an Operator be 'in' a Tenant via Parents?")

		// Policy: permit if principal is in the tenant
		policy := []byte(`
			permit(
				principal is Operator,
				action == Action::"push_credential",
				resource is DPU
			) when {
				principal in Tenant::"acme"
			};
		`)

		ps, err := cedar.NewPolicySetFromBytes("test.cedar", policy)
		if err != nil {
			t.Fatalf("Failed to parse policy: %v", err)
		}

		// Create entities with hierarchy: Operator -> Tenant
		acmeTenant := cedar.NewEntityUID("Tenant", "acme")
		aliceOperator := cedar.NewEntityUID("Operator", "alice")
		bobOperator := cedar.NewEntityUID("Operator", "bob")
		dpuResource := cedar.NewEntityUID("DPU", "dpu-001")

		entities := cedar.EntityMap{
			acmeTenant: cedar.Entity{
				UID:        acmeTenant,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			aliceOperator: cedar.Entity{
				UID:        aliceOperator,
				Parents:    cedar.NewEntityUIDSet(acmeTenant), // Alice belongs to Acme
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			bobOperator: cedar.Entity{
				UID:        bobOperator,
				Parents:    cedar.NewEntityUIDSet(), // Bob has no tenant
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			dpuResource: cedar.Entity{
				UID:        dpuResource,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
		}

		// Alice (in Acme tenant) should be permitted
		reqAlice := cedar.Request{
			Principal: aliceOperator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  dpuResource,
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, reqAlice)
		t.Logf("Alice decision: %v, reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Errorf("Expected Alice (in Acme) to be permitted, got deny")
		}

		// Bob (not in any tenant) should be denied
		reqBob := cedar.Request{
			Principal: bobOperator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  dpuResource,
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag = cedar.Authorize(ps, entities, reqBob)
		t.Logf("Bob decision: %v, reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Errorf("Expected Bob (no tenant) to be denied, got permit")
		}

		t.Log("RESULT: Entity hierarchy with 'in' operator WORKS")
	})

	// =========================================================================
	// Test 2: Attribute Access (principal.attr, resource.attr)
	// Cedar allows accessing entity attributes in policy conditions.
	// =========================================================================
	t.Run("Attribute access on entities", func(t *testing.T) {
		t.Log("Testing: Can policy access principal.role or resource.tenant?")

		// Policy: permit if principal has role "admin"
		policy := []byte(`
			permit(
				principal is Operator,
				action == Action::"push_credential",
				resource is DPU
			) when {
				principal.role == "admin"
			};
		`)

		ps, err := cedar.NewPolicySetFromBytes("test.cedar", policy)
		if err != nil {
			t.Fatalf("Failed to parse policy: %v", err)
		}

		adminOperator := cedar.NewEntityUID("Operator", "admin-alice")
		regularOperator := cedar.NewEntityUID("Operator", "regular-bob")
		dpuResource := cedar.NewEntityUID("DPU", "dpu-001")

		entities := cedar.EntityMap{
			adminOperator: cedar.Entity{
				UID:     adminOperator,
				Parents: cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{
					"role": cedar.String("admin"),
				}),
			},
			regularOperator: cedar.Entity{
				UID:     regularOperator,
				Parents: cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{
					"role": cedar.String("operator"),
				}),
			},
			dpuResource: cedar.Entity{
				UID:        dpuResource,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
		}

		// Admin should be permitted
		reqAdmin := cedar.Request{
			Principal: adminOperator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  dpuResource,
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, reqAdmin)
		t.Logf("Admin decision: %v, reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Errorf("Expected admin to be permitted, got deny")
		}

		// Regular operator should be denied
		reqRegular := cedar.Request{
			Principal: regularOperator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  dpuResource,
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag = cedar.Authorize(ps, entities, reqRegular)
		t.Logf("Regular decision: %v, reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Errorf("Expected regular operator to be denied, got permit")
		}

		t.Log("RESULT: Attribute access on entities WORKS")
	})

	// =========================================================================
	// Test 3: Resource attribute matching principal's tenant
	// Check if resource.tenant == principal's tenant (via attribute or context)
	// =========================================================================
	t.Run("Resource tenant matches principal tenant", func(t *testing.T) {
		t.Log("Testing: Can policy check resource.tenant == context.caller_tenant?")

		// Policy: permit if resource belongs to caller's tenant
		policy := []byte(`
			permit(
				principal is Operator,
				action == Action::"push_credential",
				resource is DPU
			) when {
				resource.tenant == context.caller_tenant
			};
		`)

		ps, err := cedar.NewPolicySetFromBytes("test.cedar", policy)
		if err != nil {
			t.Fatalf("Failed to parse policy: %v", err)
		}

		operator := cedar.NewEntityUID("Operator", "alice")
		acmeDPU := cedar.NewEntityUID("DPU", "dpu-acme-001")
		otherDPU := cedar.NewEntityUID("DPU", "dpu-other-001")

		entities := cedar.EntityMap{
			operator: cedar.Entity{
				UID:        operator,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			acmeDPU: cedar.Entity{
				UID:     acmeDPU,
				Parents: cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{
					"tenant": cedar.String("acme"),
				}),
			},
			otherDPU: cedar.Entity{
				UID:     otherDPU,
				Parents: cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{
					"tenant": cedar.String("other-corp"),
				}),
			},
		}

		// Same tenant should be permitted
		reqSameTenant := cedar.Request{
			Principal: operator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  acmeDPU,
			Context: cedar.NewRecord(cedar.RecordMap{
				"caller_tenant": cedar.String("acme"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, reqSameTenant)
		t.Logf("Same tenant decision: %v, reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Errorf("Expected same tenant to be permitted, got deny")
		}

		// Different tenant should be denied
		reqDiffTenant := cedar.Request{
			Principal: operator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  otherDPU,
			Context: cedar.NewRecord(cedar.RecordMap{
				"caller_tenant": cedar.String("acme"),
			}),
		}

		decision, diag = cedar.Authorize(ps, entities, reqDiffTenant)
		t.Logf("Different tenant decision: %v, reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Errorf("Expected different tenant to be denied, got permit")
		}

		t.Log("RESULT: Resource attribute matching context WORKS")
	})

	// =========================================================================
	// Test 4: EntityUID comparison (resource.tenant_ref == Tenant::"acme")
	// Check if we can store EntityUID as attribute and compare
	// =========================================================================
	t.Run("EntityUID attribute comparison", func(t *testing.T) {
		t.Log("Testing: Can policy compare resource.tenant_ref to an EntityUID?")

		// Policy: permit if resource's tenant_ref matches a specific tenant
		policy := []byte(`
			permit(
				principal is Operator,
				action == Action::"push_credential",
				resource is DPU
			) when {
				resource.tenant_ref == Tenant::"acme"
			};
		`)

		ps, err := cedar.NewPolicySetFromBytes("test.cedar", policy)
		if err != nil {
			t.Fatalf("Failed to parse policy: %v", err)
		}

		acmeTenant := cedar.NewEntityUID("Tenant", "acme")
		otherTenant := cedar.NewEntityUID("Tenant", "other")
		operator := cedar.NewEntityUID("Operator", "alice")
		acmeDPU := cedar.NewEntityUID("DPU", "dpu-acme")
		otherDPU := cedar.NewEntityUID("DPU", "dpu-other")

		entities := cedar.EntityMap{
			acmeTenant: cedar.Entity{
				UID:        acmeTenant,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			otherTenant: cedar.Entity{
				UID:        otherTenant,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			operator: cedar.Entity{
				UID:        operator,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			acmeDPU: cedar.Entity{
				UID:     acmeDPU,
				Parents: cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{
					"tenant_ref": acmeTenant, // EntityUID as attribute
				}),
			},
			otherDPU: cedar.Entity{
				UID:     otherDPU,
				Parents: cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{
					"tenant_ref": otherTenant,
				}),
			},
		}

		// Acme DPU should be permitted
		reqAcme := cedar.Request{
			Principal: operator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  acmeDPU,
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, reqAcme)
		t.Logf("Acme DPU decision: %v, reasons: %v, errors: %v", decision, diag.Reasons, diag.Errors)

		if decision != cedar.Allow {
			t.Errorf("Expected Acme DPU to be permitted, got deny")
		}

		// Other DPU should be denied
		reqOther := cedar.Request{
			Principal: operator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  otherDPU,
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag = cedar.Authorize(ps, entities, reqOther)
		t.Logf("Other DPU decision: %v, reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Errorf("Expected Other DPU to be denied, got permit")
		}

		t.Log("RESULT: EntityUID attribute comparison WORKS")
	})

	// =========================================================================
	// Test 5: Transitive hierarchy (Operator in Tenant, DPU in Tenant)
	// Check if we can use 'in' for both principal and resource membership
	// =========================================================================
	t.Run("Transitive hierarchy check", func(t *testing.T) {
		t.Log("Testing: Can policy check if principal and resource share a tenant via 'in'?")

		// Policy: permit if principal is in resource's parent tenant
		policy := []byte(`
			permit(
				principal is Operator,
				action == Action::"push_credential",
				resource is DPU
			) when {
				resource in principal.tenant_ref
			};
		`)

		ps, err := cedar.NewPolicySetFromBytes("test.cedar", policy)
		if err != nil {
			t.Fatalf("Failed to parse policy: %v", err)
		}

		acmeTenant := cedar.NewEntityUID("Tenant", "acme")
		otherTenant := cedar.NewEntityUID("Tenant", "other")
		aliceOperator := cedar.NewEntityUID("Operator", "alice")
		acmeDPU := cedar.NewEntityUID("DPU", "dpu-acme")
		otherDPU := cedar.NewEntityUID("DPU", "dpu-other")

		entities := cedar.EntityMap{
			acmeTenant: cedar.Entity{
				UID:        acmeTenant,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			otherTenant: cedar.Entity{
				UID:        otherTenant,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			aliceOperator: cedar.Entity{
				UID:     aliceOperator,
				Parents: cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{
					"tenant_ref": acmeTenant, // Alice's tenant
				}),
			},
			acmeDPU: cedar.Entity{
				UID:        acmeDPU,
				Parents:    cedar.NewEntityUIDSet(acmeTenant), // DPU belongs to Acme
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
			otherDPU: cedar.Entity{
				UID:        otherDPU,
				Parents:    cedar.NewEntityUIDSet(otherTenant), // DPU belongs to Other
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			},
		}

		// Alice accessing Acme DPU (same tenant) should be permitted
		reqSame := cedar.Request{
			Principal: aliceOperator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  acmeDPU,
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, reqSame)
		t.Logf("Same tenant (via hierarchy) decision: %v, reasons: %v, errors: %v", decision, diag.Reasons, diag.Errors)

		if decision != cedar.Allow {
			t.Errorf("Expected same tenant (via hierarchy) to be permitted, got deny")
		}

		// Alice accessing Other DPU (different tenant) should be denied
		reqDiff := cedar.Request{
			Principal: aliceOperator,
			Action:    cedar.NewEntityUID("Action", "push_credential"),
			Resource:  otherDPU,
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag = cedar.Authorize(ps, entities, reqDiff)
		t.Logf("Different tenant (via hierarchy) decision: %v, reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Errorf("Expected different tenant (via hierarchy) to be denied, got permit")
		}

		t.Log("RESULT: Transitive hierarchy check WORKS")
	})
}
