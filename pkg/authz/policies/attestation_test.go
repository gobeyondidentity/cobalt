package policies

import (
	_ "embed"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

//go:embed attestation.cedar
var attestationPolicies []byte

//go:embed roles.cedar
var rolesPoliciesForAttestation []byte

// TestAttestationGateCredentialPush tests attestation gate for credential:push.
func TestAttestationGateCredentialPush(t *testing.T) {
	// Load both attestation and roles policies (roles provides the permit)
	combined := append(rolesPoliciesForAttestation, attestationPolicies...)
	ps, err := cedar.NewPolicySetFromBytes("combined.cedar", combined)
	if err != nil {
		t.Fatalf("Failed to parse policies: %v", err)
	}

	t.Run("verified attestation permits operator", func(t *testing.T) {
		t.Log("Testing: verified attestation allows operator credential:push")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status":  cedar.String("verified"),
				"operator_authorized": cedar.Boolean(true),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for operator with verified attestation")
		}
	})

	t.Run("failed attestation blocks operator", func(t *testing.T) {
		t.Log("Testing: failed attestation blocks operator credential:push")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status":  cedar.String("failed"),
				"operator_authorized": cedar.Boolean(true),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for operator with failed attestation")
		}
	})

	t.Run("failed attestation blocks super:admin", func(t *testing.T) {
		t.Log("Testing: failed attestation blocks even super:admin (NO BYPASS)")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_super_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status": cedar.String("failed"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for super:admin with failed attestation (NO BYPASS)")
		}
	})

	t.Run("stale attestation blocks operator", func(t *testing.T) {
		t.Log("Testing: stale attestation blocks operator credential:push")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status":  cedar.String("stale"),
				"operator_authorized": cedar.Boolean(true),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for operator with stale attestation")
		}
	})

	t.Run("stale attestation blocks tenant:admin", func(t *testing.T) {
		t.Log("Testing: stale attestation blocks tenant:admin credential:push")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_tenant_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status": cedar.String("stale"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for tenant:admin with stale attestation")
		}
	})

	t.Run("stale attestation permits super:admin", func(t *testing.T) {
		t.Log("Testing: stale attestation allows super:admin (bypass available at app layer)")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_super_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status": cedar.String("stale"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for super:admin with stale attestation (bypass)")
		}
	})

	t.Run("unavailable attestation blocks operator", func(t *testing.T) {
		t.Log("Testing: unavailable attestation blocks operator credential:push")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_alice"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status":  cedar.String("unavailable"),
				"operator_authorized": cedar.Boolean(true),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for operator with unavailable attestation")
		}
	})

	t.Run("unavailable attestation permits super:admin", func(t *testing.T) {
		t.Log("Testing: unavailable attestation allows super:admin (bypass available)")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::Operator", "km_super_admin"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:push"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status": cedar.String("unavailable"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for super:admin with unavailable attestation (bypass)")
		}
	})
}

// TestAttestationGateCredentialPull tests attestation gate for DPU credential:pull.
func TestAttestationGateCredentialPull(t *testing.T) {
	// Load both attestation and resources policies
	combined := append(resourcesPolicies, attestationPolicies...)
	ps, err := cedar.NewPolicySetFromBytes("combined.cedar", combined)
	if err != nil {
		t.Fatalf("Failed to parse policies: %v", err)
	}

	t.Run("verified attestation permits DPU pull", func(t *testing.T) {
		t.Log("Testing: verified attestation allows DPU to pull own credentials")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:pull"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status": cedar.String("verified"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for DPU with verified attestation")
		}
	})

	t.Run("failed attestation blocks DPU pull", func(t *testing.T) {
		t.Log("Testing: failed attestation blocks DPU from pulling credentials")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:pull"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status": cedar.String("failed"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for DPU with failed attestation")
		}
	})

	t.Run("stale attestation blocks DPU pull", func(t *testing.T) {
		t.Log("Testing: stale attestation blocks DPU from pulling credentials")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:pull"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status": cedar.String("stale"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for DPU with stale attestation")
		}
	})

	t.Run("unavailable attestation blocks DPU pull", func(t *testing.T) {
		t.Log("Testing: unavailable attestation blocks DPU from pulling credentials")

		entities := buildAttestationTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:pull"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context: cedar.NewRecord(cedar.RecordMap{
				"attestation_status": cedar.String("unavailable"),
			}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for DPU with unavailable attestation")
		}
	})
}

// buildAttestationTestEntities creates entity map for attestation testing.
func buildAttestationTestEntities() cedar.EntityMap {
	acmeTenant := cedar.NewEntityUID("Cobalt::Tenant", "tnt_acme")

	// Operators with different roles
	operatorAlice := cedar.NewEntityUID("Cobalt::Operator", "km_alice")
	tenantAdmin := cedar.NewEntityUID("Cobalt::Operator", "km_tenant_admin")
	superAdmin := cedar.NewEntityUID("Cobalt::Operator", "km_super_admin")

	// DPU
	dpu001 := cedar.NewEntityUID("Cobalt::DPU", "dpu_001")

	return cedar.EntityMap{
		// Tenant
		acmeTenant: cedar.Entity{
			UID:        acmeTenant,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: cedar.NewRecord(cedar.RecordMap{"name": cedar.String("Acme Corp")}),
		},
		// Operators
		operatorAlice: cedar.Entity{
			UID:     operatorAlice,
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
		// DPU
		dpu001: cedar.Entity{
			UID:     dpu001,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"tenant":             cedar.String("tnt_acme"),
				"attestation_status": cedar.String("verified"),
			}),
		},
	}
}
