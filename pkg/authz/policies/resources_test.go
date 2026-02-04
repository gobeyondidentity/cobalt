package policies

import (
	_ "embed"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

//go:embed resources.cedar
var resourcesPolicies []byte

// TestDPUSelfAccess validates DPU self-access policies.
func TestDPUSelfAccess(t *testing.T) {
	ps, err := cedar.NewPolicySetFromBytes("resources.cedar", resourcesPolicies)
	if err != nil {
		t.Fatalf("Failed to parse resources.cedar: %v", err)
	}

	t.Run("DPU can pull own credentials (DPU resource)", func(t *testing.T) {
		t.Log("Testing: DPU-001 can pull credentials for DPU-001")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:pull"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for DPU pulling own credentials")
		}
	})

	t.Run("DPU can pull own credentials (IssuedCredential resource)", func(t *testing.T) {
		t.Log("Testing: DPU-001 can pull IssuedCredential targeted at DPU-001")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:pull"),
			Resource:  cedar.NewEntityUID("Cobalt::IssuedCredential", "cred_001"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for DPU pulling IssuedCredential targeted at itself")
		}
	})

	t.Run("DPU can report own attestation", func(t *testing.T) {
		t.Log("Testing: DPU-001 can report attestation for DPU-001")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "dpu:report_attestation"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for DPU reporting own attestation")
		}
	})

	t.Run("DPU can read own config", func(t *testing.T) {
		t.Log("Testing: DPU-001 can read config for DPU-001")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "dpu:read_own_config"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for DPU reading own config")
		}
	})
}

// TestDPUCrossAccessDenied validates that DPUs cannot access other DPUs' resources.
func TestDPUCrossAccessDenied(t *testing.T) {
	ps, err := cedar.NewPolicySetFromBytes("resources.cedar", resourcesPolicies)
	if err != nil {
		t.Fatalf("Failed to parse resources.cedar: %v", err)
	}

	t.Run("DPU-001 cannot pull DPU-002 credentials", func(t *testing.T) {
		t.Log("Testing: DPU-001 CANNOT pull credentials for DPU-002")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:pull"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_002"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for DPU-001 pulling DPU-002 credentials")
		}
	})

	t.Run("DPU-001 cannot pull credential targeted at DPU-002", func(t *testing.T) {
		t.Log("Testing: DPU-001 CANNOT pull IssuedCredential targeted at DPU-002")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "credential:pull"),
			Resource:  cedar.NewEntityUID("Cobalt::IssuedCredential", "cred_002"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for DPU-001 pulling credential targeted at DPU-002")
		}
	})

	t.Run("DPU-001 cannot report DPU-002 attestation", func(t *testing.T) {
		t.Log("Testing: DPU-001 CANNOT report attestation for DPU-002")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "dpu:report_attestation"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_002"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for DPU-001 reporting DPU-002 attestation")
		}
	})

	t.Run("DPU-001 cannot read DPU-002 config", func(t *testing.T) {
		t.Log("Testing: DPU-001 CANNOT read config for DPU-002")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "dpu:read_own_config"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_002"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for DPU-001 reading DPU-002 config")
		}
	})
}

// TestDPUHostRegister validates host:register policies.
func TestDPUHostRegister(t *testing.T) {
	ps, err := cedar.NewPolicySetFromBytes("resources.cedar", resourcesPolicies)
	if err != nil {
		t.Fatalf("Failed to parse resources.cedar: %v", err)
	}

	t.Run("DPU can register own host", func(t *testing.T) {
		t.Log("Testing: DPU-001 can register host for DPU-001")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "host:register"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision != cedar.Allow {
			t.Error("Expected permit for DPU registering own host")
		}
	})

	t.Run("DPU cannot register host for another DPU", func(t *testing.T) {
		t.Log("Testing: DPU-001 CANNOT register host for DPU-002")

		entities := buildDPUTestEntities()
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Cobalt::DPU", "dpu_001"),
			Action:    cedar.NewEntityUID("Cobalt::Action", "host:register"),
			Resource:  cedar.NewEntityUID("Cobalt::DPU", "dpu_002"),
			Context:   cedar.NewRecord(cedar.RecordMap{}),
		}

		decision, diag := cedar.Authorize(ps, entities, req)
		t.Logf("Decision: %v, Reasons: %v", decision, diag.Reasons)

		if decision == cedar.Allow {
			t.Error("Expected deny for DPU-001 registering host for DPU-002")
		}
	})
}

// buildDPUTestEntities creates entity map for DPU self-access testing.
func buildDPUTestEntities() cedar.EntityMap {
	acmeTenant := cedar.NewEntityUID("Cobalt::Tenant", "tnt_acme")

	// DPUs in same tenant
	dpu001 := cedar.NewEntityUID("Cobalt::DPU", "dpu_001")
	dpu002 := cedar.NewEntityUID("Cobalt::DPU", "dpu_002")

	// Credentials targeted at specific DPUs
	cred001 := cedar.NewEntityUID("Cobalt::IssuedCredential", "cred_001")
	cred002 := cedar.NewEntityUID("Cobalt::IssuedCredential", "cred_002")

	return cedar.EntityMap{
		// Tenant
		acmeTenant: cedar.Entity{
			UID:        acmeTenant,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: cedar.NewRecord(cedar.RecordMap{"name": cedar.String("Acme Corp")}),
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
		dpu002: cedar.Entity{
			UID:     dpu002,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"tenant":             cedar.String("tnt_acme"),
				"attestation_status": cedar.String("verified"),
			}),
		},
		// Credentials
		cred001: cedar.Entity{
			UID:     cred001,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"tenant":     cedar.String("tnt_acme"),
				"target_dpu": dpu001, // Targeted at DPU-001
			}),
		},
		cred002: cedar.Entity{
			UID:     cred002,
			Parents: cedar.NewEntityUIDSet(acmeTenant),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"tenant":     cedar.String("tnt_acme"),
				"target_dpu": dpu002, // Targeted at DPU-002
			}),
		},
	}
}
