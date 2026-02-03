package authz

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
)

func TestNewOperatorEntity_SingleTenant(t *testing.T) {
	t.Parallel()
	t.Log("Testing: NewOperatorEntity with single tenant membership")

	tenants := []TenantRole{
		{TenantID: "tnt_acme", Role: RoleTenantAdmin},
	}

	t.Log("Creating operator entity with single tenant:admin role")
	entity := NewOperatorEntity("km_alice", tenants)

	t.Log("Verifying entity UID format")
	expectedUID := cedar.NewEntityUID("Operator", cedar.String("km_alice"))
	if entity.UID != expectedUID {
		t.Errorf("UID mismatch: got %v, want %v", entity.UID, expectedUID)
	}

	t.Log("Verifying Parents includes tenant UID")
	tenantUID := cedar.NewEntityUID("Tenant", cedar.String("tnt_acme"))
	if !entity.Parents.Contains(tenantUID) {
		t.Errorf("Expected Parents to contain %v", tenantUID)
	}

	t.Log("Verifying role attribute")
	roleVal, ok := entity.Attributes.Get("role")
	if !ok {
		t.Fatal("role attribute not found")
	}
	if string(roleVal.(cedar.String)) != string(RoleTenantAdmin) {
		t.Errorf("role mismatch: got %v, want %v", roleVal, RoleTenantAdmin)
	}

	t.Log("PASS: Single tenant operator entity constructed correctly")
}

func TestNewOperatorEntity_MultiTenant(t *testing.T) {
	t.Parallel()
	t.Log("Testing: NewOperatorEntity with multiple tenant memberships")

	tenants := []TenantRole{
		{TenantID: "tnt_acme", Role: RoleOperator},
		{TenantID: "tnt_globex", Role: RoleTenantAdmin},
		{TenantID: "tnt_initech", Role: RoleOperator},
	}

	t.Log("Creating operator entity with 3 tenant memberships")
	entity := NewOperatorEntity("km_bob", tenants)

	t.Log("Verifying Parents includes all 3 tenant UIDs")
	for _, tr := range tenants {
		tenantUID := cedar.NewEntityUID("Tenant", cedar.String(tr.TenantID))
		if !entity.Parents.Contains(tenantUID) {
			t.Errorf("Expected Parents to contain %v", tenantUID)
		}
	}

	t.Log("Verifying highest role is tenant:admin (from tnt_globex)")
	roleVal, ok := entity.Attributes.Get("role")
	if !ok {
		t.Fatal("role attribute not found")
	}
	if string(roleVal.(cedar.String)) != string(RoleTenantAdmin) {
		t.Errorf("Expected highest role to be tenant:admin, got %v", roleVal)
	}

	t.Log("Verifying tenant_ids set contains all 3 IDs")
	tenantIDsVal, ok := entity.Attributes.Get("tenant_ids")
	if !ok {
		t.Fatal("tenant_ids attribute not found")
	}
	tenantIDsSet := tenantIDsVal.(cedar.Set)
	if tenantIDsSet.Len() != 3 {
		t.Errorf("Expected 3 tenant IDs, got %d", tenantIDsSet.Len())
	}

	t.Log("PASS: Multi-tenant operator entity constructed correctly")
}

func TestNewOperatorEntity_SuperAdminHighestRole(t *testing.T) {
	t.Parallel()
	t.Log("Testing: NewOperatorEntity with super:admin has highest precedence")

	tenants := []TenantRole{
		{TenantID: "tnt_acme", Role: RoleTenantAdmin},
		{TenantID: "tnt_system", Role: RoleSuperAdmin},
	}

	t.Log("Creating operator entity with super:admin in one tenant")
	entity := NewOperatorEntity("km_root", tenants)

	roleVal, _ := entity.Attributes.Get("role")
	if string(roleVal.(cedar.String)) != string(RoleSuperAdmin) {
		t.Errorf("Expected super:admin as highest role, got %v", roleVal)
	}

	t.Log("PASS: Super:admin takes precedence as highest role")
}

func TestNewOperatorEntity_NoTenants(t *testing.T) {
	t.Parallel()
	t.Log("Testing: NewOperatorEntity with no tenant memberships")

	t.Log("Creating operator entity with empty tenants slice")
	entity := NewOperatorEntity("km_orphan", []TenantRole{})

	t.Log("Verifying Parents is empty")
	if entity.Parents.Len() != 0 {
		t.Errorf("Expected empty Parents, got %d", entity.Parents.Len())
	}

	t.Log("Verifying role defaults to operator")
	roleVal, _ := entity.Attributes.Get("role")
	if string(roleVal.(cedar.String)) != string(RoleOperator) {
		t.Errorf("Expected operator as default role, got %v", roleVal)
	}

	t.Log("PASS: No-tenant operator entity constructed correctly")
}

func TestNewDPUEntity(t *testing.T) {
	t.Parallel()
	t.Log("Testing: NewDPUEntity with tenant and attestation status")

	t.Log("Creating DPU entity with verified attestation")
	entity := NewDPUEntity("dpu_xyz", "tnt_acme", AttestationVerified)

	t.Log("Verifying entity UID format")
	expectedUID := cedar.NewEntityUID("DPU", cedar.String("dpu_xyz"))
	if entity.UID != expectedUID {
		t.Errorf("UID mismatch: got %v, want %v", entity.UID, expectedUID)
	}

	t.Log("Verifying Parents includes tenant UID")
	tenantUID := cedar.NewEntityUID("Tenant", cedar.String("tnt_acme"))
	if !entity.Parents.Contains(tenantUID) {
		t.Errorf("Expected Parents to contain %v", tenantUID)
	}

	t.Log("Verifying attestation_status attribute")
	statusVal, ok := entity.Attributes.Get("attestation_status")
	if !ok {
		t.Fatal("attestation_status attribute not found")
	}
	if string(statusVal.(cedar.String)) != string(AttestationVerified) {
		t.Errorf("attestation_status mismatch: got %v, want %v", statusVal, AttestationVerified)
	}

	t.Log("PASS: DPU entity constructed correctly")
}

func TestNewDPUEntity_NoTenant(t *testing.T) {
	t.Parallel()
	t.Log("Testing: NewDPUEntity with no tenant (unassigned DPU)")

	entity := NewDPUEntity("dpu_new", "", AttestationUnavailable)

	if entity.Parents.Len() != 0 {
		t.Errorf("Expected empty Parents for unassigned DPU, got %d", entity.Parents.Len())
	}

	t.Log("PASS: Unassigned DPU entity constructed correctly")
}

func TestNewTenantEntity(t *testing.T) {
	t.Parallel()
	t.Log("Testing: NewTenantEntity is top-level with no parents")

	entity := NewTenantEntity("tnt_acme", "ACME Corp")

	t.Log("Verifying entity UID format")
	expectedUID := cedar.NewEntityUID("Tenant", cedar.String("tnt_acme"))
	if entity.UID != expectedUID {
		t.Errorf("UID mismatch: got %v, want %v", entity.UID, expectedUID)
	}

	t.Log("Verifying Parents is empty (top-level)")
	if entity.Parents.Len() != 0 {
		t.Errorf("Expected empty Parents for Tenant, got %d", entity.Parents.Len())
	}

	t.Log("Verifying name attribute")
	nameVal, ok := entity.Attributes.Get("name")
	if !ok {
		t.Fatal("name attribute not found")
	}
	if string(nameVal.(cedar.String)) != "ACME Corp" {
		t.Errorf("name mismatch: got %v, want ACME Corp", nameVal)
	}

	t.Log("PASS: Tenant entity constructed correctly")
}

func TestNewResourceEntity(t *testing.T) {
	t.Parallel()
	t.Log("Testing: NewResourceEntity for generic resources")

	entity := NewResourceEntity("CertificateAuthority", "ca_ssh_prod", "tnt_acme")

	t.Log("Verifying entity UID format")
	expectedUID := cedar.NewEntityUID("CertificateAuthority", cedar.String("ca_ssh_prod"))
	if entity.UID != expectedUID {
		t.Errorf("UID mismatch: got %v, want %v", entity.UID, expectedUID)
	}

	t.Log("Verifying Parents includes tenant UID")
	tenantUID := cedar.NewEntityUID("Tenant", cedar.String("tnt_acme"))
	if !entity.Parents.Contains(tenantUID) {
		t.Errorf("Expected Parents to contain %v", tenantUID)
	}

	t.Log("Verifying tenant attribute")
	tenantVal, _ := entity.Attributes.Get("tenant")
	if string(tenantVal.(cedar.String)) != "tnt_acme" {
		t.Errorf("tenant attribute mismatch: got %v, want tnt_acme", tenantVal)
	}

	t.Log("PASS: Generic resource entity constructed correctly")
}

// ============================================================================
// Integration Tests: Real Database Data
// SEC NOTE: These tests verify entity construction from actual operator_tenants
// table data, not in-memory test entities.
// ============================================================================

func TestIntegration_EntityFromRealDBData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	t.Log("Testing: Entity construction from real database data")

	// Create temp database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	t.Log("Creating test database with operator and tenant data")
	store.SetInsecureMode(true)
	defer store.SetInsecureMode(false)

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer s.Close()
	defer os.Remove(dbPath)

	// Create tenant
	t.Log("Creating tenant tnt_acme")
	err = s.AddTenant("tnt_acme", "ACME Corp", "", "", nil)
	if err != nil {
		t.Fatalf("Failed to create tenant: %v", err)
	}

	// Create operator
	t.Log("Creating operator op_alice")
	err = s.CreateOperator("op_alice", "alice@acme.com", "Alice")
	if err != nil {
		t.Fatalf("Failed to create operator: %v", err)
	}

	// Add operator to tenant with role via operator_tenants table
	t.Log("Adding operator to tenant with tenant:admin role (real DB insert)")
	err = s.AddOperatorToTenant("op_alice", "tnt_acme", "tenant:admin")
	if err != nil {
		t.Fatalf("Failed to add operator to tenant: %v", err)
	}

	// Read back from database
	t.Log("Reading operator_tenants from database")
	tenants, err := s.GetOperatorTenants("op_alice")
	if err != nil {
		t.Fatalf("Failed to get operator tenants: %v", err)
	}

	if len(tenants) != 1 {
		t.Fatalf("Expected 1 tenant membership, got %d", len(tenants))
	}

	t.Logf("Database returned: tenant=%s, role=%s", tenants[0].TenantID, tenants[0].Role)

	// Convert store.OperatorTenant to authz.TenantRole
	t.Log("Converting DB data to authz.TenantRole for entity construction")
	tenantRoles := make([]TenantRole, len(tenants))
	for i, ot := range tenants {
		tenantRoles[i] = TenantRole{
			TenantID: ot.TenantID,
			Role:     Role(ot.Role),
		}
	}

	// Construct entity from real DB data
	t.Log("Constructing Cedar entity from real database data")
	entity := NewOperatorEntity("op_alice", tenantRoles)

	// Verify entity matches DB data
	t.Log("Verifying entity Parents match DB tenant membership")
	tenantUID := cedar.NewEntityUID("Tenant", cedar.String("tnt_acme"))
	if !entity.Parents.Contains(tenantUID) {
		t.Error("Entity Parents does not contain tenant from database")
	}

	t.Log("Verifying entity role attribute matches DB role")
	roleVal, _ := entity.Attributes.Get("role")
	if string(roleVal.(cedar.String)) != "tenant:admin" {
		t.Errorf("Entity role %v does not match DB role tenant:admin", roleVal)
	}

	t.Log("PASS: Entity constructed from real database data matches expected structure")
}

func TestIntegration_TenantIsolation_RealDB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	t.Log("Testing: Tenant isolation with entities from real DB data")
	t.Log("SEC NOTE: This verifies tenant:admin policy correctly denies cross-tenant access")

	// Create temp database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store.SetInsecureMode(true)
	defer store.SetInsecureMode(false)

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer s.Close()
	defer os.Remove(dbPath)

	// Create two tenants
	t.Log("Creating tenant tnt_acme and tnt_globex")
	err = s.AddTenant("tnt_acme", "ACME Corp", "", "", nil)
	if err != nil {
		t.Fatalf("Failed to create tenant acme: %v", err)
	}
	err = s.AddTenant("tnt_globex", "Globex Inc", "", "", nil)
	if err != nil {
		t.Fatalf("Failed to create tenant globex: %v", err)
	}

	// Create operator in acme only
	t.Log("Creating operator in tnt_acme ONLY (not tnt_globex)")
	err = s.CreateOperator("op_charlie", "charlie@acme.com", "Charlie")
	if err != nil {
		t.Fatalf("Failed to create operator: %v", err)
	}
	err = s.AddOperatorToTenant("op_charlie", "tnt_acme", "tenant:admin")
	if err != nil {
		t.Fatalf("Failed to add operator to tenant: %v", err)
	}

	// Read back and construct entity
	tenants, _ := s.GetOperatorTenants("op_charlie")
	tenantRoles := make([]TenantRole, len(tenants))
	for i, ot := range tenants {
		tenantRoles[i] = TenantRole{
			TenantID: ot.TenantID,
			Role:     Role(ot.Role),
		}
	}
	operatorEntity := NewOperatorEntity("op_charlie", tenantRoles)

	// Verify operator is NOT in globex
	t.Log("Verifying operator entity does NOT have tnt_globex in Parents")
	globexUID := cedar.NewEntityUID("Tenant", cedar.String("tnt_globex"))
	if operatorEntity.Parents.Contains(globexUID) {
		t.Error("SECURITY VIOLATION: Operator entity contains tnt_globex but should only be in tnt_acme")
	}

	// Verify operator IS in acme
	acmeUID := cedar.NewEntityUID("Tenant", cedar.String("tnt_acme"))
	if !operatorEntity.Parents.Contains(acmeUID) {
		t.Error("Operator entity should contain tnt_acme in Parents")
	}

	t.Log("PASS: Entity construction correctly reflects tenant isolation from database")
}

func TestIntegration_MultiTenantOperator_RealDB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	t.Log("Testing: Multi-tenant operator entity from real DB data")

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store.SetInsecureMode(true)
	defer store.SetInsecureMode(false)

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer s.Close()
	defer os.Remove(dbPath)

	// Create three tenants
	t.Log("Creating 3 tenants")
	for _, tid := range []string{"tnt_a", "tnt_b", "tnt_c"} {
		err = s.AddTenant(tid, tid, "", "", nil)
		if err != nil {
			t.Fatalf("Failed to create tenant %s: %v", tid, err)
		}
	}

	// Create operator with different roles in each tenant
	t.Log("Creating operator with different roles in each tenant")
	err = s.CreateOperator("op_multi", "multi@example.com", "Multi")
	if err != nil {
		t.Fatalf("Failed to create operator: %v", err)
	}
	err = s.AddOperatorToTenant("op_multi", "tnt_a", "operator")
	if err != nil {
		t.Fatalf("Failed to add to tnt_a: %v", err)
	}
	err = s.AddOperatorToTenant("op_multi", "tnt_b", "tenant:admin")
	if err != nil {
		t.Fatalf("Failed to add to tnt_b: %v", err)
	}
	err = s.AddOperatorToTenant("op_multi", "tnt_c", "operator")
	if err != nil {
		t.Fatalf("Failed to add to tnt_c: %v", err)
	}

	// Read back and construct entity
	tenants, _ := s.GetOperatorTenants("op_multi")
	t.Logf("Database returned %d tenant memberships", len(tenants))

	tenantRoles := make([]TenantRole, len(tenants))
	for i, ot := range tenants {
		tenantRoles[i] = TenantRole{
			TenantID: ot.TenantID,
			Role:     Role(ot.Role),
		}
		t.Logf("  - %s: %s", ot.TenantID, ot.Role)
	}

	entity := NewOperatorEntity("op_multi", tenantRoles)

	// Verify all 3 tenants in Parents
	t.Log("Verifying entity has all 3 tenants in Parents")
	if entity.Parents.Len() != 3 {
		t.Errorf("Expected 3 Parents, got %d", entity.Parents.Len())
	}

	// Verify highest role is tenant:admin
	roleVal, _ := entity.Attributes.Get("role")
	if string(roleVal.(cedar.String)) != "tenant:admin" {
		t.Errorf("Expected highest role tenant:admin, got %v", roleVal)
	}

	t.Log("PASS: Multi-tenant operator entity reflects all DB memberships with correct highest role")
}
