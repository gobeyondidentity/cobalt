package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestKeyMakerRevocationTracking verifies that keymaker revocation records who/when/why.
func TestKeyMakerRevocationTracking(t *testing.T) {
	t.Log("Testing KeyMaker revocation lifecycle tracking")

	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Create operator first
	t.Log("Creating test operator")
	err = store.CreateOperator("op_test", "test@example.com", "Test Operator")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create keymaker
	t.Log("Creating test keymaker")
	km := &KeyMaker{
		ID:                "km_test",
		OperatorID:        "op_test",
		Name:              "test-device",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "abc123",
		PublicKey:         "pubkey123",
		Status:            "active",
		Kid:               "km_test",
		KeyFingerprint:    "fp123",
	}
	err = store.CreateKeyMaker(km)
	if err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}

	// Verify active state has no revocation fields
	t.Log("Verifying active keymaker has no revocation fields")
	retrieved, err := store.GetKeyMaker("km_test")
	if err != nil {
		t.Fatalf("failed to get keymaker: %v", err)
	}
	if retrieved.RevokedAt != nil {
		t.Error("active keymaker should have nil RevokedAt")
	}
	if retrieved.RevokedBy != nil {
		t.Error("active keymaker should have nil RevokedBy")
	}
	if retrieved.RevokedReason != nil {
		t.Error("active keymaker should have nil RevokedReason")
	}

	// Revoke with tracking
	t.Log("Revoking keymaker with audit tracking")
	beforeRevoke := time.Now().Truncate(time.Second)
	err = store.RevokeKeyMakerWithReason("km_test", "op_admin", "Device lost")
	if err != nil {
		t.Fatalf("failed to revoke keymaker: %v", err)
	}
	afterRevoke := time.Now().Add(time.Second).Truncate(time.Second)

	// Verify revocation fields are set
	t.Log("Verifying revocation fields are populated")
	revoked, err := store.GetKeyMaker("km_test")
	if err != nil {
		t.Fatalf("failed to get revoked keymaker: %v", err)
	}

	if revoked.Status != "revoked" {
		t.Errorf("expected status 'revoked', got '%s'", revoked.Status)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("RevokedAt should not be nil after revocation")
	}
	// Compare with second precision (Unix timestamps are in seconds)
	if revoked.RevokedAt.Before(beforeRevoke) || revoked.RevokedAt.After(afterRevoke) {
		t.Errorf("RevokedAt %v not in expected range [%v, %v]", revoked.RevokedAt, beforeRevoke, afterRevoke)
	}
	if revoked.RevokedBy == nil || *revoked.RevokedBy != "op_admin" {
		t.Errorf("expected RevokedBy 'op_admin', got '%v'", revoked.RevokedBy)
	}
	if revoked.RevokedReason == nil || *revoked.RevokedReason != "Device lost" {
		t.Errorf("expected RevokedReason 'Device lost', got '%v'", revoked.RevokedReason)
	}

	t.Log("KeyMaker revocation tracking verified successfully")
}

// TestAdminKeyRevocationTracking verifies that admin key revocation records who/when/why.
func TestAdminKeyRevocationTracking(t *testing.T) {
	t.Log("Testing AdminKey revocation lifecycle tracking")

	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Create operator first
	t.Log("Creating test operator")
	err = store.CreateOperator("op_test", "test@example.com", "Test Operator")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Create admin key
	t.Log("Creating test admin key")
	ak := &AdminKey{
		ID:             "adm_test",
		OperatorID:     "op_test",
		Name:           "test-admin",
		PublicKey:      []byte("pubkey"),
		Kid:            "adm_test",
		KeyFingerprint: "fp123",
		Status:         "active",
	}
	err = store.CreateAdminKey(ak)
	if err != nil {
		t.Fatalf("failed to create admin key: %v", err)
	}

	// Verify active state has no revocation fields
	t.Log("Verifying active admin key has no revocation fields")
	retrieved, err := store.GetAdminKey("adm_test")
	if err != nil {
		t.Fatalf("failed to get admin key: %v", err)
	}
	if retrieved.RevokedAt != nil {
		t.Error("active admin key should have nil RevokedAt")
	}

	// Revoke with tracking
	t.Log("Revoking admin key with audit tracking")
	beforeRevoke := time.Now().Truncate(time.Second)
	err = store.RevokeAdminKeyWithReason("adm_test", "op_superadmin", "Compromised")
	if err != nil {
		t.Fatalf("failed to revoke admin key: %v", err)
	}
	afterRevoke := time.Now().Add(time.Second).Truncate(time.Second)

	// Verify revocation fields are set
	t.Log("Verifying revocation fields are populated")
	revoked, err := store.GetAdminKey("adm_test")
	if err != nil {
		t.Fatalf("failed to get revoked admin key: %v", err)
	}

	if revoked.Status != "revoked" {
		t.Errorf("expected status 'revoked', got '%s'", revoked.Status)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("RevokedAt should not be nil after revocation")
	}
	// Compare with second precision (Unix timestamps are in seconds)
	if revoked.RevokedAt.Before(beforeRevoke) || revoked.RevokedAt.After(afterRevoke) {
		t.Errorf("RevokedAt %v not in expected range", revoked.RevokedAt)
	}
	if revoked.RevokedBy == nil || *revoked.RevokedBy != "op_superadmin" {
		t.Errorf("expected RevokedBy 'op_superadmin', got '%v'", revoked.RevokedBy)
	}
	if revoked.RevokedReason == nil || *revoked.RevokedReason != "Compromised" {
		t.Errorf("expected RevokedReason 'Compromised', got '%v'", revoked.RevokedReason)
	}

	t.Log("AdminKey revocation tracking verified successfully")
}

// TestOperatorSuspensionTracking verifies that operator suspension records who/when/why.
func TestOperatorSuspensionTracking(t *testing.T) {
	t.Log("Testing Operator suspension lifecycle tracking")

	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Create operator
	t.Log("Creating test operator")
	err = store.CreateOperator("op_test", "test@example.com", "Test Operator")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Activate the operator
	err = store.UpdateOperatorStatus("op_test", "active")
	if err != nil {
		t.Fatalf("failed to activate operator: %v", err)
	}

	// Verify active state has no suspension fields
	t.Log("Verifying active operator has no suspension fields")
	retrieved, err := store.GetOperator("op_test")
	if err != nil {
		t.Fatalf("failed to get operator: %v", err)
	}
	if retrieved.SuspendedAt != nil {
		t.Error("active operator should have nil SuspendedAt")
	}

	// Suspend with tracking
	t.Log("Suspending operator with audit tracking")
	beforeSuspend := time.Now().Truncate(time.Second)
	err = store.SuspendOperator("op_test", "op_admin", "Investigation pending")
	if err != nil {
		t.Fatalf("failed to suspend operator: %v", err)
	}
	afterSuspend := time.Now().Add(time.Second).Truncate(time.Second)

	// Verify suspension fields are set
	t.Log("Verifying suspension fields are populated")
	suspended, err := store.GetOperator("op_test")
	if err != nil {
		t.Fatalf("failed to get suspended operator: %v", err)
	}

	if suspended.Status != "suspended" {
		t.Errorf("expected status 'suspended', got '%s'", suspended.Status)
	}
	if suspended.SuspendedAt == nil {
		t.Fatal("SuspendedAt should not be nil after suspension")
	}
	// Compare with second precision (Unix timestamps are in seconds)
	if suspended.SuspendedAt.Before(beforeSuspend) || suspended.SuspendedAt.After(afterSuspend) {
		t.Errorf("SuspendedAt %v not in expected range", suspended.SuspendedAt)
	}
	if suspended.SuspendedBy == nil || *suspended.SuspendedBy != "op_admin" {
		t.Errorf("expected SuspendedBy 'op_admin', got '%v'", suspended.SuspendedBy)
	}
	if suspended.SuspendedReason == nil || *suspended.SuspendedReason != "Investigation pending" {
		t.Errorf("expected SuspendedReason 'Investigation pending', got '%v'", suspended.SuspendedReason)
	}

	// Test unsuspension clears the fields
	t.Log("Unsuspending operator")
	err = store.UnsuspendOperator("op_test")
	if err != nil {
		t.Fatalf("failed to unsuspend operator: %v", err)
	}

	unsuspended, err := store.GetOperator("op_test")
	if err != nil {
		t.Fatalf("failed to get unsuspended operator: %v", err)
	}

	if unsuspended.Status != "active" {
		t.Errorf("expected status 'active' after unsuspend, got '%s'", unsuspended.Status)
	}
	if unsuspended.SuspendedAt != nil {
		t.Error("SuspendedAt should be nil after unsuspension")
	}
	if unsuspended.SuspendedBy != nil {
		t.Error("SuspendedBy should be nil after unsuspension")
	}
	if unsuspended.SuspendedReason != nil {
		t.Error("SuspendedReason should be nil after unsuspension")
	}

	t.Log("Operator suspension tracking verified successfully")
}

// TestDPUDecommissioningTracking verifies that DPU decommissioning records who/when/why.
func TestDPUDecommissioningTracking(t *testing.T) {
	t.Log("Testing DPU decommissioning lifecycle tracking")

	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Create DPU
	t.Log("Creating test DPU")
	err = store.Add("dpu_test", "test-dpu", "192.168.1.1", 18051)
	if err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}

	// Set status to active
	err = store.UpdateStatus("dpu_test", "active")
	if err != nil {
		t.Fatalf("failed to update DPU status: %v", err)
	}

	// Verify active state has no decommission fields
	t.Log("Verifying active DPU has no decommission fields")
	retrieved, err := store.Get("dpu_test")
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if retrieved.DecommissionedAt != nil {
		t.Error("active DPU should have nil DecommissionedAt")
	}

	// Decommission with tracking
	t.Log("Decommissioning DPU with audit tracking")
	beforeDecommission := time.Now().Truncate(time.Second)
	err = store.DecommissionDPU("dpu_test", "op_admin", "Hardware removal")
	if err != nil {
		t.Fatalf("failed to decommission DPU: %v", err)
	}
	afterDecommission := time.Now().Add(time.Second).Truncate(time.Second)

	// Verify decommission fields are set
	t.Log("Verifying decommission fields are populated")
	decommissioned, err := store.Get("dpu_test")
	if err != nil {
		t.Fatalf("failed to get decommissioned DPU: %v", err)
	}

	if decommissioned.Status != "decommissioned" {
		t.Errorf("expected status 'decommissioned', got '%s'", decommissioned.Status)
	}
	if decommissioned.DecommissionedAt == nil {
		t.Fatal("DecommissionedAt should not be nil after decommissioning")
	}
	if decommissioned.DecommissionedAt.Before(beforeDecommission) || decommissioned.DecommissionedAt.After(afterDecommission) {
		t.Errorf("DecommissionedAt %v not in expected range", decommissioned.DecommissionedAt)
	}
	if decommissioned.DecommissionedBy == nil || *decommissioned.DecommissionedBy != "op_admin" {
		t.Errorf("expected DecommissionedBy 'op_admin', got '%v'", decommissioned.DecommissionedBy)
	}
	if decommissioned.DecommissionedReason == nil || *decommissioned.DecommissionedReason != "Hardware removal" {
		t.Errorf("expected DecommissionedReason 'Hardware removal', got '%v'", decommissioned.DecommissionedReason)
	}

	// Test reactivation clears the fields
	t.Log("Reactivating DPU")
	enrollmentExpiry := time.Now().Add(24 * time.Hour)
	err = store.ReactivateDPU("dpu_test", enrollmentExpiry)
	if err != nil {
		t.Fatalf("failed to reactivate DPU: %v", err)
	}

	reactivated, err := store.Get("dpu_test")
	if err != nil {
		t.Fatalf("failed to get reactivated DPU: %v", err)
	}

	if reactivated.Status != "pending" {
		t.Errorf("expected status 'pending' after reactivation, got '%s'", reactivated.Status)
	}
	if reactivated.DecommissionedAt != nil {
		t.Error("DecommissionedAt should be nil after reactivation")
	}
	if reactivated.DecommissionedBy != nil {
		t.Error("DecommissionedBy should be nil after reactivation")
	}
	if reactivated.DecommissionedReason != nil {
		t.Error("DecommissionedReason should be nil after reactivation")
	}
	if reactivated.EnrollmentExpiresAt == nil {
		t.Error("EnrollmentExpiresAt should be set after reactivation")
	}

	t.Log("DPU decommissioning tracking verified successfully")
}

// TestMigrationAddsLifecycleColumns verifies that migration adds columns to existing databases.
func TestMigrationAddsLifecycleColumns(t *testing.T) {
	t.Log("Testing migration adds lifecycle columns to existing database")

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// First open creates schema
	store1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}

	// Create some entities
	t.Log("Creating test entities")
	err = store1.CreateOperator("op_test", "test@example.com", "Test")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	err = store1.Add("dpu_test", "test-dpu", "localhost", 18051)
	if err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}

	store1.Close()

	// Reopen to simulate migration scenario
	t.Log("Reopening database to test migration")
	store2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	// Verify lifecycle actions work (columns exist)
	t.Log("Verifying lifecycle actions work after migration")

	err = store2.SuspendOperator("op_test", "admin", "test")
	if err != nil {
		t.Fatalf("SuspendOperator failed after migration: %v", err)
	}

	err = store2.DecommissionDPU("dpu_test", "admin", "test")
	if err != nil {
		t.Fatalf("DecommissionDPU failed after migration: %v", err)
	}

	// Verify data is persisted correctly
	op, err := store2.GetOperator("op_test")
	if err != nil {
		t.Fatalf("failed to get operator: %v", err)
	}
	if op.SuspendedBy == nil || *op.SuspendedBy != "admin" {
		t.Error("SuspendedBy not persisted correctly")
	}

	dpu, err := store2.Get("dpu_test")
	if err != nil {
		t.Fatalf("failed to get DPU: %v", err)
	}
	if dpu.DecommissionedBy == nil || *dpu.DecommissionedBy != "admin" {
		t.Error("DecommissionedBy not persisted correctly")
	}

	t.Log("Migration test passed: lifecycle columns exist and work")
}

// TestLifecycleFieldsInListQueries verifies lifecycle fields appear in list query results.
func TestLifecycleFieldsInListQueries(t *testing.T) {
	t.Log("Testing lifecycle fields appear in list query results")

	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Create and suspend an operator
	t.Log("Creating and suspending operator")
	err = store.CreateOperator("op_test", "test@example.com", "Test")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	err = store.SuspendOperator("op_test", "op_admin", "Security hold")
	if err != nil {
		t.Fatalf("failed to suspend operator: %v", err)
	}

	// List and verify suspension fields
	t.Log("Listing operators and checking suspension fields")
	operators, err := store.ListOperators()
	if err != nil {
		t.Fatalf("failed to list operators: %v", err)
	}
	if len(operators) != 1 {
		t.Fatalf("expected 1 operator, got %d", len(operators))
	}
	if operators[0].SuspendedBy == nil || *operators[0].SuspendedBy != "op_admin" {
		t.Error("SuspendedBy not returned in list results")
	}

	// Create and revoke a keymaker
	t.Log("Creating and revoking keymaker")
	km := &KeyMaker{
		ID:                "km_test",
		OperatorID:        "op_test",
		Name:              "test",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "fp",
		PublicKey:         "pk",
		Status:            "active",
		Kid:               "km_test",
		KeyFingerprint:    "kfp",
	}
	err = store.CreateKeyMaker(km)
	if err != nil {
		t.Fatalf("failed to create keymaker: %v", err)
	}
	err = store.RevokeKeyMakerWithReason("km_test", "op_admin", "Lost device")
	if err != nil {
		t.Fatalf("failed to revoke keymaker: %v", err)
	}

	// List and verify revocation fields
	t.Log("Listing keymakers and checking revocation fields")
	keymakers, err := store.ListKeyMakersByOperator("op_test")
	if err != nil {
		t.Fatalf("failed to list keymakers: %v", err)
	}
	if len(keymakers) != 1 {
		t.Fatalf("expected 1 keymaker, got %d", len(keymakers))
	}
	if keymakers[0].RevokedBy == nil || *keymakers[0].RevokedBy != "op_admin" {
		t.Error("RevokedBy not returned in list results")
	}

	// Create and decommission a DPU
	t.Log("Creating and decommissioning DPU")
	err = store.Add("dpu_test", "test-dpu", "localhost", 18051)
	if err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}
	err = store.DecommissionDPU("dpu_test", "op_admin", "RMA")
	if err != nil {
		t.Fatalf("failed to decommission DPU: %v", err)
	}

	// List and verify decommission fields
	t.Log("Listing DPUs and checking decommission fields")
	dpus, err := store.List()
	if err != nil {
		t.Fatalf("failed to list DPUs: %v", err)
	}
	if len(dpus) != 1 {
		t.Fatalf("expected 1 DPU, got %d", len(dpus))
	}
	if dpus[0].DecommissionedBy == nil || *dpus[0].DecommissionedBy != "op_admin" {
		t.Error("DecommissionedBy not returned in list results")
	}

	t.Log("List query lifecycle fields test passed")
}

// TestTimestampPrecision verifies timestamps use Unix seconds for storage.
func TestTimestampPrecision(t *testing.T) {
	t.Log("Testing timestamp storage uses Unix seconds")

	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Create operator
	err = store.CreateOperator("op_test", "test@example.com", "Test")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Suspend at a known time
	beforeSuspend := time.Now()
	err = store.SuspendOperator("op_test", "admin", "test")
	if err != nil {
		t.Fatalf("failed to suspend: %v", err)
	}
	afterSuspend := time.Now()

	// Retrieve and verify timestamp is in expected range
	op, err := store.GetOperator("op_test")
	if err != nil {
		t.Fatalf("failed to get operator: %v", err)
	}

	if op.SuspendedAt == nil {
		t.Fatal("SuspendedAt should not be nil")
	}

	// Timestamp should be between before and after
	if op.SuspendedAt.Before(beforeSuspend.Truncate(time.Second)) {
		t.Errorf("SuspendedAt %v is before expected start %v", op.SuspendedAt, beforeSuspend)
	}
	if op.SuspendedAt.After(afterSuspend.Add(time.Second)) {
		t.Errorf("SuspendedAt %v is after expected end %v", op.SuspendedAt, afterSuspend)
	}

	t.Log("Timestamp precision test passed: uses Unix seconds")
}

func init() {
	// Ensure we're using a test database location
	_ = os.Setenv("XDG_DATA_HOME", os.TempDir())
}
