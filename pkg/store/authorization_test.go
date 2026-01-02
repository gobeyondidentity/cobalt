package store

import (
	"testing"
	"time"
)

// TestCreateAuthorization tests successful authorization creation.
func TestCreateAuthorization(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	err := store.CreateAuthorization(
		"auth1",
		"op1",
		"tenant1",
		[]string{"ca1", "ca2"},
		[]string{"device1", "device2"},
		"admin@example.com",
		nil,
	)
	if err != nil {
		t.Fatalf("CreateAuthorization failed: %v", err)
	}

	// Verify it was created
	auth, err := store.GetAuthorization("auth1")
	if err != nil {
		t.Fatalf("GetAuthorization failed: %v", err)
	}

	if auth.ID != "auth1" {
		t.Errorf("expected ID 'auth1', got '%s'", auth.ID)
	}
	if auth.OperatorID != "op1" {
		t.Errorf("expected OperatorID 'op1', got '%s'", auth.OperatorID)
	}
	if auth.TenantID != "tenant1" {
		t.Errorf("expected TenantID 'tenant1', got '%s'", auth.TenantID)
	}
	if auth.CreatedBy != "admin@example.com" {
		t.Errorf("expected CreatedBy 'admin@example.com', got '%s'", auth.CreatedBy)
	}
	if auth.ExpiresAt != nil {
		t.Errorf("expected nil ExpiresAt, got %v", auth.ExpiresAt)
	}
	if len(auth.CAIDs) != 2 {
		t.Errorf("expected 2 CAIDs, got %d", len(auth.CAIDs))
	}
	if len(auth.DeviceIDs) != 2 {
		t.Errorf("expected 2 DeviceIDs, got %d", len(auth.DeviceIDs))
	}
}

// TestCreateAuthorizationWithExpiry tests authorization with expiration.
func TestCreateAuthorizationWithExpiry(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	expiry := time.Now().Add(24 * time.Hour)
	err := store.CreateAuthorization(
		"auth2",
		"op1",
		"tenant1",
		[]string{"ca1"},
		[]string{"all"},
		"admin@example.com",
		&expiry,
	)
	if err != nil {
		t.Fatalf("CreateAuthorization with expiry failed: %v", err)
	}

	auth, err := store.GetAuthorization("auth2")
	if err != nil {
		t.Fatalf("GetAuthorization failed: %v", err)
	}

	if auth.ExpiresAt == nil {
		t.Error("expected non-nil ExpiresAt")
	} else if auth.ExpiresAt.Unix() != expiry.Unix() {
		t.Errorf("expected ExpiresAt %v, got %v", expiry.Unix(), auth.ExpiresAt.Unix())
	}
}

// TestListAuthorizationsByOperator tests listing authorizations for an operator.
func TestListAuthorizationsByOperator(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	// Create two authorizations for op1
	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"device1"}, "admin", nil)
	store.CreateAuthorization("auth2", "op1", "tenant1", []string{"ca2"}, []string{"device2"}, "admin", nil)
	// Create one for op2
	store.CreateAuthorization("auth3", "op2", "tenant1", []string{"ca1"}, []string{"device1"}, "admin", nil)

	auths, err := store.ListAuthorizationsByOperator("op1")
	if err != nil {
		t.Fatalf("ListAuthorizationsByOperator failed: %v", err)
	}

	if len(auths) != 2 {
		t.Errorf("expected 2 authorizations for op1, got %d", len(auths))
	}

	for _, auth := range auths {
		if auth.OperatorID != "op1" {
			t.Errorf("expected OperatorID 'op1', got '%s'", auth.OperatorID)
		}
		// Verify CAIDs and DeviceIDs are populated
		if len(auth.CAIDs) == 0 {
			t.Error("expected non-empty CAIDs")
		}
		if len(auth.DeviceIDs) == 0 {
			t.Error("expected non-empty DeviceIDs")
		}
	}
}

// TestListAuthorizationsByTenant tests listing authorizations for a tenant.
func TestListAuthorizationsByTenant(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	// Create authorizations
	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"device1"}, "admin", nil)
	store.CreateAuthorization("auth2", "op2", "tenant1", []string{"ca2"}, []string{"device2"}, "admin", nil)

	auths, err := store.ListAuthorizationsByTenant("tenant1")
	if err != nil {
		t.Fatalf("ListAuthorizationsByTenant failed: %v", err)
	}

	if len(auths) != 2 {
		t.Errorf("expected 2 authorizations for tenant1, got %d", len(auths))
	}
}

// TestDeleteAuthorization tests deleting an authorization.
func TestDeleteAuthorization(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	// Create and then delete
	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"device1"}, "admin", nil)

	err := store.DeleteAuthorization("auth1")
	if err != nil {
		t.Fatalf("DeleteAuthorization failed: %v", err)
	}

	// Verify it's gone
	_, err = store.GetAuthorization("auth1")
	if err == nil {
		t.Error("expected error for deleted authorization, got nil")
	}

	// Verify cascade deleted the CA and device associations
	auths, _ := store.ListAuthorizationsByOperator("op1")
	if len(auths) != 0 {
		t.Errorf("expected 0 authorizations after delete, got %d", len(auths))
	}
}

// TestDeleteAuthorizationNotFound tests deleting a non-existent authorization.
func TestDeleteAuthorizationNotFound(t *testing.T) {
	store := setupTestStore(t)

	err := store.DeleteAuthorization("nonexistent")
	if err == nil {
		t.Error("expected error for deleting nonexistent authorization, got nil")
	}
}

// TestCheckCAAuthorizationAuthorized tests CA authorization check when authorized.
func TestCheckCAAuthorizationAuthorized(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1", "ca2"}, []string{"device1"}, "admin", nil)

	authorized, err := store.CheckCAAuthorization("op1", "ca1")
	if err != nil {
		t.Fatalf("CheckCAAuthorization failed: %v", err)
	}
	if !authorized {
		t.Error("expected operator to be authorized for ca1")
	}

	authorized, err = store.CheckCAAuthorization("op1", "ca2")
	if err != nil {
		t.Fatalf("CheckCAAuthorization failed: %v", err)
	}
	if !authorized {
		t.Error("expected operator to be authorized for ca2")
	}
}

// TestCheckCAAuthorizationNotAuthorized tests CA authorization check when not authorized.
func TestCheckCAAuthorizationNotAuthorized(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"device1"}, "admin", nil)

	// Check for CA that operator does NOT have access to
	authorized, err := store.CheckCAAuthorization("op1", "ca-not-authorized")
	if err != nil {
		t.Fatalf("CheckCAAuthorization failed: %v", err)
	}
	if authorized {
		t.Error("expected operator to NOT be authorized for ca-not-authorized")
	}

	// Check for operator with no authorizations
	authorized, err = store.CheckCAAuthorization("op-no-auths", "ca1")
	if err != nil {
		t.Fatalf("CheckCAAuthorization failed: %v", err)
	}
	if authorized {
		t.Error("expected op-no-auths to NOT be authorized")
	}
}

// TestCheckDeviceAuthorizationExplicit tests device authorization with explicit device ID.
func TestCheckDeviceAuthorizationExplicit(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"device1", "device2"}, "admin", nil)

	// Authorized for device1
	authorized, err := store.CheckDeviceAuthorization("op1", "device1")
	if err != nil {
		t.Fatalf("CheckDeviceAuthorization failed: %v", err)
	}
	if !authorized {
		t.Error("expected operator to be authorized for device1")
	}

	// Authorized for device2
	authorized, err = store.CheckDeviceAuthorization("op1", "device2")
	if err != nil {
		t.Fatalf("CheckDeviceAuthorization failed: %v", err)
	}
	if !authorized {
		t.Error("expected operator to be authorized for device2")
	}

	// NOT authorized for device3
	authorized, err = store.CheckDeviceAuthorization("op1", "device3")
	if err != nil {
		t.Fatalf("CheckDeviceAuthorization failed: %v", err)
	}
	if authorized {
		t.Error("expected operator to NOT be authorized for device3")
	}
}

// TestCheckDeviceAuthorizationAllSelector tests device authorization with "all" selector.
func TestCheckDeviceAuthorizationAllSelector(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	// Create authorization with "all" selector
	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"all"}, "admin", nil)

	// Should be authorized for any device
	authorized, err := store.CheckDeviceAuthorization("op1", "device1")
	if err != nil {
		t.Fatalf("CheckDeviceAuthorization failed: %v", err)
	}
	if !authorized {
		t.Error("expected operator to be authorized for device1 via 'all' selector")
	}

	authorized, err = store.CheckDeviceAuthorization("op1", "any-random-device")
	if err != nil {
		t.Fatalf("CheckDeviceAuthorization failed: %v", err)
	}
	if !authorized {
		t.Error("expected operator to be authorized for any-random-device via 'all' selector")
	}
}

// TestCheckFullAuthorization tests combined CA and device authorization check.
func TestCheckFullAuthorization(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	// Create authorization for op1: ca1 + device1
	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"device1"}, "admin", nil)

	// Authorized for ca1 + device1
	authorized, err := store.CheckFullAuthorization("op1", "ca1", "device1")
	if err != nil {
		t.Fatalf("CheckFullAuthorization failed: %v", err)
	}
	if !authorized {
		t.Error("expected operator to be authorized for ca1 + device1")
	}

	// NOT authorized for ca1 + device2 (device not in scope)
	authorized, err = store.CheckFullAuthorization("op1", "ca1", "device2")
	if err != nil {
		t.Fatalf("CheckFullAuthorization failed: %v", err)
	}
	if authorized {
		t.Error("expected operator to NOT be authorized for ca1 + device2")
	}

	// NOT authorized for ca2 + device1 (CA not in scope)
	authorized, err = store.CheckFullAuthorization("op1", "ca2", "device1")
	if err != nil {
		t.Fatalf("CheckFullAuthorization failed: %v", err)
	}
	if authorized {
		t.Error("expected operator to NOT be authorized for ca2 + device1")
	}
}

// TestCheckFullAuthorizationWithAllDevices tests full authorization with "all" device selector.
func TestCheckFullAuthorizationWithAllDevices(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	// Create authorization with "all" devices
	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"all"}, "admin", nil)

	// Authorized for ca1 + any device
	authorized, err := store.CheckFullAuthorization("op1", "ca1", "any-device")
	if err != nil {
		t.Fatalf("CheckFullAuthorization failed: %v", err)
	}
	if !authorized {
		t.Error("expected operator to be authorized for ca1 + any device via 'all' selector")
	}

	// NOT authorized for ca2 + any device (CA not in scope)
	authorized, err = store.CheckFullAuthorization("op1", "ca2", "any-device")
	if err != nil {
		t.Fatalf("CheckFullAuthorization failed: %v", err)
	}
	if authorized {
		t.Error("expected operator to NOT be authorized for ca2")
	}
}

// TestCheckAuthorizationMultipleGrants tests authorization across multiple grants.
func TestCheckAuthorizationMultipleGrants(t *testing.T) {
	store := setupTestStore(t)
	setupAuthorizationTestData(t, store)

	// Create two separate authorizations for same operator
	store.CreateAuthorization("auth1", "op1", "tenant1", []string{"ca1"}, []string{"device1"}, "admin", nil)
	store.CreateAuthorization("auth2", "op1", "tenant1", []string{"ca2"}, []string{"device2"}, "admin", nil)

	// Operator should be authorized for ca1 (from auth1)
	authorized, _ := store.CheckCAAuthorization("op1", "ca1")
	if !authorized {
		t.Error("expected operator to be authorized for ca1")
	}

	// Operator should be authorized for ca2 (from auth2)
	authorized, _ = store.CheckCAAuthorization("op1", "ca2")
	if !authorized {
		t.Error("expected operator to be authorized for ca2")
	}

	// Operator should be authorized for device1 (from auth1)
	authorized, _ = store.CheckDeviceAuthorization("op1", "device1")
	if !authorized {
		t.Error("expected operator to be authorized for device1")
	}

	// Operator should be authorized for device2 (from auth2)
	authorized, _ = store.CheckDeviceAuthorization("op1", "device2")
	if !authorized {
		t.Error("expected operator to be authorized for device2")
	}
}

// setupAuthorizationTestData creates prerequisite data for authorization tests.
func setupAuthorizationTestData(t *testing.T, store *Store) {
	t.Helper()

	// Create tenant
	if err := store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create operators
	if err := store.CreateOperator("op1", "op1@example.com", "Operator One"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	if err := store.CreateOperator("op2", "op2@example.com", "Operator Two"); err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
}
