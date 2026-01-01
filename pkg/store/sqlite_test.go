package store

import (
	"os"
	"path/filepath"
	"testing"
)

// setupTestStore creates a temporary SQLite database for testing.
func setupTestStore(t *testing.T) *Store {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}

	t.Cleanup(func() {
		store.Close()
		os.Remove(dbPath)
	})

	return store
}

// TestTenantCRUD tests basic CRUD operations for tenants.
func TestTenantCRUD(t *testing.T) {
	store := setupTestStore(t)

	// Test AddTenant
	t.Run("AddTenant", func(t *testing.T) {
		err := store.AddTenant("t1", "Acme Corp", "Test tenant", "admin@acme.com", []string{"production", "us-east"})
		if err != nil {
			t.Fatalf("AddTenant failed: %v", err)
		}

		// Verify tenant was added
		tenant, err := store.GetTenant("t1")
		if err != nil {
			t.Fatalf("GetTenant failed: %v", err)
		}
		if tenant.Name != "Acme Corp" {
			t.Errorf("expected name 'Acme Corp', got '%s'", tenant.Name)
		}
		if tenant.Description != "Test tenant" {
			t.Errorf("expected description 'Test tenant', got '%s'", tenant.Description)
		}
		if tenant.Contact != "admin@acme.com" {
			t.Errorf("expected contact 'admin@acme.com', got '%s'", tenant.Contact)
		}
		if len(tenant.Tags) != 2 {
			t.Errorf("expected 2 tags, got %d", len(tenant.Tags))
		}
	})

	// Test AddTenant duplicate name
	t.Run("AddTenant_DuplicateName", func(t *testing.T) {
		err := store.AddTenant("t2", "Acme Corp", "Another", "", nil)
		if err == nil {
			t.Error("expected error for duplicate name, got nil")
		}
	})

	// Test GetTenant by name
	t.Run("GetTenant_ByName", func(t *testing.T) {
		tenant, err := store.GetTenant("Acme Corp")
		if err != nil {
			t.Fatalf("GetTenant by name failed: %v", err)
		}
		if tenant.ID != "t1" {
			t.Errorf("expected ID 't1', got '%s'", tenant.ID)
		}
	})

	// Test GetTenant not found
	t.Run("GetTenant_NotFound", func(t *testing.T) {
		_, err := store.GetTenant("nonexistent")
		if err == nil {
			t.Error("expected error for nonexistent tenant, got nil")
		}
	})

	// Test UpdateTenant
	t.Run("UpdateTenant", func(t *testing.T) {
		err := store.UpdateTenant("t1", "Acme Inc", "Updated description", "new@acme.com", []string{"staging"})
		if err != nil {
			t.Fatalf("UpdateTenant failed: %v", err)
		}

		tenant, _ := store.GetTenant("t1")
		if tenant.Name != "Acme Inc" {
			t.Errorf("expected name 'Acme Inc', got '%s'", tenant.Name)
		}
		if tenant.Description != "Updated description" {
			t.Errorf("expected description 'Updated description', got '%s'", tenant.Description)
		}
		if len(tenant.Tags) != 1 || tenant.Tags[0] != "staging" {
			t.Errorf("expected tags ['staging'], got %v", tenant.Tags)
		}
	})

	// Test ListTenants
	t.Run("ListTenants", func(t *testing.T) {
		// Add another tenant
		store.AddTenant("t3", "Beta Inc", "", "", nil)

		tenants, err := store.ListTenants()
		if err != nil {
			t.Fatalf("ListTenants failed: %v", err)
		}
		if len(tenants) != 2 {
			t.Errorf("expected 2 tenants, got %d", len(tenants))
		}
	})

	// Test RemoveTenant
	t.Run("RemoveTenant", func(t *testing.T) {
		err := store.RemoveTenant("t3")
		if err != nil {
			t.Fatalf("RemoveTenant failed: %v", err)
		}

		tenants, _ := store.ListTenants()
		if len(tenants) != 1 {
			t.Errorf("expected 1 tenant after removal, got %d", len(tenants))
		}
	})

	// Test RemoveTenant not found
	t.Run("RemoveTenant_NotFound", func(t *testing.T) {
		err := store.RemoveTenant("nonexistent")
		if err == nil {
			t.Error("expected error for removing nonexistent tenant, got nil")
		}
	})
}

// TestDPUTenantAssignment tests DPU-tenant assignment operations.
func TestDPUTenantAssignment(t *testing.T) {
	store := setupTestStore(t)

	// Setup: Create tenant and DPUs
	store.AddTenant("tenant1", "Test Tenant", "", "", nil)
	store.Add("dpu1", "bf3-lab-01", "192.168.1.204", 50051)
	store.Add("dpu2", "bf3-lab-02", "192.168.1.205", 50051)
	store.Add("dpu3", "bf3-prod-01", "192.168.1.206", 50051)

	// Test AssignDPUToTenant
	t.Run("AssignDPUToTenant", func(t *testing.T) {
		err := store.AssignDPUToTenant("dpu1", "tenant1")
		if err != nil {
			t.Fatalf("AssignDPUToTenant failed: %v", err)
		}

		dpu, _ := store.Get("dpu1")
		if dpu.TenantID == nil || *dpu.TenantID != "tenant1" {
			t.Errorf("expected tenant_id 'tenant1', got %v", dpu.TenantID)
		}
	})

	// Test AssignDPUToTenant by name
	t.Run("AssignDPUToTenant_ByName", func(t *testing.T) {
		err := store.AssignDPUToTenant("bf3-lab-02", "tenant1")
		if err != nil {
			t.Fatalf("AssignDPUToTenant by name failed: %v", err)
		}

		dpu, _ := store.Get("dpu2")
		if dpu.TenantID == nil || *dpu.TenantID != "tenant1" {
			t.Errorf("expected tenant_id 'tenant1', got %v", dpu.TenantID)
		}
	})

	// Test ListDPUsByTenant
	t.Run("ListDPUsByTenant", func(t *testing.T) {
		dpus, err := store.ListDPUsByTenant("tenant1")
		if err != nil {
			t.Fatalf("ListDPUsByTenant failed: %v", err)
		}
		if len(dpus) != 2 {
			t.Errorf("expected 2 DPUs for tenant, got %d", len(dpus))
		}
	})

	// Test GetTenantDPUCount
	t.Run("GetTenantDPUCount", func(t *testing.T) {
		count, err := store.GetTenantDPUCount("tenant1")
		if err != nil {
			t.Fatalf("GetTenantDPUCount failed: %v", err)
		}
		if count != 2 {
			t.Errorf("expected count 2, got %d", count)
		}
	})

	// Test UnassignDPUFromTenant
	t.Run("UnassignDPUFromTenant", func(t *testing.T) {
		err := store.UnassignDPUFromTenant("dpu1")
		if err != nil {
			t.Fatalf("UnassignDPUFromTenant failed: %v", err)
		}

		dpu, _ := store.Get("dpu1")
		if dpu.TenantID != nil {
			t.Errorf("expected nil tenant_id after unassign, got %v", dpu.TenantID)
		}

		count, _ := store.GetTenantDPUCount("tenant1")
		if count != 1 {
			t.Errorf("expected count 1 after unassign, got %d", count)
		}
	})

	// Test UnassignDPUFromTenant not found
	t.Run("UnassignDPUFromTenant_NotFound", func(t *testing.T) {
		err := store.UnassignDPUFromTenant("nonexistent")
		if err == nil {
			t.Error("expected error for unassigning nonexistent DPU, got nil")
		}
	})
}

// TestDPULabels tests the labels functionality on DPUs.
func TestDPULabels(t *testing.T) {
	store := setupTestStore(t)

	// Create a DPU
	store.Add("dpu1", "bf3-test", "192.168.1.204", 50051)

	t.Run("DPU_HasEmptyLabels", func(t *testing.T) {
		dpu, err := store.Get("dpu1")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if dpu.Labels == nil {
			t.Error("expected non-nil labels map, got nil")
		}
		if len(dpu.Labels) != 0 {
			t.Errorf("expected empty labels, got %v", dpu.Labels)
		}
	})
}

// TestTenantEmptyTags tests tenant with empty tags.
func TestTenantEmptyTags(t *testing.T) {
	store := setupTestStore(t)

	// Create tenant with nil tags
	err := store.AddTenant("t1", "No Tags Tenant", "", "", nil)
	if err != nil {
		t.Fatalf("AddTenant failed: %v", err)
	}

	tenant, err := store.GetTenant("t1")
	if err != nil {
		t.Fatalf("GetTenant failed: %v", err)
	}

	if tenant.Tags == nil {
		t.Error("expected non-nil tags slice, got nil")
	}
	if len(tenant.Tags) != 0 {
		t.Errorf("expected empty tags, got %v", tenant.Tags)
	}
}
