package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nmelo/secure-infra/pkg/store"
)

// setupTestServer creates a test server with a temporary database.
func setupTestServer(t *testing.T) (*Server, *http.ServeMux) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store.SetInsecureMode(true)
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}

	t.Cleanup(func() {
		s.Close()
		os.Remove(dbPath)
	})

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	return server, mux
}

// TestTenantListEmpty tests listing tenants when none exist.
func TestTenantListEmpty(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/tenants", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result []tenantResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected empty list, got %d tenants", len(result))
	}
}

// TestTenantCreate tests creating a new tenant.
func TestTenantCreate(t *testing.T) {
	_, mux := setupTestServer(t)

	body := `{"name": "Acme Corp", "description": "Test tenant", "contact": "admin@acme.com", "tags": ["production", "us-east"]}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var result tenantResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Name != "Acme Corp" {
		t.Errorf("expected name 'Acme Corp', got '%s'", result.Name)
	}
	if result.Description != "Test tenant" {
		t.Errorf("expected description 'Test tenant', got '%s'", result.Description)
	}
	if result.Contact != "admin@acme.com" {
		t.Errorf("expected contact 'admin@acme.com', got '%s'", result.Contact)
	}
	if len(result.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(result.Tags))
	}
	if result.ID == "" {
		t.Error("expected non-empty ID")
	}
}

// TestTenantCreate_MissingName tests creating a tenant without a name.
func TestTenantCreate_MissingName(t *testing.T) {
	_, mux := setupTestServer(t)

	body := `{"description": "No name tenant"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestTenantCreate_DuplicateName tests creating a tenant with duplicate name.
func TestTenantCreate_DuplicateName(t *testing.T) {
	_, mux := setupTestServer(t)

	// Create first tenant
	body := `{"name": "Acme Corp"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("failed to create first tenant: %d", w.Code)
	}

	// Try to create duplicate
	req = httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d", w.Code)
	}
}

// TestTenantGet tests retrieving a specific tenant.
func TestTenantGet(t *testing.T) {
	_, mux := setupTestServer(t)

	// Create a tenant first
	body := `{"name": "Test Tenant", "description": "For testing"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var created tenantResponse
	json.NewDecoder(w.Body).Decode(&created)

	// Get the tenant
	req = httptest.NewRequest("GET", "/api/tenants/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result tenantResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Name != "Test Tenant" {
		t.Errorf("expected name 'Test Tenant', got '%s'", result.Name)
	}
}

// TestTenantGet_NotFound tests retrieving a non-existent tenant.
func TestTenantGet_NotFound(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/tenants/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

// TestTenantUpdate tests updating a tenant.
func TestTenantUpdate(t *testing.T) {
	_, mux := setupTestServer(t)

	// Create a tenant first
	body := `{"name": "Original Name", "description": "Original desc"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var created tenantResponse
	json.NewDecoder(w.Body).Decode(&created)

	// Update the tenant
	updateBody := `{"name": "New Name", "description": "New description", "contact": "new@example.com"}`
	req = httptest.NewRequest("PUT", "/api/tenants/"+created.ID, bytes.NewBufferString(updateBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result tenantResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Name != "New Name" {
		t.Errorf("expected name 'New Name', got '%s'", result.Name)
	}
	if result.Description != "New description" {
		t.Errorf("expected description 'New description', got '%s'", result.Description)
	}
}

// TestTenantDelete tests deleting a tenant.
func TestTenantDelete(t *testing.T) {
	_, mux := setupTestServer(t)

	// Create a tenant first
	body := `{"name": "To Delete"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var created tenantResponse
	json.NewDecoder(w.Body).Decode(&created)

	// Delete the tenant
	req = httptest.NewRequest("DELETE", "/api/tenants/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", w.Code)
	}

	// Verify it's gone
	req = httptest.NewRequest("GET", "/api/tenants/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404 after delete, got %d", w.Code)
	}
}

// TestTenantDelete_NotFound tests deleting a non-existent tenant.
func TestTenantDelete_NotFound(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("DELETE", "/api/tenants/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

// TestTenantDPUAssignment tests DPU assignment to tenants via API.
func TestTenantDPUAssignment(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant
	tenantBody := `{"name": "Test Tenant"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(tenantBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var tenant tenantResponse
	json.NewDecoder(w.Body).Decode(&tenant)

	// Add a DPU directly to the store (simulating existing DPU)
	server.store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)

	// Assign DPU to tenant
	assignBody := `{"dpuId": "dpu1"}`
	req = httptest.NewRequest("POST", "/api/tenants/"+tenant.ID+"/dpus", bytes.NewBufferString(assignBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// List DPUs for tenant
	req = httptest.NewRequest("GET", "/api/tenants/"+tenant.ID+"/dpus", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var dpus []dpuResponse
	if err := json.NewDecoder(w.Body).Decode(&dpus); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(dpus) != 1 {
		t.Errorf("expected 1 DPU, got %d", len(dpus))
	}

	// Unassign DPU
	req = httptest.NewRequest("DELETE", "/api/tenants/"+tenant.ID+"/dpus/dpu1", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify DPU is unassigned
	req = httptest.NewRequest("GET", "/api/tenants/"+tenant.ID+"/dpus", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&dpus)
	if len(dpus) != 0 {
		t.Errorf("expected 0 DPUs after unassign, got %d", len(dpus))
	}
}

// TestTenantDelete_WithDPUs tests that deleting a tenant with assigned DPUs fails.
func TestTenantDelete_WithDPUs(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant
	tenantBody := `{"name": "Tenant With DPU"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(tenantBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var tenant tenantResponse
	json.NewDecoder(w.Body).Decode(&tenant)

	// Add and assign a DPU
	server.store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)
	server.store.AssignDPUToTenant("dpu1", tenant.ID)

	// Try to delete tenant
	req = httptest.NewRequest("DELETE", "/api/tenants/"+tenant.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTenantListWithDPUCount tests that tenant list includes DPU counts.
func TestTenantListWithDPUCount(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant
	tenantBody := `{"name": "Tenant With DPUs"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(tenantBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var tenant tenantResponse
	json.NewDecoder(w.Body).Decode(&tenant)

	// Add and assign DPUs
	server.store.Add("dpu1", "bf3-1", "192.168.1.100", 50051)
	server.store.Add("dpu2", "bf3-2", "192.168.1.101", 50051)
	server.store.AssignDPUToTenant("dpu1", tenant.ID)
	server.store.AssignDPUToTenant("dpu2", tenant.ID)

	// List tenants
	req = httptest.NewRequest("GET", "/api/tenants", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var tenants []tenantResponse
	json.NewDecoder(w.Body).Decode(&tenants)

	if len(tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(tenants))
	}

	if tenants[0].DPUCount != 2 {
		t.Errorf("expected DPUCount 2, got %d", tenants[0].DPUCount)
	}
}
