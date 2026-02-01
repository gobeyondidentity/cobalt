package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/internal/version"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
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

// TestHealthEndpoint tests the /health endpoint at root level.
func TestHealthEndpoint(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%v'", result["status"])
	}
	if result["version"] != version.Version {
		t.Errorf("expected version '%s', got '%v'", version.Version, result["version"])
	}
}

// TestAPIHealthEndpoint tests the /api/health endpoint returns same response as /health.
func TestAPIHealthEndpoint(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%v'", result["status"])
	}
	if result["version"] != version.Version {
		t.Errorf("expected version '%s', got '%v'", version.Version, result["version"])
	}
}

// TestHealthEndpoint_BootstrapStatusClosed tests health returns bootstrap_status "closed" when no bootstrap window.
func TestHealthEndpoint_BootstrapStatusClosed(t *testing.T) {
	t.Log("Testing /health returns bootstrap_status='closed' when no bootstrap window exists")

	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying bootstrap_status is 'closed'")
	if result["bootstrap_status"] != "closed" {
		t.Errorf("expected bootstrap_status 'closed', got '%v'", result["bootstrap_status"])
	}

	t.Log("Verifying bootstrap_expires_at is NOT present")
	if _, ok := result["bootstrap_expires_at"]; ok {
		t.Error("expected bootstrap_expires_at to NOT be present when closed")
	}

	t.Log("Verifying bootstrap_admin_id is NOT present")
	if _, ok := result["bootstrap_admin_id"]; ok {
		t.Error("expected bootstrap_admin_id to NOT be present when closed")
	}
}

// TestHealthEndpoint_BootstrapStatusOpen tests health returns bootstrap_status "open" with expiration time.
func TestHealthEndpoint_BootstrapStatusOpen(t *testing.T) {
	t.Log("Testing /health returns bootstrap_status='open' with expires_at when window is active")

	server, mux := setupTestServer(t)

	// Initialize bootstrap window
	t.Log("Initializing bootstrap window")
	if err := server.store.InitBootstrapWindow(); err != nil {
		t.Fatalf("failed to init bootstrap window: %v", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying bootstrap_status is 'open'")
	if result["bootstrap_status"] != "open" {
		t.Errorf("expected bootstrap_status 'open', got '%v'", result["bootstrap_status"])
	}

	t.Log("Verifying bootstrap_expires_at is present and valid RFC3339")
	expiresAt, ok := result["bootstrap_expires_at"].(string)
	if !ok {
		t.Fatal("expected bootstrap_expires_at to be a string")
	}
	if expiresAt == "" {
		t.Error("expected bootstrap_expires_at to be non-empty")
	}
	// Verify it parses as RFC3339
	parsedTime, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Errorf("expected bootstrap_expires_at to be RFC3339 format, got error: %v", err)
	}
	// Should be about 10 minutes from now
	untilExpiry := time.Until(parsedTime)
	if untilExpiry < 9*time.Minute || untilExpiry > 11*time.Minute {
		t.Errorf("expected bootstrap_expires_at to be ~10 minutes from now, got %v", untilExpiry)
	}

	t.Log("Verifying bootstrap_admin_id is NOT present when open")
	if _, ok := result["bootstrap_admin_id"]; ok {
		t.Error("expected bootstrap_admin_id to NOT be present when status is 'open'")
	}
}

// TestHealthEndpoint_BootstrapStatusEnrolled tests health returns bootstrap_status "enrolled" with admin ID.
func TestHealthEndpoint_BootstrapStatusEnrolled(t *testing.T) {
	t.Log("Testing /health returns bootstrap_status='enrolled' with admin_id when admin exists")

	server, mux := setupTestServer(t)

	// Initialize bootstrap window and complete enrollment
	t.Log("Completing bootstrap enrollment")
	server.store.InitBootstrapWindow()
	if err := server.store.CompleteBootstrap("adm_test456"); err != nil {
		t.Fatalf("failed to complete bootstrap: %v", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying bootstrap_status is 'enrolled'")
	if result["bootstrap_status"] != "enrolled" {
		t.Errorf("expected bootstrap_status 'enrolled', got '%v'", result["bootstrap_status"])
	}

	t.Log("Verifying bootstrap_admin_id is present and correct")
	adminID, ok := result["bootstrap_admin_id"].(string)
	if !ok {
		t.Fatal("expected bootstrap_admin_id to be a string")
	}
	if adminID != "adm_test456" {
		t.Errorf("expected bootstrap_admin_id 'adm_test456', got '%s'", adminID)
	}

	t.Log("Verifying bootstrap_expires_at is NOT present when enrolled")
	if _, ok := result["bootstrap_expires_at"]; ok {
		t.Error("expected bootstrap_expires_at to NOT be present when status is 'enrolled'")
	}
}

// TestHealthEndpoint_BootstrapStatusExpired tests health returns "closed" when window expired.
func TestHealthEndpoint_BootstrapStatusExpired(t *testing.T) {
	t.Log("Testing /health returns bootstrap_status='closed' when window has expired")

	server, mux := setupTestServer(t)

	// Initialize bootstrap window and manually expire it
	t.Log("Creating expired bootstrap window")
	server.store.InitBootstrapWindow()
	expiredTime := time.Now().Add(-11 * time.Minute).Unix()
	_, err := server.store.DB().Exec(`UPDATE bootstrap_state SET window_opened_at = ? WHERE id = 1`, expiredTime)
	if err != nil {
		t.Fatalf("failed to expire window: %v", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Log("Verifying bootstrap_status is 'closed' for expired window")
	if result["bootstrap_status"] != "closed" {
		t.Errorf("expected bootstrap_status 'closed', got '%v'", result["bootstrap_status"])
	}

	t.Log("Verifying bootstrap_expires_at is NOT present when closed")
	if _, ok := result["bootstrap_expires_at"]; ok {
		t.Error("expected bootstrap_expires_at to NOT be present when closed")
	}
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

// TestTenantDelete_WithInvites tests that deleting a tenant with pending invites fails.
func TestTenantDelete_WithInvites(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create a tenant
	tenantBody := `{"name": "Tenant With Invites"}`
	req := httptest.NewRequest("POST", "/api/tenants", bytes.NewBufferString(tenantBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var tenant tenantResponse
	json.NewDecoder(w.Body).Decode(&tenant)

	// Create a pending invite for the tenant
	invite := &store.InviteCode{
		ID:            "inv_test",
		CodeHash:      "testhash123",
		OperatorEmail: "newuser@example.com",
		TenantID:      tenant.ID,
		Role:          "operator",
		CreatedBy:     "admin@example.com",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Status:        "pending",
	}
	if err := server.store.CreateInviteCode(invite); err != nil {
		t.Fatalf("failed to create invite: %v", err)
	}

	// Try to delete tenant
	req = httptest.NewRequest("DELETE", "/api/tenants/"+tenant.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409, got %d: %s", w.Code, w.Body.String())
	}

	// Verify error message mentions invites
	body := w.Body.String()
	if !strings.Contains(body, "invites") {
		t.Errorf("expected error to mention invites, got: %s", body)
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

// ----- Host Scan Endpoint Tests -----

// TestHostScan_Success tests the host scan endpoint returns correct structure.
func TestHostScan_Success(t *testing.T) {
	server, mux := setupTestServer(t)

	// Setup: Add a DPU and register a host
	server.store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)

	host := &store.AgentHost{
		DPUName:  "bf3-test",
		DPUID:    "dpu1",
		Hostname: "gpu-node-01",
		TenantID: "",
	}
	server.store.RegisterAgentHost(host)

	// Call the scan endpoint
	req := httptest.NewRequest("POST", "/api/v1/hosts/gpu-node-01/scan", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result hostScanResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify response structure
	if result.Host != "gpu-node-01" {
		t.Errorf("expected host 'gpu-node-01', got '%s'", result.Host)
	}
	if result.Method != "agent" {
		t.Errorf("expected method 'agent', got '%s'", result.Method)
	}
	if result.Keys == nil {
		t.Error("expected keys array to be present (not nil)")
	}
	if result.ScannedAt == "" {
		t.Error("expected scanned_at to be set")
	}
}

// TestHostScan_NotFound tests scan endpoint returns 404 for unknown host.
func TestHostScan_NotFound(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("POST", "/api/v1/hosts/nonexistent-host/scan", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)

	if result["error"] == "" {
		t.Error("expected error message in response")
	}
}

// TestListAgentHosts_EmptyReturnsWrappedFormat tests that empty hosts list returns {"hosts": []} not [].
func TestListAgentHosts_EmptyReturnsWrappedFormat(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Parse as raw JSON to verify structure
	var rawResult map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&rawResult); err != nil {
		t.Fatalf("expected JSON object with 'hosts' key, got error: %v (body: %s)", err, w.Body.String())
	}

	// Verify "hosts" key exists
	hosts, ok := rawResult["hosts"]
	if !ok {
		t.Fatalf("expected 'hosts' key in response, got: %v", rawResult)
	}

	// Verify hosts is an array
	hostsArray, ok := hosts.([]interface{})
	if !ok {
		t.Fatalf("expected 'hosts' to be an array, got: %T", hosts)
	}

	// Verify it's empty
	if len(hostsArray) != 0 {
		t.Errorf("expected empty hosts array, got %d items", len(hostsArray))
	}
}

// TestListAgentHosts_WithHostsReturnsWrappedFormat tests that hosts list returns {"hosts": [...]} format.
func TestListAgentHosts_WithHostsReturnsWrappedFormat(t *testing.T) {
	server, mux := setupTestServer(t)

	// Setup: Add a DPU and register a host
	server.store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)

	host := &store.AgentHost{
		DPUName:  "bf3-test",
		DPUID:    "dpu1",
		Hostname: "test-host",
		TenantID: "",
	}
	server.store.RegisterAgentHost(host)

	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Parse as raw JSON to verify structure
	var rawResult map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&rawResult); err != nil {
		t.Fatalf("expected JSON object with 'hosts' key, got error: %v", err)
	}

	// Verify "hosts" key exists
	hosts, ok := rawResult["hosts"]
	if !ok {
		t.Fatalf("expected 'hosts' key in response, got: %v", rawResult)
	}

	// Verify hosts is an array with one item
	hostsArray, ok := hosts.([]interface{})
	if !ok {
		t.Fatalf("expected 'hosts' to be an array, got: %T", hosts)
	}

	if len(hostsArray) != 1 {
		t.Errorf("expected 1 host, got %d", len(hostsArray))
	}
}

// TestHostScan_ResponseFormat tests the scan response has all expected fields.
func TestHostScan_ResponseFormat(t *testing.T) {
	server, mux := setupTestServer(t)

	// Setup: Add a DPU and register a host
	server.store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)

	host := &store.AgentHost{
		DPUName:  "bf3-test",
		DPUID:    "dpu1",
		Hostname: "test-host",
		TenantID: "",
	}
	server.store.RegisterAgentHost(host)

	// Call the scan endpoint
	req := httptest.NewRequest("POST", "/api/v1/hosts/test-host/scan", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Parse as raw JSON to verify field names
	var rawResult map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&rawResult); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify all required fields are present
	expectedFields := []string{"host", "method", "keys", "scanned_at"}
	for _, field := range expectedFields {
		if _, ok := rawResult[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Verify keys is an array
	keys, ok := rawResult["keys"].([]interface{})
	if !ok {
		t.Error("keys field should be an array")
	}
	if keys == nil {
		t.Error("keys array should not be nil")
	}
}

// ----- Host Posture by DPU Endpoint Tests -----

// TestGetHostPostureByDPU_UnknownDPU tests 404 for unknown DPU name.
func TestGetHostPostureByDPU_UnknownDPU(t *testing.T) {
	t.Log("Testing GET /api/v1/hosts/{dpu-name}/posture returns 404 for unknown DPU")

	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/hosts/nonexistent-dpu/posture", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)

	if !strings.Contains(result["error"], "Host not found for DPU") {
		t.Errorf("expected error to mention 'Host not found for DPU', got: %s", result["error"])
	}
}

// TestGetHostPostureByDPU_NoPosture tests 404 when host exists but has no posture data.
func TestGetHostPostureByDPU_NoPosture(t *testing.T) {
	t.Log("Testing GET /api/v1/hosts/{dpu-name}/posture returns 404 when host has no posture")

	server, mux := setupTestServer(t)

	// Setup: Add a DPU and register a host without posture
	t.Log("Creating DPU and registering host without posture data")
	server.store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)

	host := &store.AgentHost{
		DPUName:  "bf3-test",
		DPUID:    "dpu1",
		Hostname: "gpu-node-01",
		TenantID: "",
	}
	server.store.RegisterAgentHost(host)

	t.Log("Calling GET /api/v1/hosts/bf3-test/posture")
	req := httptest.NewRequest("GET", "/api/v1/hosts/bf3-test/posture", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)

	if !strings.Contains(result["error"], "No posture data available") {
		t.Errorf("expected error to mention 'No posture data available', got: %s", result["error"])
	}
}

// TestGetHostPostureByDPU_Success tests successful posture retrieval.
func TestGetHostPostureByDPU_Success(t *testing.T) {
	t.Log("Testing GET /api/v1/hosts/{dpu-name}/posture returns posture data")

	server, mux := setupTestServer(t)

	// Setup: Add a DPU and register a host with posture
	t.Log("Creating DPU and registering host")
	server.store.Add("dpu1", "bf3-test", "192.168.1.100", 50051)

	host := &store.AgentHost{
		DPUName:  "bf3-test",
		DPUID:    "dpu1",
		Hostname: "gpu-node-01",
		TenantID: "",
	}
	server.store.RegisterAgentHost(host)

	// Add posture data
	t.Log("Adding posture data for host")
	secureBoot := true
	tpmPresent := true
	posture := &store.AgentHostPosture{
		HostID:         host.ID,
		SecureBoot:     &secureBoot,
		DiskEncryption: "luks",
		OSVersion:      "Ubuntu 22.04",
		KernelVersion:  "5.15.0-generic",
		TPMPresent:     &tpmPresent,
		PostureHash:    "abc123",
	}
	server.store.UpdateAgentHostPosture(posture)

	t.Log("Calling GET /api/v1/hosts/bf3-test/posture")
	req := httptest.NewRequest("GET", "/api/v1/hosts/bf3-test/posture", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	t.Log("Verifying posture response fields")
	var result agentPostureResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify posture fields
	if result.SecureBoot == nil || *result.SecureBoot != true {
		t.Error("expected secure_boot to be true")
	}
	if result.DiskEncryption != "luks" {
		t.Errorf("expected disk_encryption 'luks', got '%s'", result.DiskEncryption)
	}
	if result.OSVersion != "Ubuntu 22.04" {
		t.Errorf("expected os_version 'Ubuntu 22.04', got '%s'", result.OSVersion)
	}
	if result.KernelVersion != "5.15.0-generic" {
		t.Errorf("expected kernel_version '5.15.0-generic', got '%s'", result.KernelVersion)
	}
	if result.TPMPresent == nil || *result.TPMPresent != true {
		t.Error("expected tpm_present to be true")
	}
	if result.PostureHash != "abc123" {
		t.Errorf("expected posture_hash 'abc123', got '%s'", result.PostureHash)
	}
	if result.CollectedAt == "" {
		t.Error("expected collected_at to be set")
	}
}
