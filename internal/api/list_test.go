package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// addTestAuth adds DPoP identity to a request for testing.
func addTestAuth(req *http.Request, operatorID, email, kid string) *http.Request {
	identity := &dpop.Identity{
		OperatorID: operatorID,
		KID:        kid,
	}
	ctx := dpop.ContextWithIdentity(req.Context(), identity)
	return req.WithContext(ctx)
}

// TestListOperatorsStatusFilter tests the status filter for listing operators.
func TestListOperatorsStatusFilter(t *testing.T) {
	// Setup test store
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer st.Close()

	// Create test tenant
	err = st.AddTenant("tenant_test", "test-tenant", "Test tenant", "test@example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create tenant: %v", err)
	}

	// Create operators with different statuses
	err = st.CreateOperator("op_active", "active@example.com", "Active User")
	if err != nil {
		t.Fatalf("Failed to create active operator: %v", err)
	}
	st.UpdateOperatorStatus("op_active", "active")
	st.AddOperatorToTenant("op_active", "tenant_test", "super:admin")

	err = st.CreateOperator("op_suspended", "suspended@example.com", "Suspended User")
	if err != nil {
		t.Fatalf("Failed to create suspended operator: %v", err)
	}
	st.SuspendOperator("op_suspended", "admin", "test suspension")
	st.AddOperatorToTenant("op_suspended", "tenant_test", "operator")

	t.Log("Testing ListOperatorsFiltered with status=active")

	// Test filter by status=active
	opts := store.ListOptions{Status: "active"}
	operators, total, err := st.ListOperatorsFiltered(opts)
	if err != nil {
		t.Fatalf("ListOperatorsFiltered failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 active operator, got %d", total)
	}
	if len(operators) != 1 || operators[0].Email != "active@example.com" {
		t.Errorf("Expected active@example.com, got %v", operators)
	}

	t.Log("Testing ListOperatorsFiltered with status=suspended")

	// Test filter by status=suspended
	opts = store.ListOptions{Status: "suspended"}
	operators, total, err = st.ListOperatorsFiltered(opts)
	if err != nil {
		t.Fatalf("ListOperatorsFiltered failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 suspended operator, got %d", total)
	}
	if len(operators) != 1 || operators[0].Status != "suspended" {
		t.Errorf("Expected suspended operator, got %v", operators)
	}
	if operators[0].SuspendedReason == nil || *operators[0].SuspendedReason != "test suspension" {
		t.Errorf("Expected suspension reason 'test suspension', got %v", operators[0].SuspendedReason)
	}
}

// TestListOperatorsTenantIsolation tests that tenant filtering works correctly.
func TestListOperatorsTenantIsolation(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer st.Close()

	// Create two tenants
	st.AddTenant("tenant_a", "tenant-a", "", "", nil)
	st.AddTenant("tenant_b", "tenant-b", "", "", nil)

	// Create operators in different tenants
	st.CreateOperator("op_a", "a@example.com", "User A")
	st.AddOperatorToTenant("op_a", "tenant_a", "operator")
	st.UpdateOperatorStatus("op_a", "active")

	st.CreateOperator("op_b", "b@example.com", "User B")
	st.AddOperatorToTenant("op_b", "tenant_b", "operator")
	st.UpdateOperatorStatus("op_b", "active")

	t.Log("Testing tenant isolation - should only see operators in tenant_a")

	// Filter by tenant_a
	opts := store.ListOptions{TenantID: "tenant_a"}
	operators, total, err := st.ListOperatorsFiltered(opts)
	if err != nil {
		t.Fatalf("ListOperatorsFiltered failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 operator in tenant_a, got %d", total)
	}
	if len(operators) != 1 || operators[0].Email != "a@example.com" {
		t.Errorf("Expected a@example.com, got %v", operators)
	}
}

// TestListOperatorsPagination tests pagination for listing operators.
func TestListOperatorsPagination(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer st.Close()

	// Create 5 operators
	for i := 0; i < 5; i++ {
		id := "op_" + string(rune('a'+i))
		email := string(rune('a'+i)) + "@example.com"
		st.CreateOperator(id, email, "User")
		st.UpdateOperatorStatus(id, "active")
	}

	t.Log("Testing pagination: limit=2, offset=0")

	// First page
	opts := store.ListOptions{Limit: 2, Offset: 0}
	operators, total, err := st.ListOperatorsFiltered(opts)
	if err != nil {
		t.Fatalf("ListOperatorsFiltered failed: %v", err)
	}

	if total != 5 {
		t.Errorf("Expected total=5, got %d", total)
	}
	if len(operators) != 2 {
		t.Errorf("Expected 2 operators on first page, got %d", len(operators))
	}

	t.Log("Testing pagination: limit=2, offset=2")

	// Second page
	opts = store.ListOptions{Limit: 2, Offset: 2}
	operators, _, err = st.ListOperatorsFiltered(opts)
	if err != nil {
		t.Fatalf("ListOperatorsFiltered failed: %v", err)
	}

	if len(operators) != 2 {
		t.Errorf("Expected 2 operators on second page, got %d", len(operators))
	}

	t.Log("Testing pagination: limit=2, offset=4")

	// Third page (partial)
	opts = store.ListOptions{Limit: 2, Offset: 4}
	operators, _, err = st.ListOperatorsFiltered(opts)
	if err != nil {
		t.Fatalf("ListOperatorsFiltered failed: %v", err)
	}

	if len(operators) != 1 {
		t.Errorf("Expected 1 operator on third page, got %d", len(operators))
	}
}

// TestListKeyMakersStatusFilter tests the status filter for listing keymakers.
func TestListKeyMakersStatusFilter(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer st.Close()

	// Create operator
	st.CreateOperator("op_test", "test@example.com", "Test User")
	st.UpdateOperatorStatus("op_test", "active")

	// Create active keymaker
	activeKM := &store.KeyMaker{
		ID:                "km_active",
		OperatorID:        "op_test",
		Name:              "Active KM",
		Platform:          "darwin",
		SecureElement:     "secure_enclave",
		DeviceFingerprint: "fp_active",
		PublicKey:         "pubkey_active",
		Status:            "active",
		Kid:               "kid_active",
		KeyFingerprint:    "kfp_active",
	}
	if err := st.CreateKeyMaker(activeKM); err != nil {
		t.Fatalf("Failed to create active keymaker: %v", err)
	}

	// Create revoked keymaker
	revokedKM := &store.KeyMaker{
		ID:                "km_revoked",
		OperatorID:        "op_test",
		Name:              "Revoked KM",
		Platform:          "linux",
		SecureElement:     "tpm",
		DeviceFingerprint: "fp_revoked",
		PublicKey:         "pubkey_revoked",
		Status:            "active",
		Kid:               "kid_revoked",
		KeyFingerprint:    "kfp_revoked",
	}
	if err := st.CreateKeyMaker(revokedKM); err != nil {
		t.Fatalf("Failed to create revoked keymaker: %v", err)
	}
	if err := st.RevokeKeyMakerWithReason("km_revoked", "admin", "test revocation"); err != nil {
		t.Fatalf("Failed to revoke keymaker: %v", err)
	}

	t.Log("Testing ListKeyMakersFiltered with status=active")

	opts := store.ListOptions{Status: "active"}
	keymakers, total, err := st.ListKeyMakersFiltered(opts)
	if err != nil {
		t.Fatalf("ListKeyMakersFiltered failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 active keymaker, got %d", total)
	}
	if len(keymakers) != 1 || keymakers[0].ID != "km_active" {
		t.Errorf("Expected km_active, got %v", keymakers)
	}

	t.Log("Testing ListKeyMakersFiltered with status=revoked")

	opts = store.ListOptions{Status: "revoked"}
	keymakers, total, err = st.ListKeyMakersFiltered(opts)
	if err != nil {
		t.Fatalf("ListKeyMakersFiltered failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 revoked keymaker, got %d", total)
	}
	if len(keymakers) != 1 || keymakers[0].Status != "revoked" {
		t.Errorf("Expected revoked keymaker, got %v", keymakers)
	}
	if keymakers[0].RevokedReason == nil || *keymakers[0].RevokedReason != "test revocation" {
		t.Errorf("Expected revocation reason 'test revocation', got %v", keymakers[0].RevokedReason)
	}
}

// TestListDPUsStatusFilter tests the status filter for listing DPUs.
func TestListDPUsStatusFilter(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer st.Close()

	// Create DPUs with different statuses
	st.Add("dpu_active", "active-dpu", "10.0.0.1", 18051)
	st.UpdateStatus("dpu_active", "active")

	st.Add("dpu_decom", "decommissioned-dpu", "10.0.0.2", 18051)
	st.DecommissionDPU("dpu_decom", "admin", "end of life")

	st.Add("dpu_pending", "pending-dpu", "10.0.0.3", 18051)
	st.SetDPUEnrollmentPending("dpu_pending", time.Now().Add(24*time.Hour))

	t.Log("Testing ListDPUsFiltered with status=active")

	opts := store.ListOptions{Status: "active"}
	dpus, total, err := st.ListDPUsFiltered(opts)
	if err != nil {
		t.Fatalf("ListDPUsFiltered failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 active DPU, got %d", total)
	}
	if len(dpus) != 1 || dpus[0].Name != "active-dpu" {
		t.Errorf("Expected active-dpu, got %v", dpus)
	}

	t.Log("Testing ListDPUsFiltered with status=decommissioned")

	opts = store.ListOptions{Status: "decommissioned"}
	dpus, total, err = st.ListDPUsFiltered(opts)
	if err != nil {
		t.Fatalf("ListDPUsFiltered failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 decommissioned DPU, got %d", total)
	}
	if len(dpus) != 1 || dpus[0].Status != "decommissioned" {
		t.Errorf("Expected decommissioned DPU, got %v", dpus)
	}
	if dpus[0].DecommissionedReason == nil || *dpus[0].DecommissionedReason != "end of life" {
		t.Errorf("Expected decommission reason 'end of life', got %v", dpus[0].DecommissionedReason)
	}
}

// TestListDPUsTenantIsolation tests tenant filtering for DPUs.
func TestListDPUsTenantIsolation(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer st.Close()

	// Create tenants
	st.AddTenant("tenant_a", "tenant-a", "", "", nil)
	st.AddTenant("tenant_b", "tenant-b", "", "", nil)

	// Create DPUs in different tenants
	st.Add("dpu_a", "dpu-a", "10.0.0.1", 18051)
	st.AssignDPUToTenant("dpu_a", "tenant_a")

	st.Add("dpu_b", "dpu-b", "10.0.0.2", 18051)
	st.AssignDPUToTenant("dpu_b", "tenant_b")

	t.Log("Testing tenant isolation - should only see DPUs in tenant_a")

	opts := store.ListOptions{TenantID: "tenant_a"}
	dpus, total, err := st.ListDPUsFiltered(opts)
	if err != nil {
		t.Fatalf("ListDPUsFiltered failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected 1 DPU in tenant_a, got %d", total)
	}
	if len(dpus) != 1 || dpus[0].Name != "dpu-a" {
		t.Errorf("Expected dpu-a, got %v", dpus)
	}
}

// TestListEndpointInvalidStatus tests that invalid status values return 400.
func TestListEndpointInvalidStatus(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer st.Close()

	server := NewServer(st)

	// Create admin user
	st.AddTenant("tenant_test", "test", "", "", nil)
	st.CreateOperator("op_admin", "admin@test.com", "Admin")
	st.UpdateOperatorStatus("op_admin", "active")
	st.AddOperatorToTenant("op_admin", "tenant_test", "super:admin")

	// Create test request with invalid status
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operators?status=invalid", nil)
	req = addTestAuth(req, "op_admin", "admin@test.com", "adm_test")
	rr := httptest.NewRecorder()

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Error("Expected error message in response")
	}
	t.Logf("Got expected error: %s", resp["error"])
}

// TestListEndpointNegativePagination tests that negative pagination values return 400.
func TestListEndpointNegativePagination(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer st.Close()

	server := NewServer(st)

	// Create admin user
	st.AddTenant("tenant_test", "test", "", "", nil)
	st.CreateOperator("op_admin", "admin@test.com", "Admin")
	st.UpdateOperatorStatus("op_admin", "active")
	st.AddOperatorToTenant("op_admin", "tenant_test", "super:admin")

	tests := []struct {
		name  string
		query string
	}{
		{"negative limit", "/api/v1/operators?limit=-1"},
		{"negative offset", "/api/v1/operators?offset=-1"},
		{"invalid limit", "/api/v1/operators?limit=abc"},
		{"invalid offset", "/api/v1/operators?offset=xyz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.query, nil)
			req = addTestAuth(req, "op_admin", "admin@test.com", "adm_test")
			rr := httptest.NewRecorder()

			mux := http.NewServeMux()
			server.RegisterRoutes(mux)
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", rr.Code)
			}
			t.Logf("Got expected 400 response for %s", tt.name)
		})
	}
}
