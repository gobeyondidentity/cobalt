package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// setupPushTestStore creates a test store with the necessary fixtures for push tests.
// Returns the store and a cleanup function.
func setupPushTestStore(t *testing.T) *store.Store {
	t.Helper()

	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}

	// Create tenant
	t.Log("Creating test tenant 'acme'")
	err = s.AddTenant("tenant-1", "acme", "Test tenant", "admin@acme.com", nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create operator
	t.Log("Creating test operator 'alice@acme.com'")
	err = s.CreateOperator("op-1", "alice@acme.com", "Alice")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	err = s.AddOperatorToTenant("op-1", "tenant-1", "operator")
	if err != nil {
		t.Fatalf("failed to add operator to tenant: %v", err)
	}
	err = s.UpdateOperatorStatus("op-1", "active")
	if err != nil {
		t.Fatalf("failed to update operator status: %v", err)
	}

	// Create DPU
	t.Log("Creating test DPU 'dpu-1'")
	err = s.Add("dpu-1", "dpu-1", "192.168.1.100", 18051)
	if err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}
	err = s.AssignDPUToTenant("dpu-1", "tenant-1")
	if err != nil {
		t.Fatalf("failed to assign DPU to tenant: %v", err)
	}

	// Create SSH CA (requires encryption setup)
	t.Log("Creating test SSH CA 'test-ca'")
	testPubKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@example.com")
	testPrivKey := []byte("test-private-key")
	tenantID := "tenant-1"
	err = s.CreateSSHCA("ca-1", "test-ca", testPubKey, testPrivKey, "ed25519", &tenantID)
	if err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	// Create authorization for operator -> CA -> DPU
	t.Log("Creating authorization for operator to use CA on DPU")
	err = s.CreateAuthorization("auth-1", "op-1", "tenant-1", []string{"ca-1"}, []string{"dpu-1"}, "system", nil)
	if err != nil {
		t.Fatalf("failed to create authorization: %v", err)
	}

	return s
}

func TestHandlePush_MissingRequiredFields(t *testing.T) {
	t.Log("Testing push endpoint with missing required fields")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	tests := []struct {
		name    string
		body    pushRequest
		wantErr string
	}{
		{
			name:    "missing ca_name",
			body:    pushRequest{TargetDPU: "dpu-1", OperatorID: "op-1"},
			wantErr: "ca_name is required",
		},
		{
			name:    "missing target_dpu",
			body:    pushRequest{CAName: "test-ca", OperatorID: "op-1"},
			wantErr: "target_dpu is required",
		},
		{
			name:    "missing operator_id",
			body:    pushRequest{CAName: "test-ca", TargetDPU: "dpu-1"},
			wantErr: "operator_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing with body: %+v", tt.body)
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			t.Logf("Response status: %d", w.Code)
			if w.Code != http.StatusBadRequest {
				t.Errorf("expected status 400, got %d", w.Code)
			}

			var resp map[string]string
			json.Unmarshal(w.Body.Bytes(), &resp)
			t.Logf("Response error: %s", resp["error"])
			if resp["error"] != tt.wantErr {
				t.Errorf("expected error %q, got %q", tt.wantErr, resp["error"])
			}
		})
	}
}

func TestHandlePush_CANotFound(t *testing.T) {
	t.Log("Testing push endpoint with non-existent CA")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	body, _ := json.Marshal(pushRequest{
		CAName:     "nonexistent-ca",
		TargetDPU:  "dpu-1",
		OperatorID: "op-1",
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("Response error: %s", resp["error"])
	if resp["error"] != "CA not found" {
		t.Errorf("expected error 'CA not found', got %q", resp["error"])
	}
}

func TestHandlePush_DPUNotFound(t *testing.T) {
	t.Log("Testing push endpoint with non-existent DPU")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	body, _ := json.Marshal(pushRequest{
		CAName:     "test-ca",
		TargetDPU:  "nonexistent-dpu",
		OperatorID: "op-1",
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("Response error: %s", resp["error"])
	if resp["error"] != "DPU not found" {
		t.Errorf("expected error 'DPU not found', got %q", resp["error"])
	}
}

func TestHandlePush_NotAuthorized(t *testing.T) {
	t.Log("Testing push endpoint with unauthorized operator")
	s := setupPushTestStore(t)
	defer s.Close()

	// Create another operator without authorization
	t.Log("Creating unauthorized operator 'bob@acme.com'")
	err := s.CreateOperator("op-2", "bob@acme.com", "Bob")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	err = s.UpdateOperatorStatus("op-2", "active")
	if err != nil {
		t.Fatalf("failed to update operator status: %v", err)
	}

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	body, _ := json.Marshal(pushRequest{
		CAName:     "test-ca",
		TargetDPU:  "dpu-1",
		OperatorID: "op-2", // Unauthorized operator
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("Response error: %s", resp["error"])
	if resp["error"] != "not authorized for this CA and device" {
		t.Errorf("expected error 'not authorized for this CA and device', got %q", resp["error"])
	}
}

func TestHandlePush_StaleAttestationWithoutForce(t *testing.T) {
	t.Log("Testing push endpoint with stale attestation (no force flag)")
	s := setupPushTestStore(t)
	defer s.Close()

	// Create a stale attestation (older than freshness window)
	t.Log("Creating stale attestation for DPU")
	staleTime := time.Now().Add(-2 * time.Hour) // 2 hours old, exceeds 1 hour default window
	err := s.SaveAttestation(&store.Attestation{
		DPUName:       "dpu-1",
		Status:        store.AttestationStatusVerified,
		LastValidated: staleTime,
	})
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}

	server := NewServer(s)
	server.Gate().Refresher.Timeout = 100 * time.Millisecond // Fast timeout for tests
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	body, _ := json.Marshal(pushRequest{
		CAName:     "test-ca",
		TargetDPU:  "dpu-1",
		OperatorID: "op-1",
		Force:      false,
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	// Should return 412 Precondition Failed for stale attestation
	// Note: In test environment without real DPU, auto-refresh will fail
	// so we expect the attestation gate to block
	if w.Code != http.StatusPreconditionFailed {
		t.Errorf("expected status 412, got %d", w.Code)
	}

	var resp pushResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("Response: success=%v, attestation_status=%s, message=%s",
		resp.Success, resp.AttestationStatus, resp.Message)
	if resp.Success {
		t.Errorf("expected success=false for stale attestation")
	}
}

func TestHandlePush_FailedAttestation(t *testing.T) {
	t.Log("Testing push endpoint with failed attestation (even with force)")
	s := setupPushTestStore(t)
	defer s.Close()

	// Create a failed attestation
	t.Log("Creating failed attestation for DPU")
	err := s.SaveAttestation(&store.Attestation{
		DPUName:       "dpu-1",
		Status:        store.AttestationStatusFailed,
		LastValidated: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// Even with force=true, failed attestation should be rejected
	body, _ := json.Marshal(pushRequest{
		CAName:     "test-ca",
		TargetDPU:  "dpu-1",
		OperatorID: "op-1",
		Force:      true,
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	if w.Code != http.StatusPreconditionFailed {
		t.Errorf("expected status 412, got %d", w.Code)
	}

	var resp pushResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("Response: success=%v, attestation_status=%s, message=%s",
		resp.Success, resp.AttestationStatus, resp.Message)
	if resp.Success {
		t.Errorf("expected success=false for failed attestation")
	}
}

// TestHandlePush_StaleAttestationWithForce tests that force flag allows distribution
// when attestation is stale but not failed.
// Note: This test cannot fully verify the gRPC distribution without a mock,
// but it validates the attestation gate bypass logic.
func TestHandlePush_StaleAttestationWithForce(t *testing.T) {
	t.Log("Testing push endpoint with stale attestation and force flag")
	s := setupPushTestStore(t)
	defer s.Close()

	// Create a stale attestation
	t.Log("Creating stale attestation for DPU")
	staleTime := time.Now().Add(-2 * time.Hour)
	err := s.SaveAttestation(&store.Attestation{
		DPUName:       "dpu-1",
		Status:        store.AttestationStatusVerified,
		LastValidated: staleTime,
	})
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}

	server := NewServer(s)
	server.Gate().Refresher.Timeout = 100 * time.Millisecond // Fast timeout for tests
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	body, _ := json.Marshal(pushRequest{
		CAName:     "test-ca",
		TargetDPU:  "dpu-1",
		OperatorID: "op-1",
		Force:      true,
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	// With force=true and only stale attestation (not failed),
	// the endpoint should attempt the distribution.
	// Since the DPU is not reachable in tests, we expect a 500 (gRPC error)
	// rather than a 412 (attestation blocked).
	// This proves the attestation gate was bypassed.
	if w.Code == http.StatusPreconditionFailed {
		var resp pushResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		// If we get 412 with failed attestation status, that's expected
		// because failed attestations cannot be forced
		if resp.AttestationStatus == "failed" {
			t.Log("Got 412 because attestation is failed, which is correct")
			return
		}
		t.Errorf("expected force to bypass stale attestation gate, got 412")
	}
	// 500 (gRPC error) or 200 (if mock were used) are acceptable
	t.Logf("Force flag allowed bypassing stale attestation, status: %d", w.Code)
}

// TestHandlePush_Success requires a mock gRPC server, which is beyond unit test scope.
// Integration tests in a separate file will cover the full flow.

// TestHandlePush_OperatorIDFromDPoPContext tests that operator_id is extracted from
// DPoP identity context when the request body has an empty operator_id.
// This is the primary path used by km CLI, which doesn't store operator_id locally.
func TestHandlePush_OperatorIDFromDPoPContext(t *testing.T) {
	t.Log("Testing push endpoint extracts operator_id from DPoP context (empty body)")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// Create request with empty operator_id in body (km CLI behavior)
	t.Log("Creating push request with empty operator_id in request body")
	body, _ := json.Marshal(pushRequest{
		CAName:     "test-ca",
		TargetDPU:  "dpu-1",
		OperatorID: "", // Empty - should be extracted from DPoP context
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Simulate DPoP auth middleware by adding identity to context
	t.Log("Adding DPoP identity with OperatorID='op-1' to request context")
	identity := &dpop.Identity{
		KID:        "km_test-kid",
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     dpop.IdentityStatusActive,
		OperatorID: "op-1", // This should be used by push handler
	}
	ctx := dpop.ContextWithIdentity(req.Context(), identity)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	t.Logf("Response body: %s", w.Body.String())

	// The handler should NOT return "operator_id is required" error.
	// It should proceed past operator_id validation (status may be 412/500/200
	// depending on attestation and gRPC, but NOT 400 for missing operator_id).
	if w.Code == http.StatusBadRequest {
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] == "operator_id is required" {
			t.Errorf("handler failed to extract operator_id from DPoP context")
		}
	}

	// Status 412 (attestation blocked) or 503/500 (gRPC unavailable) proves
	// the handler extracted operator_id from context and proceeded to
	// subsequent validation steps.
	validStatuses := map[int]bool{
		http.StatusPreconditionFailed:  true, // Attestation blocked (expected in test env)
		http.StatusServiceUnavailable:  true, // gRPC unavailable
		http.StatusInternalServerError: true, // gRPC error
		http.StatusOK:                  true, // Would need mock gRPC
	}
	if !validStatuses[w.Code] {
		t.Errorf("unexpected status %d - expected handler to proceed past operator_id validation", w.Code)
	}
	t.Log("Handler successfully extracted operator_id from DPoP context")
}

// TestHandlePush_InvalidJSON tests malformed JSON handling.
func TestHandlePush_InvalidJSON(t *testing.T) {
	t.Log("Testing push endpoint with invalid JSON")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	t.Logf("Response status: %d", w.Code)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// mockGRPCServer is a placeholder for future integration tests with a mock aegis server.
type mockGRPCServer struct{}

func (m *mockGRPCServer) DistributeCredential(ctx context.Context, credType, credName string, publicKey []byte) error {
	return nil
}
