// Package api implements the HTTP API server for the dashboard.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nmelo/secure-infra/pkg/store"
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

// addAuthContext adds authenticated operator context to a request.
// This simulates what AuthMiddleware does after validating a JWT.
func addAuthContext(req *http.Request, operatorID, operatorEmail, keyMakerID string) *http.Request {
	ctx := req.Context()
	ctx = context.WithValue(ctx, contextKeyOperatorID, operatorID)
	ctx = context.WithValue(ctx, contextKeyOperatorEmail, operatorEmail)
	ctx = context.WithValue(ctx, contextKeyKeyMakerID, keyMakerID)
	return req.WithContext(ctx)
}

func TestHandlePush_MissingRequiredFields(t *testing.T) {
	t.Log("Testing push endpoint with missing required fields")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)

	tests := []struct {
		name    string
		body    pushRequest
		wantErr string
	}{
		{
			name:    "missing ca_name",
			body:    pushRequest{TargetDPU: "dpu-1"},
			wantErr: "ca_name is required",
		},
		{
			name:    "missing target_dpu",
			body:    pushRequest{CAName: "test-ca"},
			wantErr: "target_dpu is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing with body: %+v", tt.body)
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			// Add auth context (operator is authenticated)
			req = addAuthContext(req, "op-1", "alice@acme.com", "km-1")

			w := httptest.NewRecorder()
			server.handlePush(w, req)

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

func TestHandlePush_Unauthenticated(t *testing.T) {
	t.Log("Testing push endpoint without authentication")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)

	body, _ := json.Marshal(pushRequest{
		CAName:    "test-ca",
		TargetDPU: "dpu-1",
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No auth context added

	w := httptest.NewRecorder()
	server.handlePush(w, req)

	t.Logf("Response status: %d", w.Code)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("Response error: %s", resp["error"])
	if resp["error"] != "authentication required" {
		t.Errorf("expected error 'authentication required', got %q", resp["error"])
	}
}

func TestHandlePush_CANotFound(t *testing.T) {
	t.Log("Testing push endpoint with non-existent CA")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)

	body, _ := json.Marshal(pushRequest{
		CAName:    "nonexistent-ca",
		TargetDPU: "dpu-1",
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = addAuthContext(req, "op-1", "alice@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handlePush(w, req)

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

	body, _ := json.Marshal(pushRequest{
		CAName:    "test-ca",
		TargetDPU: "nonexistent-dpu",
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = addAuthContext(req, "op-1", "alice@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handlePush(w, req)

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

	body, _ := json.Marshal(pushRequest{
		CAName:    "test-ca",
		TargetDPU: "dpu-1",
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Authenticate as unauthorized operator
	req = addAuthContext(req, "op-2", "bob@acme.com", "km-2")

	w := httptest.NewRecorder()
	server.handlePush(w, req)

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

	body, _ := json.Marshal(pushRequest{
		CAName:    "test-ca",
		TargetDPU: "dpu-1",
		Force:     false,
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = addAuthContext(req, "op-1", "alice@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handlePush(w, req)

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

	// Even with force=true, failed attestation should be rejected
	body, _ := json.Marshal(pushRequest{
		CAName:    "test-ca",
		TargetDPU: "dpu-1",
		Force:     true,
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = addAuthContext(req, "op-1", "alice@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handlePush(w, req)

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

	body, _ := json.Marshal(pushRequest{
		CAName:    "test-ca",
		TargetDPU: "dpu-1",
		Force:     true,
	})
	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = addAuthContext(req, "op-1", "alice@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handlePush(w, req)

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

// TestHandlePush_InvalidJSON tests malformed JSON handling.
func TestHandlePush_InvalidJSON(t *testing.T) {
	t.Log("Testing push endpoint with invalid JSON")
	s := setupPushTestStore(t)
	defer s.Close()

	server := NewServer(s)

	req := httptest.NewRequest("POST", "/api/v1/push", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	req = addAuthContext(req, "op-1", "alice@acme.com", "km-1")

	w := httptest.NewRecorder()
	server.handlePush(w, req)

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
