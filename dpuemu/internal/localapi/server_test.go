// Package localapi provides the HTTP REST API for host-agent communication.
package localapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/dpuemu/internal/fixture"
	agentv1 "github.com/gobeyondidentity/secure-infra/gen/go/agent/v1"
)

func TestRegister_NewHost(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	req := registerRequest{
		Hostname: "test-host-1",
		Posture: &posturePayload{
			OSVersion:     "Ubuntu 22.04",
			KernelVersion: "5.15.0",
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp registerResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.HostID == "" {
		t.Error("expected non-empty host_id")
	}
	if !strings.HasPrefix(resp.HostID, "host_") {
		t.Errorf("expected host_id to start with 'host_', got %s", resp.HostID)
	}
	if resp.DPUName == "" {
		t.Error("expected non-empty dpu_name")
	}
	if resp.RefreshInterval != "5m" {
		t.Errorf("expected refresh_interval '5m', got %s", resp.RefreshInterval)
	}
}

func TestRegister_ExistingHost(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	req := registerRequest{
		Hostname: "existing-host",
	}
	body, _ := json.Marshal(req)

	// First registration
	httpReq1 := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	httpReq1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, httpReq1)

	if w1.Code != http.StatusCreated {
		t.Fatalf("first registration failed: %d", w1.Code)
	}

	var resp1 registerResponse
	json.Unmarshal(w1.Body.Bytes(), &resp1)
	firstHostID := resp1.HostID

	// Second registration (same hostname)
	body2, _ := json.Marshal(req)
	httpReq2 := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body2))
	httpReq2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, httpReq2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected status 200 for existing host, got %d", w2.Code)
	}

	var resp2 registerResponse
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	if resp2.HostID != firstHostID {
		t.Errorf("expected same host_id %s, got %s", firstHostID, resp2.HostID)
	}
}

func TestPosture_Success(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	req := postureRequest{
		Hostname: "posture-host",
		Posture: &posturePayload{
			OSVersion:     "Ubuntu 22.04",
			KernelVersion: "5.15.0",
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/posture", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Body should be empty on success
	if w.Body.Len() != 0 {
		t.Errorf("expected empty body, got %s", w.Body.String())
	}
}

func TestCert_Success(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	req := certRequest{
		Hostname:   "cert-host",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test@host",
		Principals: []string{"cert-host"},
		KeyType:    "ed25519",
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/cert", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp certResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Certificate == "" {
		t.Error("expected non-empty certificate")
	}
	if !strings.Contains(resp.Certificate, "MOCK_CERTIFICATE_DATA") {
		t.Errorf("expected mock certificate, got %s", resp.Certificate)
	}
	if resp.ValidUntil == "" {
		t.Error("expected non-empty valid_until")
	}

	// Verify valid_until is a valid RFC3339 timestamp in the future
	validTime, err := time.Parse(time.RFC3339, resp.ValidUntil)
	if err != nil {
		t.Errorf("valid_until is not RFC3339: %v", err)
	}
	if validTime.Before(time.Now()) {
		t.Error("valid_until should be in the future")
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/register", strings.NewReader("{invalid json"))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp errorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if resp.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestPosture_InvalidJSON(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/posture", strings.NewReader("not json"))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestCert_InvalidJSON(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/cert", strings.NewReader("[]"))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestRegister_MissingHostname(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	req := registerRequest{
		Hostname: "",
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp errorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp.Error, "hostname") {
		t.Errorf("expected error about hostname, got %s", resp.Error)
	}
}

func TestUnknownEndpoint(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	httpReq := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	httpReq := httptest.NewRequest(http.MethodGet, "/local/v1/register", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestNilFixture(t *testing.T) {
	srv := New(nil, "")

	req := registerRequest{
		Hostname: "nil-fixture-host",
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp registerResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Should use default "dpuemu" when fixture is nil
	if resp.DPUName != "dpuemu" {
		t.Errorf("expected dpu_name 'dpuemu', got %s", resp.DPUName)
	}
}

func TestRegister_RelayToControlPlane(t *testing.T) {
	// Track calls to the mock control plane
	var receivedRequests []controlPlaneRegisterRequest
	var mu sync.Mutex

	// Create a mock control plane server
	mockCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/hosts/register" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req controlPlaneRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		receivedRequests = append(receivedRequests, req)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"host_id":          "cp_host_123",
			"refresh_interval": "5m",
		})
	}))
	defer mockCP.Close()

	// Create localapi server with control plane URL
	fix := &fixture.Fixture{
		SystemInfo: &agentv1.GetSystemInfoResponse{
			Hostname: "test-dpu",
		},
	}
	srv := New(fix, mockCP.URL)

	// Register a host
	req := registerRequest{
		Hostname: "relay-test-host",
		Posture: &posturePayload{
			OSVersion:     "Ubuntu 22.04",
			KernelVersion: "5.15.0",
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	// Local registration should succeed
	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	// Wait for the async relay to complete
	time.Sleep(100 * time.Millisecond)

	// Verify the control plane received the request
	mu.Lock()
	defer mu.Unlock()

	if len(receivedRequests) != 1 {
		t.Fatalf("expected 1 request to control plane, got %d", len(receivedRequests))
	}

	cpReq := receivedRequests[0]
	if cpReq.DPUName != "test-dpu" {
		t.Errorf("expected dpu_name 'test-dpu', got %s", cpReq.DPUName)
	}
	if cpReq.Hostname != "relay-test-host" {
		t.Errorf("expected hostname 'relay-test-host', got %s", cpReq.Hostname)
	}
	if cpReq.Posture == nil {
		t.Error("expected posture to be forwarded")
	} else {
		if cpReq.Posture.OSVersion != "Ubuntu 22.04" {
			t.Errorf("expected os_version 'Ubuntu 22.04', got %s", cpReq.Posture.OSVersion)
		}
	}
}

func TestRegister_RelayFailureDoesNotAffectLocal(t *testing.T) {
	// Create a mock control plane that always fails
	mockCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockCP.Close()

	fix := fixture.DefaultFixture()
	srv := New(fix, mockCP.URL)

	// Register a host
	req := registerRequest{
		Hostname: "relay-fail-host",
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	// Local registration should still succeed
	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201 despite relay failure, got %d: %s", w.Code, w.Body.String())
	}

	var resp registerResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.HostID == "" {
		t.Error("expected non-empty host_id")
	}
}

func TestRegister_NoRelayWhenControlPlaneEmpty(t *testing.T) {
	// Create localapi server without control plane URL
	fix := fixture.DefaultFixture()
	srv := New(fix, "")

	// Register a host
	req := registerRequest{
		Hostname: "no-relay-host",
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, httpReq)

	// Local registration should succeed (no panic or error from nil URL)
	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}
}
