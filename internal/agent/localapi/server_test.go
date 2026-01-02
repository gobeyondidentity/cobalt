package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockControlPlane is a test server that mocks the Control Plane API.
type mockControlPlane struct {
	server *httptest.Server

	// Configurable responses
	registerResponse  *ProxiedRegisterResponse
	registerError     string
	postureError      string
	certResponse      *ProxiedCertResponse
	certError         string
	pingError         bool

	// Request tracking
	lastRegisterReq *ProxiedRegisterRequest
	lastPostureReq  *ProxiedPostureRequest
	lastCertReq     *ProxiedCertRequest
}

func newMockControlPlane() *mockControlPlane {
	m := &mockControlPlane{}
	m.server = httptest.NewServer(http.HandlerFunc(m.handler))
	return m
}

func (m *mockControlPlane) handler(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/v1/health" && r.Method == http.MethodGet:
		if m.pingError {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)

	case r.URL.Path == "/api/v1/hosts/register" && r.Method == http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &m.lastRegisterReq)

		if m.registerError != "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: m.registerError})
			return
		}

		resp := m.registerResponse
		if resp == nil {
			resp = &ProxiedRegisterResponse{HostID: "host_12345678"}
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)

	case r.Method == http.MethodPost && len(r.URL.Path) > 15 && r.URL.Path[len(r.URL.Path)-8:] == "/posture":
		body, _ := io.ReadAll(r.Body)
		var posture PosturePayload
		json.Unmarshal(body, &posture)
		m.lastPostureReq = &ProxiedPostureRequest{Posture: &posture}

		if m.postureError != "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: m.postureError})
			return
		}
		w.WriteHeader(http.StatusOK)

	case r.URL.Path == "/api/v1/certs/sign" && r.Method == http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &m.lastCertReq)

		if m.certError != "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: m.certError})
			return
		}

		resp := m.certResponse
		if resp == nil {
			resp = &ProxiedCertResponse{
				Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA...",
				Serial:      12345,
				ValidBefore: time.Now().Add(8 * time.Hour).Format(time.RFC3339),
			}
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *mockControlPlane) close() {
	m.server.Close()
}

func (m *mockControlPlane) url() string {
	return m.server.URL
}

func TestLocalAPI_Health(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid", LastChecked: time.Now()}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/local/v1/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("expected status healthy, got %s", resp.Status)
	}
	if resp.DPUName != "dpu-test" {
		t.Errorf("expected DPU name dpu-test, got %s", resp.DPUName)
	}
	if resp.AttestationStatus != "valid" {
		t.Errorf("expected attestation valid, got %s", resp.AttestationStatus)
	}
	if resp.ControlPlane != "connected" {
		t.Errorf("expected control plane connected, got %s", resp.ControlPlane)
	}
}

func TestLocalAPI_Register(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		DPUID:           "dpu_12345678",
		DPUSerial:       "SN12345",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid", LastChecked: time.Now()}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	body, _ := json.Marshal(RegisterRequest{
		Hostname: "test-host",
		Posture: &PosturePayload{
			SecureBoot:    boolPtr(true),
			OSVersion:     "Ubuntu 24.04",
			KernelVersion: "6.8.0-generic",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp RegisterResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.HostID == "" {
		t.Error("expected non-empty host ID")
	}
	if resp.DPUName != "dpu-test" {
		t.Errorf("expected DPU name dpu-test, got %s", resp.DPUName)
	}

	// Verify the proxied request
	if mock.lastRegisterReq == nil {
		t.Fatal("expected register request to be proxied")
	}
	if mock.lastRegisterReq.DPUName != "dpu-test" {
		t.Errorf("expected DPU name dpu-test, got %s", mock.lastRegisterReq.DPUName)
	}
	if mock.lastRegisterReq.AttestationStatus != "valid" {
		t.Errorf("expected attestation valid, got %s", mock.lastRegisterReq.AttestationStatus)
	}
}

func TestLocalAPI_Posture(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid", LastChecked: time.Now()}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// First register a host
	server.setPairedHost("test-host", "host_12345678")

	// Then update posture
	body, _ := json.Marshal(PostureRequest{
		Hostname: "test-host",
		Posture: &PosturePayload{
			SecureBoot:     boolPtr(true),
			DiskEncryption: "luks",
			OSVersion:      "Ubuntu 24.04",
			KernelVersion:  "6.8.0-generic",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/local/v1/posture", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp PostureResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Accepted {
		t.Error("expected posture to be accepted")
	}
}

func TestLocalAPI_Cert(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		DPUSerial:       "SN12345",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{
				Status:       "valid",
				Measurements: []string{"abc123", "def456"},
				LastChecked:  time.Now(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// First register a host
	server.setPairedHost("test-host", "host_12345678")

	body, _ := json.Marshal(CertRequest{
		Hostname:   "test-host",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest...",
		Principals: []string{"ubuntu", "admin"},
	})

	req := httptest.NewRequest(http.MethodPost, "/local/v1/cert", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CertResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Certificate == "" {
		t.Error("expected non-empty certificate")
	}
	if resp.Serial == 0 {
		t.Error("expected non-zero serial")
	}

	// Verify the proxied request includes attestation
	if mock.lastCertReq == nil {
		t.Fatal("expected cert request to be proxied")
	}
	if mock.lastCertReq.DPUName != "dpu-test" {
		t.Errorf("expected DPU name dpu-test, got %s", mock.lastCertReq.DPUName)
	}
	if mock.lastCertReq.AttestationStatus != "valid" {
		t.Errorf("expected attestation valid, got %s", mock.lastCertReq.AttestationStatus)
	}
	if len(mock.lastCertReq.Measurements) != 2 {
		t.Errorf("expected 2 measurements, got %d", len(mock.lastCertReq.Measurements))
	}
}

func TestLocalAPI_RejectsNonLocalRequests(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:9443", // TCP listener
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/local/v1/health", nil)
	req.RemoteAddr = "192.168.1.100:12345" // Non-local IP
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestLocalAPI_HostnamePairing(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Register first host
	body1, _ := json.Marshal(RegisterRequest{Hostname: "host-a"})
	req1 := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body1))
	req1.RemoteAddr = "127.0.0.1:12345"
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d", w1.Code)
	}

	// Try to register second host (should fail)
	body2, _ := json.Marshal(RegisterRequest{Hostname: "host-b"})
	req2 := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body2))
	req2.RemoteAddr = "127.0.0.1:12345"
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Errorf("expected status 409 for second registration, got %d", w2.Code)
	}
}

func TestLocalAPI_AllowedHostnames(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:       "localhost:0",
		ControlPlaneURL:  mock.url(),
		DPUName:          "dpu-test",
		AllowedHostnames: []string{"allowed-host"},
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Try to register disallowed host
	body, _ := json.Marshal(RegisterRequest{Hostname: "disallowed-host"})
	req := httptest.NewRequest(http.MethodPost, "/local/v1/register", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for disallowed host, got %d", w.Code)
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestLocalAPI_CredentialPush(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid", LastChecked: time.Now()}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// First register a host so we have a paired host
	server.setPairedHost("test-host", "host_12345678")

	// Test credential push request
	body, _ := json.Marshal(CredentialPushRequest{
		CredentialType: "ssh-ca",
		CredentialName: "prod-ca",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest..."),
	})

	req := httptest.NewRequest(http.MethodPost, "/local/v1/credential", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CredentialPushResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Without tmfifo, should indicate credential is pending
	// The response indicates tmfifo is not available
	if resp.Success && resp.Error == "" {
		t.Log("credential push accepted (tmfifo may be mocked)")
	}
}

func TestLocalAPI_CredentialPush_NoHostPaired(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid", LastChecked: time.Now()}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Don't register any host

	body, _ := json.Marshal(CredentialPushRequest{
		CredentialType: "ssh-ca",
		CredentialName: "prod-ca",
		Data:           []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest..."),
	})

	req := httptest.NewRequest(http.MethodPost, "/local/v1/credential", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusPreconditionFailed {
		t.Errorf("expected status 412 for no paired host, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLocalAPI_CredentialPush_ValidationErrors(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid", LastChecked: time.Now()}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	tests := []struct {
		name           string
		request        CredentialPushRequest
		expectedStatus int
		expectedError  string
	}{
		{
			name: "missing credential_type",
			request: CredentialPushRequest{
				CredentialName: "prod-ca",
				Data:           []byte("ssh-ed25519 ..."),
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "credential_type is required",
		},
		{
			name: "missing credential_name",
			request: CredentialPushRequest{
				CredentialType: "ssh-ca",
				Data:           []byte("ssh-ed25519 ..."),
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "credential_name is required",
		},
		{
			name: "missing data",
			request: CredentialPushRequest{
				CredentialType: "ssh-ca",
				CredentialName: "prod-ca",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "data is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPost, "/local/v1/credential", bytes.NewReader(body))
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.server.Handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tc.expectedStatus, w.Code, w.Body.String())
			}

			var resp ErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.Error != tc.expectedError {
				t.Errorf("expected error '%s', got '%s'", tc.expectedError, resp.Error)
			}
		})
	}
}

func TestLocalAPI_CredentialQueue(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
		AttestationFetcher: func(ctx context.Context) (*AttestationInfo, error) {
			return &AttestationInfo{Status: "valid", LastChecked: time.Now()}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Pair a host
	server.setPairedHost("test-host", "host_12345678")

	// Push credentials via PushCredential method
	ctx := context.Background()
	result, err := server.PushCredential(ctx, "ssh-ca", "ca1", []byte("key1"))
	if err != nil {
		t.Fatalf("PushCredential failed: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}

	result, err = server.PushCredential(ctx, "ssh-ca", "ca2", []byte("key2"))
	if err != nil {
		t.Fatalf("PushCredential failed: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}

	// Get queued credentials
	creds := server.GetQueuedCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 queued credentials, got %d", len(creds))
	}

	if creds[0].CredName != "ca1" {
		t.Errorf("expected first cred to be 'ca1', got '%s'", creds[0].CredName)
	}
	if creds[1].CredName != "ca2" {
		t.Errorf("expected second cred to be 'ca2', got '%s'", creds[1].CredName)
	}

	// Queue should be empty after retrieval
	creds = server.GetQueuedCredentials()
	if len(creds) != 0 {
		t.Errorf("expected empty queue after retrieval, got %d", len(creds))
	}
}

func TestLocalAPI_PushCredential_NoPairedHost(t *testing.T) {
	mock := newMockControlPlane()
	defer mock.close()

	server, err := NewServer(&Config{
		ListenAddr:      "localhost:0",
		ControlPlaneURL: mock.url(),
		DPUName:         "dpu-test",
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Don't pair any host
	ctx := context.Background()
	_, err = server.PushCredential(ctx, "ssh-ca", "ca1", []byte("key1"))
	if err == nil {
		t.Error("expected error when no host is paired")
	}
}
