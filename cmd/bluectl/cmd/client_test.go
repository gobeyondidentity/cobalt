package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNexusClient_AddDPU(t *testing.T) {
	tests := []struct {
		name       string
		dpuName    string
		host       string
		port       int
		serverResp dpuResponse
		serverCode int
		wantErr    bool
	}{
		{
			name:    "successful add",
			dpuName: "bf3-lab",
			host:    "192.168.1.204",
			port:    18051,
			serverResp: dpuResponse{
				ID:     "abc12345",
				Name:   "bf3-lab",
				Host:   "192.168.1.204",
				Port:   18051,
				Status: "healthy",
			},
			serverCode: http.StatusCreated,
			wantErr:    false,
		},
		{
			name:       "conflict - DPU exists",
			dpuName:    "bf3-lab",
			host:       "192.168.1.204",
			port:       18051,
			serverCode: http.StatusConflict,
			wantErr:    true,
		},
		{
			name:       "server error",
			dpuName:    "bf3-lab",
			host:       "192.168.1.204",
			port:       18051,
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/api/dpus" {
					t.Errorf("expected /api/dpus, got %s", r.URL.Path)
				}

				// Verify request body
				var req addDPURequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				if req.Name != tt.dpuName {
					t.Errorf("expected name %s, got %s", tt.dpuName, req.Name)
				}
				if req.Host != tt.host {
					t.Errorf("expected host %s, got %s", tt.host, req.Host)
				}
				if req.Port != tt.port {
					t.Errorf("expected port %d, got %d", tt.port, req.Port)
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusCreated {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			resp, err := client.AddDPU(context.Background(), tt.dpuName, tt.host, tt.port)

			if (err != nil) != tt.wantErr {
				t.Errorf("AddDPU() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp.ID != tt.serverResp.ID {
					t.Errorf("expected ID %s, got %s", tt.serverResp.ID, resp.ID)
				}
				if resp.Name != tt.serverResp.Name {
					t.Errorf("expected Name %s, got %s", tt.serverResp.Name, resp.Name)
				}
			}
		})
	}
}

func TestNexusClient_ListDPUs(t *testing.T) {
	tests := []struct {
		name       string
		serverResp []dpuResponse
		serverCode int
		wantErr    bool
		wantCount  int
	}{
		{
			name: "successful list with DPUs",
			serverResp: []dpuResponse{
				{ID: "abc12345", Name: "bf3-lab", Host: "192.168.1.204", Port: 18051, Status: "healthy"},
				{ID: "def67890", Name: "bf3-dev", Host: "192.168.1.205", Port: 18051, Status: "offline"},
			},
			serverCode: http.StatusOK,
			wantErr:    false,
			wantCount:  2,
		},
		{
			name:       "empty list",
			serverResp: []dpuResponse{},
			serverCode: http.StatusOK,
			wantErr:    false,
			wantCount:  0,
		},
		{
			name:       "server error",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if r.URL.Path != "/api/dpus" {
					t.Errorf("expected /api/dpus, got %s", r.URL.Path)
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			resp, err := client.ListDPUs(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("ListDPUs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(resp) != tt.wantCount {
					t.Errorf("expected %d DPUs, got %d", tt.wantCount, len(resp))
				}
			}
		})
	}
}

func TestNexusClient_RemoveDPU(t *testing.T) {
	tests := []struct {
		name       string
		dpuID      string
		serverCode int
		wantErr    bool
	}{
		{
			name:       "successful remove",
			dpuID:      "abc12345",
			serverCode: http.StatusNoContent,
			wantErr:    false,
		},
		{
			name:       "not found",
			dpuID:      "nonexistent",
			serverCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "server error",
			dpuID:      "abc12345",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE, got %s", r.Method)
				}
				expectedPath := "/api/dpus/" + tt.dpuID
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.serverCode)
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			err := client.RemoveDPU(context.Background(), tt.dpuID)

			if (err != nil) != tt.wantErr {
				t.Errorf("RemoveDPU() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewNexusClient(t *testing.T) {
	// Test that trailing slash is removed
	client := NewNexusClient("http://localhost:8080/")
	if client.baseURL != "http://localhost:8080" {
		t.Errorf("expected trailing slash removed, got %s", client.baseURL)
	}

	// Test without trailing slash
	client = NewNexusClient("http://localhost:8080")
	if client.baseURL != "http://localhost:8080" {
		t.Errorf("expected base URL unchanged, got %s", client.baseURL)
	}
}

// ----- Tenant Client Tests -----

func TestNexusClient_ListTenants(t *testing.T) {
	tests := []struct {
		name       string
		serverResp []tenantResponse
		serverCode int
		wantErr    bool
		wantCount  int
	}{
		{
			name: "successful list with tenants",
			serverResp: []tenantResponse{
				{ID: "tnt_abc123", Name: "Production", Description: "Prod environment", Contact: "ops@example.com", Tags: []string{"prod"}, DPUCount: 2, CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z"},
				{ID: "tnt_def456", Name: "Development", Description: "Dev environment", Contact: "dev@example.com", Tags: []string{"dev"}, DPUCount: 1, CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z"},
			},
			serverCode: http.StatusOK,
			wantErr:    false,
			wantCount:  2,
		},
		{
			name:       "empty list",
			serverResp: []tenantResponse{},
			serverCode: http.StatusOK,
			wantErr:    false,
			wantCount:  0,
		},
		{
			name:       "server error",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if r.URL.Path != "/api/tenants" {
					t.Errorf("expected /api/tenants, got %s", r.URL.Path)
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			resp, err := client.ListTenants(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("ListTenants() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(resp) != tt.wantCount {
					t.Errorf("expected %d tenants, got %d", tt.wantCount, len(resp))
				}
			}
		})
	}
}

func TestNexusClient_CreateTenant(t *testing.T) {
	tests := []struct {
		name        string
		tenantName  string
		description string
		contact     string
		tags        []string
		serverResp  tenantResponse
		serverCode  int
		wantErr     bool
	}{
		{
			name:        "successful create",
			tenantName:  "Production",
			description: "Prod environment",
			contact:     "ops@example.com",
			tags:        []string{"prod"},
			serverResp: tenantResponse{
				ID:          "tnt_abc123",
				Name:        "Production",
				Description: "Prod environment",
				Contact:     "ops@example.com",
				Tags:        []string{"prod"},
				DPUCount:    0,
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
			serverCode: http.StatusCreated,
			wantErr:    false,
		},
		{
			name:        "conflict - tenant exists",
			tenantName:  "Production",
			description: "Prod environment",
			contact:     "ops@example.com",
			tags:        []string{"prod"},
			serverCode:  http.StatusConflict,
			wantErr:     true,
		},
		{
			name:        "server error",
			tenantName:  "Production",
			description: "Prod environment",
			contact:     "ops@example.com",
			tags:        []string{"prod"},
			serverCode:  http.StatusInternalServerError,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/api/tenants" {
					t.Errorf("expected /api/tenants, got %s", r.URL.Path)
				}

				// Verify request body
				var req createTenantRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				if req.Name != tt.tenantName {
					t.Errorf("expected name %s, got %s", tt.tenantName, req.Name)
				}
				if req.Description != tt.description {
					t.Errorf("expected description %s, got %s", tt.description, req.Description)
				}
				if req.Contact != tt.contact {
					t.Errorf("expected contact %s, got %s", tt.contact, req.Contact)
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusCreated {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			resp, err := client.CreateTenant(context.Background(), tt.tenantName, tt.description, tt.contact, tt.tags)

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTenant() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp.ID != tt.serverResp.ID {
					t.Errorf("expected ID %s, got %s", tt.serverResp.ID, resp.ID)
				}
				if resp.Name != tt.serverResp.Name {
					t.Errorf("expected Name %s, got %s", tt.serverResp.Name, resp.Name)
				}
			}
		})
	}
}

func TestNexusClient_GetTenant(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		serverResp tenantResponse
		serverCode int
		wantErr    bool
	}{
		{
			name:     "successful get",
			tenantID: "tnt_abc123",
			serverResp: tenantResponse{
				ID:          "tnt_abc123",
				Name:        "Production",
				Description: "Prod environment",
				Contact:     "ops@example.com",
				Tags:        []string{"prod"},
				DPUCount:    2,
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
			serverCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "not found",
			tenantID:   "nonexistent",
			serverCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "server error",
			tenantID:   "tnt_abc123",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				expectedPath := "/api/tenants/" + tt.tenantID
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			resp, err := client.GetTenant(context.Background(), tt.tenantID)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetTenant() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp.ID != tt.serverResp.ID {
					t.Errorf("expected ID %s, got %s", tt.serverResp.ID, resp.ID)
				}
				if resp.Name != tt.serverResp.Name {
					t.Errorf("expected Name %s, got %s", tt.serverResp.Name, resp.Name)
				}
			}
		})
	}
}

func TestNexusClient_UpdateTenant(t *testing.T) {
	tests := []struct {
		name        string
		tenantID    string
		tenantName  string
		description string
		contact     string
		tags        []string
		serverResp  tenantResponse
		serverCode  int
		wantErr     bool
	}{
		{
			name:        "successful update",
			tenantID:    "tnt_abc123",
			tenantName:  "Production Updated",
			description: "Updated description",
			contact:     "newops@example.com",
			tags:        []string{"prod", "updated"},
			serverResp: tenantResponse{
				ID:          "tnt_abc123",
				Name:        "Production Updated",
				Description: "Updated description",
				Contact:     "newops@example.com",
				Tags:        []string{"prod", "updated"},
				DPUCount:    2,
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			},
			serverCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:        "not found",
			tenantID:    "nonexistent",
			tenantName:  "Production Updated",
			description: "Updated description",
			contact:     "newops@example.com",
			tags:        []string{"prod", "updated"},
			serverCode:  http.StatusNotFound,
			wantErr:     true,
		},
		{
			name:        "server error",
			tenantID:    "tnt_abc123",
			tenantName:  "Production Updated",
			description: "Updated description",
			contact:     "newops@example.com",
			tags:        []string{"prod", "updated"},
			serverCode:  http.StatusInternalServerError,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut {
					t.Errorf("expected PUT, got %s", r.Method)
				}
				expectedPath := "/api/tenants/" + tt.tenantID
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				// Verify request body
				var req updateTenantRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				if req.Name != tt.tenantName {
					t.Errorf("expected name %s, got %s", tt.tenantName, req.Name)
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			resp, err := client.UpdateTenant(context.Background(), tt.tenantID, tt.tenantName, tt.description, tt.contact, tt.tags)

			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateTenant() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp.ID != tt.serverResp.ID {
					t.Errorf("expected ID %s, got %s", tt.serverResp.ID, resp.ID)
				}
				if resp.Name != tt.serverResp.Name {
					t.Errorf("expected Name %s, got %s", tt.serverResp.Name, resp.Name)
				}
			}
		})
	}
}

func TestNexusClient_DeleteTenant(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		serverCode int
		wantErr    bool
	}{
		{
			name:       "successful delete",
			tenantID:   "tnt_abc123",
			serverCode: http.StatusNoContent,
			wantErr:    false,
		},
		{
			name:       "not found",
			tenantID:   "nonexistent",
			serverCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "conflict - has DPUs",
			tenantID:   "tnt_abc123",
			serverCode: http.StatusConflict,
			wantErr:    true,
		},
		{
			name:       "server error",
			tenantID:   "tnt_abc123",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE, got %s", r.Method)
				}
				expectedPath := "/api/tenants/" + tt.tenantID
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.serverCode)
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			err := client.DeleteTenant(context.Background(), tt.tenantID)

			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteTenant() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNexusClient_AssignDPUToTenant(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		dpuID      string
		serverCode int
		wantErr    bool
	}{
		{
			name:       "successful assign",
			tenantID:   "tnt_abc123",
			dpuID:      "dpu_xyz789",
			serverCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "tenant not found",
			tenantID:   "nonexistent",
			dpuID:      "dpu_xyz789",
			serverCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "DPU not found",
			tenantID:   "tnt_abc123",
			dpuID:      "nonexistent",
			serverCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "server error",
			tenantID:   "tnt_abc123",
			dpuID:      "dpu_xyz789",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				expectedPath := "/api/tenants/" + tt.tenantID + "/dpus"
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				// Verify request body
				var req assignDPURequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				if req.DPUID != tt.dpuID {
					t.Errorf("expected dpuId %s, got %s", tt.dpuID, req.DPUID)
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusOK {
					json.NewEncoder(w).Encode(dpuResponse{ID: tt.dpuID, TenantID: &tt.tenantID})
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			err := client.AssignDPUToTenant(context.Background(), tt.tenantID, tt.dpuID)

			if (err != nil) != tt.wantErr {
				t.Errorf("AssignDPUToTenant() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAssignDPURemote_ResolvesNames(t *testing.T) {
	// Test data: API returns IDs, but we pass names to assignDPURemote
	tenantID := "tnt_abc123"
	tenantName := "Production"
	dpuID := "dpu_xyz789"
	dpuName := "bf3-lab"

	tests := []struct {
		name           string
		tenantInput    string // What the user passes (name or ID)
		dpuInput       string // What the user passes (name or ID)
		expectTenantID string // What should be sent to the API
		expectDPUID    string // What should be sent to the API
		wantErr        bool
		errContains    string
	}{
		{
			name:           "resolve both names to IDs",
			tenantInput:    tenantName, // "Production"
			dpuInput:       dpuName,    // "bf3-lab"
			expectTenantID: tenantID,   // should resolve to "tnt_abc123"
			expectDPUID:    dpuID,      // should resolve to "dpu_xyz789"
			wantErr:        false,
		},
		{
			name:           "pass IDs directly",
			tenantInput:    tenantID, // "tnt_abc123"
			dpuInput:       dpuID,    // "dpu_xyz789"
			expectTenantID: tenantID,
			expectDPUID:    dpuID,
			wantErr:        false,
		},
		{
			name:           "resolve tenant name, pass DPU ID",
			tenantInput:    tenantName, // "Production"
			dpuInput:       dpuID,      // "dpu_xyz789"
			expectTenantID: tenantID,
			expectDPUID:    dpuID,
			wantErr:        false,
		},
		{
			name:           "pass tenant ID, resolve DPU name",
			tenantInput:    tenantID, // "tnt_abc123"
			dpuInput:       dpuName,  // "bf3-lab"
			expectTenantID: tenantID,
			expectDPUID:    dpuID,
			wantErr:        false,
		},
		{
			name:        "tenant not found",
			tenantInput: "nonexistent",
			dpuInput:    dpuName,
			wantErr:     true,
			errContains: "tenant not found",
		},
		{
			name:        "DPU not found",
			tenantInput: tenantName,
			dpuInput:    "nonexistent",
			wantErr:     true,
			errContains: "DPU not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var assignCalled bool
			var receivedTenantID, receivedDPUID string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/tenants":
					// Return list of tenants for name resolution
					tenants := []tenantResponse{
						{ID: tenantID, Name: tenantName, Description: "Prod env"},
						{ID: "tnt_other", Name: "Development", Description: "Dev env"},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tenants)

				case r.Method == http.MethodGet && r.URL.Path == "/api/dpus":
					// Return list of DPUs for name resolution
					dpus := []dpuResponse{
						{ID: dpuID, Name: dpuName, Host: "192.168.1.204", Port: 18051},
						{ID: "dpu_other", Name: "bf3-dev", Host: "192.168.1.205", Port: 18051},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(dpus)

				case r.Method == http.MethodPost && len(r.URL.Path) > len("/api/tenants/") && r.URL.Path[len(r.URL.Path)-5:] == "/dpus":
					// This is the assign call: POST /api/tenants/{tenantID}/dpus
					assignCalled = true
					// Extract tenant ID from path: /api/tenants/{tenantID}/dpus
					path := r.URL.Path
					path = path[len("/api/tenants/"):] // Remove prefix
					path = path[:len(path)-5]          // Remove "/dpus" suffix
					receivedTenantID = path

					// Get DPU ID from request body
					var req assignDPURequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Errorf("failed to decode assign request: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					receivedDPUID = req.DPUID

					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(dpuResponse{ID: receivedDPUID, TenantID: &receivedTenantID})

				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			err := assignDPURemote(context.Background(), server.URL, tt.tenantInput, tt.dpuInput)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !assignCalled {
				t.Error("expected assign API to be called")
				return
			}

			if receivedTenantID != tt.expectTenantID {
				t.Errorf("expected tenant ID %q in API call, got %q", tt.expectTenantID, receivedTenantID)
			}

			if receivedDPUID != tt.expectDPUID {
				t.Errorf("expected DPU ID %q in API call, got %q", tt.expectDPUID, receivedDPUID)
			}
		})
	}
}


func TestNexusClient_UnassignDPUFromTenant(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		dpuID      string
		serverCode int
		wantErr    bool
	}{
		{
			name:       "successful unassign",
			tenantID:   "tnt_abc123",
			dpuID:      "dpu_xyz789",
			serverCode: http.StatusNoContent,
			wantErr:    false,
		},
		{
			name:       "tenant not found",
			tenantID:   "nonexistent",
			dpuID:      "dpu_xyz789",
			serverCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "DPU not found",
			tenantID:   "tnt_abc123",
			dpuID:      "nonexistent",
			serverCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "DPU not assigned to tenant",
			tenantID:   "tnt_abc123",
			dpuID:      "dpu_xyz789",
			serverCode: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name:       "server error",
			tenantID:   "tnt_abc123",
			dpuID:      "dpu_xyz789",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE, got %s", r.Method)
				}
				expectedPath := "/api/tenants/" + tt.tenantID + "/dpus/" + tt.dpuID
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.serverCode)
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			err := client.UnassignDPUFromTenant(context.Background(), tt.tenantID, tt.dpuID)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnassignDPUFromTenant() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ----- Operator Client Tests -----

func TestNexusClient_InviteOperator(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		tenantName string
		role       string
		serverResp inviteOperatorResponse
		serverCode int
		wantErr    bool
	}{
		{
			name:       "successful invite",
			email:      "nelson@acme.com",
			tenantName: "acme",
			role:       "operator",
			serverResp: inviteOperatorResponse{
				Status:     "invited",
				InviteCode: "ACME-ABCD-1234",
				ExpiresAt:  "2024-01-02T00:00:00Z",
				Operator: struct {
					ID     string `json:"id"`
					Email  string `json:"email"`
					Status string `json:"status"`
				}{
					ID:     "op_abc123",
					Email:  "nelson@acme.com",
					Status: "pending_invite",
				},
			},
			serverCode: http.StatusCreated,
			wantErr:    false,
		},
		{
			name:       "operator already exists",
			email:      "nelson@acme.com",
			tenantName: "acme",
			role:       "operator",
			serverResp: inviteOperatorResponse{
				Status: "already_exists",
				Operator: struct {
					ID     string `json:"id"`
					Email  string `json:"email"`
					Status string `json:"status"`
				}{
					ID:     "op_abc123",
					Email:  "nelson@acme.com",
					Status: "active",
				},
			},
			serverCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "tenant not found",
			email:      "nelson@acme.com",
			tenantName: "nonexistent",
			role:       "operator",
			serverCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "server error",
			email:      "nelson@acme.com",
			tenantName: "acme",
			role:       "operator",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/api/v1/operators/invite" {
					t.Errorf("expected /api/v1/operators/invite, got %s", r.URL.Path)
				}

				// Verify request body
				var req inviteOperatorRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				if req.Email != tt.email {
					t.Errorf("expected email %s, got %s", tt.email, req.Email)
				}
				if req.TenantName != tt.tenantName {
					t.Errorf("expected tenant_name %s, got %s", tt.tenantName, req.TenantName)
				}
				if req.Role != tt.role {
					t.Errorf("expected role %s, got %s", tt.role, req.Role)
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusCreated || tt.serverCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			resp, err := client.InviteOperator(context.Background(), tt.email, tt.tenantName, tt.role)

			if (err != nil) != tt.wantErr {
				t.Errorf("InviteOperator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp.Status != tt.serverResp.Status {
					t.Errorf("expected status %s, got %s", tt.serverResp.Status, resp.Status)
				}
				if resp.Operator.Email != tt.serverResp.Operator.Email {
					t.Errorf("expected operator email %s, got %s", tt.serverResp.Operator.Email, resp.Operator.Email)
				}
			}
		})
	}
}

// ----- Agent Host Client Tests -----

func TestNexusClient_ListAgentHosts(t *testing.T) {
	tests := []struct {
		name       string
		tenant     string
		serverResp []agentHostResponse
		serverCode int
		wantErr    bool
		wantCount  int
	}{
		{
			name:   "successful list with hosts",
			tenant: "",
			serverResp: []agentHostResponse{
				{ID: "host_abc123", DPUName: "bf3-lab", Hostname: "worker-1", LastSeenAt: "2024-01-01T00:00:00Z"},
				{ID: "host_def456", DPUName: "bf3-dev", Hostname: "worker-2", LastSeenAt: "2024-01-01T01:00:00Z"},
			},
			serverCode: http.StatusOK,
			wantErr:    false,
			wantCount:  2,
		},
		{
			name:       "empty list",
			tenant:     "",
			serverResp: []agentHostResponse{},
			serverCode: http.StatusOK,
			wantErr:    false,
			wantCount:  0,
		},
		{
			name:   "list filtered by tenant",
			tenant: "acme",
			serverResp: []agentHostResponse{
				{ID: "host_abc123", DPUName: "bf3-lab", Hostname: "worker-1", LastSeenAt: "2024-01-01T00:00:00Z"},
			},
			serverCode: http.StatusOK,
			wantErr:    false,
			wantCount:  1,
		},
		{
			name:       "server error",
			tenant:     "",
			serverCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Log("Creating test server that returns wrapped hosts response")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				expectedPath := "/api/v1/hosts"
				if r.URL.Path != expectedPath {
					t.Errorf("expected %s, got %s", expectedPath, r.URL.Path)
				}

				// Verify tenant query parameter if expected
				if tt.tenant != "" {
					gotTenant := r.URL.Query().Get("tenant")
					if gotTenant != tt.tenant {
						t.Errorf("expected tenant query param %s, got %s", tt.tenant, gotTenant)
					}
				}

				w.WriteHeader(tt.serverCode)
				if tt.serverCode == http.StatusOK {
					// Server returns wrapped response: {"hosts": [...]}
					t.Log("Returning wrapped response format: {\"hosts\": [...]}")
					wrapper := struct {
						Hosts []agentHostResponse `json:"hosts"`
					}{Hosts: tt.serverResp}
					json.NewEncoder(w).Encode(wrapper)
				}
			}))
			defer server.Close()

			t.Log("Calling ListAgentHosts via NexusClient")
			client := NewNexusClient(server.URL)
			resp, err := client.ListAgentHosts(context.Background(), tt.tenant)

			if (err != nil) != tt.wantErr {
				t.Errorf("ListAgentHosts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				t.Logf("Verifying response contains %d hosts", tt.wantCount)
				if len(resp) != tt.wantCount {
					t.Errorf("expected %d hosts, got %d", tt.wantCount, len(resp))
				}

				// Verify host data is correctly parsed
				for i, host := range resp {
					if host.ID != tt.serverResp[i].ID {
						t.Errorf("host[%d]: expected ID %s, got %s", i, tt.serverResp[i].ID, host.ID)
					}
					if host.DPUName != tt.serverResp[i].DPUName {
						t.Errorf("host[%d]: expected DPUName %s, got %s", i, tt.serverResp[i].DPUName, host.DPUName)
					}
					if host.Hostname != tt.serverResp[i].Hostname {
						t.Errorf("host[%d]: expected Hostname %s, got %s", i, tt.serverResp[i].Hostname, host.Hostname)
					}
				}
			}
		})
	}
}

func TestNexusClient_ListAgentHosts_RejectsUnwrappedResponse(t *testing.T) {
	// This test ensures the client properly handles the wrapped format and rejects
	// a server returning a raw array instead of {"hosts": [...]}
	t.Log("Testing that client expects wrapped response format")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Simulate a buggy server returning raw array instead of wrapped
		t.Log("Server returning raw array (incorrect format)")
		rawArray := []agentHostResponse{
			{ID: "host_abc123", DPUName: "bf3-lab", Hostname: "worker-1"},
		}
		json.NewEncoder(w).Encode(rawArray)
	}))
	defer server.Close()

	client := NewNexusClient(server.URL)
	_, err := client.ListAgentHosts(context.Background(), "")

	// With wrapped response handling, a raw array causes a JSON decode error
	// because it cannot unmarshal an array into the wrapper struct
	t.Log("Verifying that raw array response causes decode error")
	if err == nil {
		t.Error("expected error when server returns raw array, got nil")
		return
	}

	if !strings.Contains(err.Error(), "failed to decode response") {
		t.Errorf("expected decode error, got: %v", err)
	}
}
