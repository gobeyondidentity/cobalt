package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetRoleRemote(t *testing.T) {
	t.Parallel()
	t.Log("Testing setRoleRemote function with name resolution")

	// Test data
	operatorEmail := "alice@acme.com"
	operatorID := "op_alice123"
	tenantName := "acme"
	tenantID := "tnt_acme123"
	role := "tenant:admin"

	tests := []struct {
		name        string
		email       string
		tenant      string
		role        string
		wantErr     bool
		errContains string
	}{
		{
			name:    "successful set-role",
			email:   operatorEmail,
			tenant:  tenantName,
			role:    role,
			wantErr: false,
		},
		{
			name:        "operator not found",
			email:       "nobody@acme.com",
			tenant:      tenantName,
			role:        role,
			wantErr:     true,
			errContains: "operator not found",
		},
		{
			name:        "tenant not found",
			email:       operatorEmail,
			tenant:      "nonexistent",
			role:        role,
			wantErr:     true,
			errContains: "tenant not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var assignRoleCalled bool
			var receivedOperatorID, receivedTenantID, receivedRole string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("Received request: %s %s", r.Method, r.URL.Path)

				switch {
				// GET /api/v1/operators/{email} - Get operator by email
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/operators/"):
					email := r.URL.Path[len("/api/v1/operators/"):]
					if email == operatorEmail {
						w.WriteHeader(http.StatusOK)
						json.NewEncoder(w).Encode(operatorResponse{
							ID:    operatorID,
							Email: operatorEmail,
						})
					} else {
						w.WriteHeader(http.StatusNotFound)
						json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
					}

				// GET /api/tenants - List tenants
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tenants":
					tenants := []tenantResponse{
						{ID: tenantID, Name: tenantName},
						{ID: "tnt_other", Name: "other-tenant"},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tenants)

				// POST /api/v1/operators/{id}/roles - Assign role
				case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/roles"):
					assignRoleCalled = true
					// Extract operator ID from path
					path := r.URL.Path
					path = strings.TrimPrefix(path, "/api/v1/operators/")
					path = strings.TrimSuffix(path, "/roles")
					receivedOperatorID = path

					var req assignRoleRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Errorf("failed to decode request: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					receivedTenantID = req.TenantID
					receivedRole = req.Role

					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			err := setRoleRemote(context.Background(), server.URL, tt.email, tt.tenant, tt.role)

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

			if !assignRoleCalled {
				t.Error("expected AssignRole API to be called")
				return
			}

			t.Log("Verifying resolved IDs were passed to API")
			if receivedOperatorID != operatorID {
				t.Errorf("expected operator ID %q, got %q", operatorID, receivedOperatorID)
			}
			if receivedTenantID != tenantID {
				t.Errorf("expected tenant ID %q, got %q", tenantID, receivedTenantID)
			}
			if receivedRole != tt.role {
				t.Errorf("expected role %q, got %q", tt.role, receivedRole)
			}
		})
	}
}

func TestRemoveRoleRemote(t *testing.T) {
	t.Parallel()
	t.Log("Testing removeRoleRemote function with name resolution")

	// Test data
	operatorEmail := "alice@acme.com"
	operatorID := "op_alice123"
	tenantName := "acme"
	tenantID := "tnt_acme123"

	tests := []struct {
		name        string
		email       string
		tenant      string
		wantErr     bool
		errContains string
	}{
		{
			name:    "successful remove-role",
			email:   operatorEmail,
			tenant:  tenantName,
			wantErr: false,
		},
		{
			name:        "operator not found",
			email:       "nobody@acme.com",
			tenant:      tenantName,
			wantErr:     true,
			errContains: "operator not found",
		},
		{
			name:        "tenant not found",
			email:       operatorEmail,
			tenant:      "nonexistent",
			wantErr:     true,
			errContains: "tenant not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var removeRoleCalled bool
			var receivedOperatorID, receivedTenantID string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("Received request: %s %s", r.Method, r.URL.Path)

				switch {
				// GET /api/v1/operators/{email} - Get operator by email
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/operators/"):
					email := r.URL.Path[len("/api/v1/operators/"):]
					if email == operatorEmail {
						w.WriteHeader(http.StatusOK)
						json.NewEncoder(w).Encode(operatorResponse{
							ID:    operatorID,
							Email: operatorEmail,
						})
					} else {
						w.WriteHeader(http.StatusNotFound)
						json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
					}

				// GET /api/tenants - List tenants
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tenants":
					tenants := []tenantResponse{
						{ID: tenantID, Name: tenantName},
						{ID: "tnt_other", Name: "other-tenant"},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tenants)

				// DELETE /api/v1/operators/{id}/roles/{tenant_id} - Remove role
				case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/roles/"):
					removeRoleCalled = true
					// Extract operator ID and tenant ID from path
					// Path: /api/v1/operators/{id}/roles/{tenant_id}
					path := r.URL.Path
					path = strings.TrimPrefix(path, "/api/v1/operators/")
					parts := strings.Split(path, "/roles/")
					if len(parts) == 2 {
						receivedOperatorID = parts[0]
						receivedTenantID = parts[1]
					}

					w.WriteHeader(http.StatusNoContent)

				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			err := removeRoleRemote(context.Background(), server.URL, tt.email, tt.tenant)

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

			if !removeRoleCalled {
				t.Error("expected RemoveRole API to be called")
				return
			}

			t.Log("Verifying resolved IDs were passed to API")
			if receivedOperatorID != operatorID {
				t.Errorf("expected operator ID %q, got %q", operatorID, receivedOperatorID)
			}
			if receivedTenantID != tenantID {
				t.Errorf("expected tenant ID %q, got %q", tenantID, receivedTenantID)
			}
		})
	}
}

func TestSetRoleRemote_PermissionDenied(t *testing.T) {
	t.Parallel()
	t.Log("Testing setRoleRemote with permission denied response")

	operatorEmail := "alice@acme.com"
	operatorID := "op_alice123"
	tenantName := "acme"
	tenantID := "tnt_acme123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/operators/"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(operatorResponse{ID: operatorID, Email: operatorEmail})

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tenants":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]tenantResponse{{ID: tenantID, Name: tenantName}})

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/roles"):
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot assign role 'super:admin': your role 'tenant:admin' does not have sufficient privileges",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	err := setRoleRemote(context.Background(), server.URL, operatorEmail, tenantName, "super:admin")

	if err == nil {
		t.Error("expected permission denied error, got nil")
		return
	}

	t.Log("Verifying error contains permission message")
	if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "privileges") {
		t.Errorf("expected permission error, got: %v", err)
	}
}
