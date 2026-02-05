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

			client := NewNexusClient(server.URL)
			err := setRoleRemote(context.Background(), server.URL, tt.email, tt.tenant, tt.role, client)

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

			client := NewNexusClient(server.URL)
			err := removeRoleRemote(context.Background(), server.URL, tt.email, tt.tenant, client)

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

	client := NewNexusClient(server.URL)
	err := setRoleRemote(context.Background(), server.URL, operatorEmail, tenantName, "super:admin", client)

	if err == nil {
		t.Error("expected permission denied error, got nil")
		return
	}

	t.Log("Verifying error contains permission message")
	if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "privileges") {
		t.Errorf("expected permission error, got: %v", err)
	}
}

func TestFormatDeviceSelector(t *testing.T) {
	t.Parallel()
	t.Log("Testing formatDeviceSelector formats device names correctly")

	tests := []struct {
		name        string
		deviceNames []string
		want        string
	}{
		{
			name:        "all devices",
			deviceNames: []string{"all"},
			want:        "all devices",
		},
		{
			name:        "single device",
			deviceNames: []string{"bf3-lab-01"},
			want:        "bf3-lab-01",
		},
		{
			name:        "multiple devices",
			deviceNames: []string{"bf3-lab-01", "bf3-lab-02", "bf3-prod-01"},
			want:        "bf3-lab-01, bf3-lab-02, bf3-prod-01",
		},
		{
			name:        "empty list",
			deviceNames: []string{},
			want:        "-",
		},
		{
			name:        "nil slice",
			deviceNames: nil,
			want:        "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDeviceSelector(tt.deviceNames)
			if got != tt.want {
				t.Errorf("formatDeviceSelector(%v) = %q, want %q", tt.deviceNames, got, tt.want)
			}
		})
	}
}

func TestRevokeAuthorizationRemote(t *testing.T) {
	t.Parallel()
	t.Log("Testing revokeAuthorizationRemote function with name resolution")

	// Test data
	operatorEmail := "nelson@acme.com"
	operatorID := "op_nelson123"
	tenantName := "acme"
	tenantID := "tnt_acme123"
	caName := "ops-ca"
	caID := "ca_ops123"
	authID := "auth_12345"

	tests := []struct {
		name        string
		email       string
		tenant      string
		ca          string
		wantErr     bool
		errContains string
	}{
		{
			name:    "successful revoke",
			email:   operatorEmail,
			tenant:  tenantName,
			ca:      caName,
			wantErr: false,
		},
		{
			name:        "operator not found",
			email:       "nobody@acme.com",
			tenant:      tenantName,
			ca:          caName,
			wantErr:     true,
			errContains: "operator not found",
		},
		{
			name:        "tenant not found",
			email:       operatorEmail,
			tenant:      "nonexistent",
			ca:          caName,
			wantErr:     true,
			errContains: "tenant not found",
		},
		{
			name:        "CA not found",
			email:       operatorEmail,
			tenant:      tenantName,
			ca:          "nonexistent-ca",
			wantErr:     true,
			errContains: "CA not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var deleteAuthCalled bool
			var receivedAuthID string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("Received request: %s %s", r.Method, r.URL.Path)

				switch {
				// GET /api/v1/operators/{email} - Get operator by email
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/operators/") && !strings.Contains(r.URL.Path, "/roles"):
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

				// GET /api/v1/tenants - List tenants
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tenants":
					tenants := []tenantResponse{
						{ID: tenantID, Name: tenantName},
						{ID: "tnt_other", Name: "other-tenant"},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tenants)

				// GET /api/v1/credentials/ssh-cas/{name} - Get SSH CA by name
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/credentials/ssh-cas/"):
					name := r.URL.Path[len("/api/v1/credentials/ssh-cas/"):]
					if name == caName {
						w.WriteHeader(http.StatusOK)
						json.NewEncoder(w).Encode(sshCAResponse{
							ID:   caID,
							Name: caName,
						})
					} else {
						w.WriteHeader(http.StatusNotFound)
						json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
					}

				// GET /api/v1/authorizations?operator_id=... - List authorizations
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/authorizations":
					auths := []authorizationResponse{
						{
							ID:          authID,
							OperatorID:  operatorID,
							TenantID:    tenantID,
							CAIDs:       []string{caID},
							CANames:     []string{caName},
							DeviceIDs:   []string{"all"},
							DeviceNames: []string{"all"},
							CreatedAt:   "2026-01-01T00:00:00Z",
							CreatedBy:   "system",
						},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(auths)

				// DELETE /api/v1/authorizations/{id} - Delete authorization
				case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/authorizations/"):
					deleteAuthCalled = true
					receivedAuthID = r.URL.Path[len("/api/v1/authorizations/"):]
					w.WriteHeader(http.StatusNoContent)

				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			client := NewNexusClient(server.URL)
			err := revokeAuthorizationRemote(context.Background(), server.URL, tt.email, tt.tenant, tt.ca, true, client)

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

			if !deleteAuthCalled {
				t.Error("expected DeleteAuthorization API to be called")
				return
			}

			t.Log("Verifying correct authorization ID was passed to API")
			if receivedAuthID != authID {
				t.Errorf("expected authorization ID %q, got %q", authID, receivedAuthID)
			}
		})
	}
}

func TestRevokeAuthorizationRemote_NoMatchingAuthorization(t *testing.T) {
	t.Parallel()
	t.Log("Testing revokeAuthorizationRemote when no matching authorization exists")

	operatorEmail := "nelson@acme.com"
	operatorID := "op_nelson123"
	tenantName := "acme"
	tenantID := "tnt_acme123"
	caName := "ops-ca"
	caID := "ca_ops123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/operators/"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(operatorResponse{ID: operatorID, Email: operatorEmail})

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tenants":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]tenantResponse{{ID: tenantID, Name: tenantName}})

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/credentials/ssh-cas/"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(sshCAResponse{ID: caID, Name: caName})

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/authorizations":
			// Return empty list - no authorizations
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]authorizationResponse{})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewNexusClient(server.URL)
	err := revokeAuthorizationRemote(context.Background(), server.URL, operatorEmail, tenantName, caName, true, client)

	if err == nil {
		t.Error("expected error for no matching authorization, got nil")
		return
	}

	t.Log("Verifying error message indicates no authorization found")
	if !strings.Contains(err.Error(), "no authorization found") {
		t.Errorf("expected 'no authorization found' error, got: %v", err)
	}
}

func TestRevokeAuthorizationRemote_OtherAuthorizationsRemain(t *testing.T) {
	t.Parallel()
	t.Log("Testing revokeAuthorizationRemote only revokes the specified CA authorization")

	operatorEmail := "nelson@acme.com"
	operatorID := "op_nelson123"
	tenantName := "acme"
	tenantID := "tnt_acme123"
	targetCA := "ops-ca"
	targetCAID := "ca_ops123"
	otherCA := "dev-ca"
	otherCAID := "ca_dev456"
	targetAuthID := "auth_target"
	otherAuthID := "auth_other"

	var deletedAuthIDs []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/operators/"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(operatorResponse{ID: operatorID, Email: operatorEmail})

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tenants":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]tenantResponse{{ID: tenantID, Name: tenantName}})

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/credentials/ssh-cas/"):
			name := r.URL.Path[len("/api/v1/credentials/ssh-cas/"):]
			if name == targetCA {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(sshCAResponse{ID: targetCAID, Name: targetCA})
			} else if name == otherCA {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(sshCAResponse{ID: otherCAID, Name: otherCA})
			} else {
				w.WriteHeader(http.StatusNotFound)
			}

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/authorizations":
			// Return two authorizations - one for each CA
			auths := []authorizationResponse{
				{
					ID:          targetAuthID,
					OperatorID:  operatorID,
					TenantID:    tenantID,
					CAIDs:       []string{targetCAID},
					CANames:     []string{targetCA},
					DeviceIDs:   []string{"all"},
					DeviceNames: []string{"all"},
				},
				{
					ID:          otherAuthID,
					OperatorID:  operatorID,
					TenantID:    tenantID,
					CAIDs:       []string{otherCAID},
					CANames:     []string{otherCA},
					DeviceIDs:   []string{"all"},
					DeviceNames: []string{"all"},
				},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(auths)

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/authorizations/"):
			id := r.URL.Path[len("/api/v1/authorizations/"):]
			deletedAuthIDs = append(deletedAuthIDs, id)
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewNexusClient(server.URL)
	err := revokeAuthorizationRemote(context.Background(), server.URL, operatorEmail, tenantName, targetCA, true, client)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	t.Log("Verifying only the target authorization was deleted")
	if len(deletedAuthIDs) != 1 {
		t.Errorf("expected 1 authorization deleted, got %d", len(deletedAuthIDs))
		return
	}
	if deletedAuthIDs[0] != targetAuthID {
		t.Errorf("expected authorization %q to be deleted, got %q", targetAuthID, deletedAuthIDs[0])
	}
}
