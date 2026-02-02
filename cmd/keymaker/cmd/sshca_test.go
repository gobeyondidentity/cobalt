package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterSSHCA_Success(t *testing.T) {
	// Cannot run in parallel - registerSSHCA uses global DPoP state
	t.Log("Testing SSH CA registration succeeds on 201 Created")

	// Mock server that returns success
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request at: " + r.URL.Path)

		// Verify request method and path
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/ssh-cas" {
			t.Errorf("Expected path /api/v1/ssh-cas, got %s", r.URL.Path)
		}

		// Parse and validate request body
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if req["name"] == "" {
			t.Error("Request missing 'name' field")
		}
		if req["public_key"] == "" {
			t.Error("Request missing 'public_key' field")
		}
		if req["key_type"] == "" {
			t.Error("Request missing 'key_type' field")
		}
		if req["operator_id"] == "" {
			t.Error("Request missing 'operator_id' field")
		}

		t.Logf("Registration request for CA: %s", req["name"])

		// Return success response
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"id":         "ca_abc123",
			"name":       req["name"],
			"key_type":   req["key_type"],
			"created_at": "2026-01-28T12:00:00Z",
		})
	}))
	defer server.Close()

	config := &KMConfig{
		OperatorID:      "op_test123",
		ControlPlaneURL: server.URL,
	}

	t.Log("Calling registerSSHCA with test config")
	registered, warning := registerSSHCA(config, "test-ca", "ssh-ed25519 AAAAC3NzaC1...", "ed25519")

	if !registered {
		t.Error("Expected registration to succeed")
	}
	if warning != "" {
		t.Errorf("Expected no warning, got: %s", warning)
	}
	t.Log("Registration succeeded as expected")
}

func TestRegisterSSHCA_Conflict(t *testing.T) {
	// Cannot run in parallel - registerSSHCA uses global DPoP state
	t.Log("Testing SSH CA registration handles 409 Conflict silently")

	// Mock server that returns conflict
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request - returning conflict")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "SSH CA with this name already exists",
		})
	}))
	defer server.Close()

	config := &KMConfig{
		OperatorID:      "op_test123",
		ControlPlaneURL: server.URL,
	}

	t.Log("Calling registerSSHCA expecting conflict response")
	registered, warning := registerSSHCA(config, "existing-ca", "ssh-ed25519 AAAAC3NzaC1...", "ed25519")

	if registered {
		t.Error("Expected registration to return false for conflict")
	}
	if warning != "" {
		t.Errorf("Expected no warning for conflict (silent), got: %s", warning)
	}
	t.Log("Conflict handled silently as expected")
}

func TestRegisterSSHCA_ServerError(t *testing.T) {
	// Cannot run in parallel - registerSSHCA uses global DPoP state
	t.Log("Testing SSH CA registration returns warning on server error")

	// Mock server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request - returning internal server error")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "database connection failed",
		})
	}))
	defer server.Close()

	config := &KMConfig{
		OperatorID:      "op_test123",
		ControlPlaneURL: server.URL,
	}

	t.Log("Calling registerSSHCA expecting error response")
	registered, warning := registerSSHCA(config, "test-ca", "ssh-ed25519 AAAAC3NzaC1...", "ed25519")

	if registered {
		t.Error("Expected registration to return false for server error")
	}
	if warning == "" {
		t.Error("Expected warning message for server error")
	}
	t.Logf("Warning returned as expected: %s", warning)
}

func TestRegisterSSHCA_ConnectionFailed(t *testing.T) {
	// Cannot run in parallel - registerSSHCA uses global DPoP state
	t.Log("Testing SSH CA registration returns warning when connection fails")

	config := &KMConfig{
		OperatorID:      "op_test123",
		ControlPlaneURL: "http://localhost:99999", // Invalid port
	}

	t.Log("Calling registerSSHCA with unreachable server")
	registered, warning := registerSSHCA(config, "test-ca", "ssh-ed25519 AAAAC3NzaC1...", "ed25519")

	if registered {
		t.Error("Expected registration to return false for connection failure")
	}
	if warning == "" {
		t.Error("Expected warning message for connection failure")
	}
	if warning == "" || len(warning) < 10 {
		t.Errorf("Expected descriptive warning, got: %s", warning)
	}
	t.Logf("Connection failure warning: %s", warning)
}

func TestRegisterSSHCA_BadRequest(t *testing.T) {
	// Cannot run in parallel - registerSSHCA uses global DPoP state
	t.Log("Testing SSH CA registration handles 400 Bad Request")

	// Mock server that returns bad request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Received request - returning bad request")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "operator not found",
		})
	}))
	defer server.Close()

	config := &KMConfig{
		OperatorID:      "op_invalid",
		ControlPlaneURL: server.URL,
	}

	t.Log("Calling registerSSHCA with invalid operator")
	registered, warning := registerSSHCA(config, "test-ca", "ssh-ed25519 AAAAC3NzaC1...", "ed25519")

	if registered {
		t.Error("Expected registration to return false for bad request")
	}
	if warning != "operator not found" {
		t.Errorf("Expected warning 'operator not found', got: %s", warning)
	}
	t.Log("Bad request handled correctly")
}

func TestRegisterSSHCA_RequestBody(t *testing.T) {
	// Cannot run in parallel - registerSSHCA uses global DPoP state
	t.Log("Testing SSH CA registration sends correct request body")

	expectedName := "my-test-ca"
	expectedPubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJKpF..."
	expectedKeyType := "ed25519"
	expectedOperatorID := "op_abc123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		t.Logf("Validating request body fields")

		if req["name"] != expectedName {
			t.Errorf("Expected name %q, got %q", expectedName, req["name"])
		}
		if req["public_key"] != expectedPubKey {
			t.Errorf("Expected public_key %q, got %q", expectedPubKey, req["public_key"])
		}
		if req["key_type"] != expectedKeyType {
			t.Errorf("Expected key_type %q, got %q", expectedKeyType, req["key_type"])
		}
		if req["operator_id"] != expectedOperatorID {
			t.Errorf("Expected operator_id %q, got %q", expectedOperatorID, req["operator_id"])
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "ca_test"})
	}))
	defer server.Close()

	config := &KMConfig{
		OperatorID:      expectedOperatorID,
		ControlPlaneURL: server.URL,
	}

	t.Log("Calling registerSSHCA with specific values")
	registerSSHCA(config, expectedName, expectedPubKey, expectedKeyType)
	t.Log("Request body validation complete")
}
