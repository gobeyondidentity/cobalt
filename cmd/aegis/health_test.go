package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobeyondidentity/secure-infra/internal/version"
)

func TestHealthEndpoint(t *testing.T) {
	t.Log("Testing /health endpoint returns status and version")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": version.Version,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	t.Log("Making GET request to /health")
	mux.ServeHTTP(w, req)

	t.Log("Verifying response status code is 200")
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	t.Log("Verifying Content-Type is application/json")
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", contentType)
	}

	t.Log("Parsing JSON response body")
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	t.Log("Verifying response contains status=ok")
	if resp["status"] != "ok" {
		t.Fatalf("expected status=ok, got status=%s", resp["status"])
	}

	t.Logf("Verifying response contains version=%s", version.Version)
	if resp["version"] != version.Version {
		t.Fatalf("expected version=%s, got version=%s", version.Version, resp["version"])
	}

	t.Log("/health endpoint returns correct JSON: {\"status\":\"ok\",\"version\":\"" + version.Version + "\"}")
}

func TestHealthEndpointMethodNotAllowed(t *testing.T) {
	t.Log("Testing /health endpoint rejects non-GET methods")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": version.Version,
		})
	})

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		t.Logf("Testing %s /health returns 405", method)
		req := httptest.NewRequest(method, "/health", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /health: expected status 405, got %d", method, w.Code)
		}
	}

	t.Log("Non-GET methods correctly rejected")
}
