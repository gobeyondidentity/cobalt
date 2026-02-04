package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/internal/version"
)

func TestHealthEndpoint(t *testing.T) {
	t.Log("Starting health server on port 18099")
	shutdown := startHealthServer(18099)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		shutdown(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	t.Log("Making GET request to /health")
	resp, err := http.Get("http://localhost:18099/health")
	if err != nil {
		t.Fatalf("Failed to GET /health: %v", err)
	}
	defer resp.Body.Close()

	t.Log("Verifying response status code is 200")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	t.Log("Verifying Content-Type is application/json")
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	t.Log("Reading and parsing response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v (body: %s)", err, string(body))
	}

	t.Logf("Response: %s", string(body))

	t.Log("Verifying status field is 'ok'")
	if result["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", result["status"])
	}

	t.Log("Verifying version field matches internal/version.Version")
	if result["version"] != version.Version {
		t.Errorf("Expected version '%s', got '%s'", version.Version, result["version"])
	}
}

func TestHealthEndpointDisabled(t *testing.T) {
	t.Log("Starting health server with port 0 (disabled)")
	shutdown := startHealthServer(0)

	t.Log("Verifying shutdown function is callable (no-op)")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Errorf("Shutdown should not error when disabled: %v", err)
	}
	t.Log("Health server disabled correctly")
}
