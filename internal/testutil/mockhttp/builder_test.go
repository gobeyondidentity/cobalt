package mockhttp

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestJSON(t *testing.T) {
	t.Parallel()
	t.Log("Testing JSON response handler")

	type response struct {
		Message string `json:"message"`
	}

	server, client := New().
		JSON("/api/test", response{Message: "hello"}).
		Build()
	defer server.Close()

	t.Log("Making GET request to /api/test")
	resp, err := client.Get(server.URL + "/api/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var got response
	json.NewDecoder(resp.Body).Decode(&got)
	if got.Message != "hello" {
		t.Errorf("expected message=hello, got %s", got.Message)
	}
	t.Log("JSON response correctly returned")
}

func TestJSONWithStatus(t *testing.T) {
	t.Parallel()
	t.Log("Testing JSON response with custom status code")

	server, client := New().
		JSONWithStatus("/api/created", http.StatusCreated, map[string]string{"id": "123"}).
		Build()
	defer server.Close()

	resp, err := client.Get(server.URL + "/api/created")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
	t.Log("Custom status code correctly returned")
}

func TestStatus(t *testing.T) {
	t.Parallel()
	t.Log("Testing status-only response")

	server, client := New().
		Status("/not-found", http.StatusNotFound).
		Build()
	defer server.Close()

	resp, err := client.Get(server.URL + "/not-found")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
	t.Log("Status response correctly returned")
}

func TestStatusWithBody(t *testing.T) {
	t.Parallel()
	t.Log("Testing status response with body")

	server, client := New().
		StatusWithBody("/error", http.StatusInternalServerError, `{"error": "oops"}`).
		Build()
	defer server.Close()

	resp, err := client.Get(server.URL + "/error")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "oops") {
		t.Errorf("expected body to contain 'oops', got %s", body)
	}
	t.Log("Status with body correctly returned")
}

func TestText(t *testing.T) {
	t.Parallel()
	t.Log("Testing plain text response")

	server, client := New().
		Text("/metrics", "cpu_percent 45.2\n").
		Build()
	defer server.Close()

	resp, err := client.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "cpu_percent") {
		t.Errorf("expected prometheus metrics, got %s", body)
	}
	t.Log("Text response correctly returned")
}

func TestCapture(t *testing.T) {
	t.Parallel()
	t.Log("Testing request capture")

	builder := New()
	capture := builder.Capture()
	server, client := builder.
		JSON("/api/data", map[string]string{"status": "ok"}).
		Build()
	defer server.Close()

	t.Log("Making POST request with JSON body")
	req, _ := http.NewRequest("POST", server.URL+"/api/data", strings.NewReader(`{"name":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom", "value")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if capture.Count() != 1 {
		t.Fatalf("expected 1 captured request, got %d", capture.Count())
	}

	captured := capture.Last()
	if captured.Method != "POST" {
		t.Errorf("expected POST, got %s", captured.Method)
	}
	if captured.Path != "/api/data" {
		t.Errorf("expected /api/data, got %s", captured.Path)
	}
	if captured.Headers.Get("X-Custom") != "value" {
		t.Errorf("expected X-Custom=value, got %s", captured.Headers.Get("X-Custom"))
	}

	var body map[string]string
	if err := captured.BodyJSON(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["name"] != "test" {
		t.Errorf("expected name=test, got %s", body["name"])
	}
	t.Log("Request correctly captured")
}

func TestRequireBasicAuth(t *testing.T) {
	t.Parallel()
	t.Log("Testing Basic auth requirement")

	server, client := New().
		RequireBasicAuth("admin", "secret").
		JSON("/api/secure", map[string]string{"data": "sensitive"}).
		Build()
	defer server.Close()

	t.Log("Making request without auth")
	resp, err := client.Get(server.URL + "/api/secure")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}

	t.Log("Making request with correct auth")
	req, _ := http.NewRequest("GET", server.URL+"/api/secure", nil)
	req.SetBasicAuth("admin", "secret")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with auth, got %d", resp.StatusCode)
	}
	t.Log("Basic auth correctly enforced")
}

func TestRequireHeader(t *testing.T) {
	t.Parallel()
	t.Log("Testing header requirement")

	server, client := New().
		RequireHeader("X-API-Key", "secret-key").
		JSON("/api/data", map[string]string{"ok": "true"}).
		Build()
	defer server.Close()

	t.Log("Making request without required header")
	resp, err := client.Get(server.URL + "/api/data")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 without header, got %d", resp.StatusCode)
	}

	t.Log("Making request with correct header")
	req, _ := http.NewRequest("GET", server.URL+"/api/data", nil)
	req.Header.Set("X-API-Key", "secret-key")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with header, got %d", resp.StatusCode)
	}
	t.Log("Header requirement correctly enforced")
}

func TestTLS(t *testing.T) {
	t.Parallel()
	t.Log("Testing TLS server")

	server, client := New().
		TLS().
		JSON("/api/secure", map[string]string{"secure": "true"}).
		Build()
	defer server.Close()

	if !strings.HasPrefix(server.URL, "https://") {
		t.Errorf("expected https URL, got %s", server.URL)
	}

	resp, err := client.Get(server.URL + "/api/secure")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	t.Log("TLS server working correctly")
}

func TestRoute(t *testing.T) {
	t.Parallel()
	t.Log("Testing method-specific routing")

	server, client := New().
		Route("POST", "/api/items", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"created": true}`))
		}).
		Route("GET", "/api/items", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"items": []}`))
		}).
		Build()
	defer server.Close()

	t.Log("Testing GET request")
	resp, _ := client.Get(server.URL + "/api/items")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	t.Log("Testing POST request")
	resp, _ = client.Post(server.URL+"/api/items", "application/json", nil)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST: expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	t.Log("Method-specific routing works correctly")
}

func TestPathMatching(t *testing.T) {
	t.Parallel()
	t.Log("Testing path matching with wildcards")

	server, client := New().
		JSON("/exact", map[string]string{"type": "exact"}).
		JSON("/prefix/*", map[string]string{"type": "prefix"}).
		Build()
	defer server.Close()

	tests := []struct {
		path     string
		expected string
	}{
		{"/exact", "exact"},
		{"/prefix/a", "prefix"},
		{"/prefix/a/b/c", "prefix"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			resp, err := client.Get(server.URL + tt.path)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			var result map[string]string
			json.NewDecoder(resp.Body).Decode(&result)
			if result["type"] != tt.expected {
				t.Errorf("path %s: expected type=%s, got %s", tt.path, tt.expected, result["type"])
			}
		})
	}
	t.Log("Path matching works correctly")
}

func TestDefaultStatus(t *testing.T) {
	t.Parallel()
	t.Log("Testing default status for unmatched routes")

	server, client := New().
		DefaultStatus(http.StatusServiceUnavailable).
		JSON("/api/health", map[string]string{"status": "ok"}).
		Build()
	defer server.Close()

	t.Log("Requesting unmatched path")
	resp, _ := client.Get(server.URL + "/unknown")
	resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for unmatched, got %d", resp.StatusCode)
	}
	t.Log("Default status correctly returned for unmatched routes")
}

func TestCaptureMultiple(t *testing.T) {
	t.Parallel()
	t.Log("Testing multiple request capture")

	builder := New()
	capture := builder.Capture()
	server, client := builder.
		JSON("/api/data", map[string]string{}).
		Build()
	defer server.Close()

	for i := 0; i < 3; i++ {
		client.Get(server.URL + "/api/data")
	}

	if capture.Count() != 3 {
		t.Errorf("expected 3 captured requests, got %d", capture.Count())
	}

	all := capture.All()
	if len(all) != 3 {
		t.Errorf("expected 3 requests in All(), got %d", len(all))
	}

	capture.Clear()
	if capture.Count() != 0 {
		t.Errorf("expected 0 after Clear(), got %d", capture.Count())
	}
	t.Log("Multiple request capture works correctly")
}

func TestBuildURL(t *testing.T) {
	t.Parallel()
	t.Log("Testing BuildURL convenience method")

	url, close := New().
		JSON("/api/test", map[string]string{"ok": "true"}).
		BuildURL()
	defer close()

	resp, err := http.Get(url + "/api/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	t.Log("BuildURL convenience method works correctly")
}
