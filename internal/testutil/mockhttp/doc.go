// Package mockhttp provides a builder pattern for creating mock HTTP servers in tests.
//
// This package eliminates boilerplate when testing HTTP clients by providing
// a fluent API for configuring mock responses, capturing requests, and validating headers.
//
// # Basic Usage
//
// Create a mock server that returns JSON:
//
//	server, client := mockhttp.New().
//		JSON("/api/users", []User{{ID: 1, Name: "Alice"}}).
//		Build()
//	defer server.Close()
//
// # Status Codes
//
// Return specific status codes with or without bodies:
//
//	server, _ := mockhttp.New().
//		Status("/not-found", http.StatusNotFound).
//		StatusWithBody("/error", 500, `{"error": "internal"}`).
//		JSONWithStatus("/created", 201, map[string]string{"id": "123"}).
//		Build()
//
// # Request Capture
//
// Capture requests for assertion in tests:
//
//	capture := mockhttp.New().Capture()
//	server, _ := mockhttp.New().
//		JSON("/api/data", response).
//		Build()
//	defer server.Close()
//
//	// ... make requests ...
//
//	req := capture.Last()
//	if req.Method != "POST" {
//		t.Errorf("expected POST, got %s", req.Method)
//	}
//
//	var body MyRequest
//	req.BodyJSON(&body)
//
// # Authentication
//
// Require Basic authentication:
//
//	server, _ := mockhttp.New().
//		RequireBasicAuth("admin", "secret").
//		JSON("/api/secure", data).
//		Build()
//
// # Header Validation
//
// Require specific headers:
//
//	server, _ := mockhttp.New().
//		RequireHeaderPresent("Authorization").
//		RequireHeader("Content-Type", "application/json").
//		JSON("/api/data", response).
//		Build()
//
// # TLS Servers
//
// Create HTTPS mock servers:
//
//	server, client := mockhttp.New().
//		TLS().
//		JSON("/api/secure", data).
//		Build()
//	defer server.Close()
//	// Use the returned client for TLS requests
//
// # Custom Handlers
//
// Add custom routing logic:
//
//	server, _ := mockhttp.New().
//		Route("POST", "/api/items", func(w http.ResponseWriter, r *http.Request) {
//			var item Item
//			json.NewDecoder(r.Body).Decode(&item)
//			w.WriteHeader(http.StatusCreated)
//			json.NewEncoder(w).Encode(item)
//		}).
//		Build()
//
// # Path Matching
//
// Paths support exact match and prefix match with "*" suffix:
//
//	server, _ := mockhttp.New().
//		JSON("/exact/path", data1).           // Matches only /exact/path
//		JSON("/prefix/*", data2).             // Matches /prefix/anything
//		Build()
package mockhttp
