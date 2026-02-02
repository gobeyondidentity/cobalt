package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRIMClient_ListRIMIDs(t *testing.T) {
	client := NewRIMClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ids, err := client.ListRIMIDs(ctx)
	if err != nil {
		t.Fatalf("ListRIMIDs failed: %v", err)
	}

	if len(ids) == 0 {
		t.Error("Expected non-empty RIM ID list")
	}

	t.Logf("Found %d RIM IDs", len(ids))

	// Check for expected patterns (GPUs should be present)
	hasGPU := false
	for _, id := range ids {
		if len(id) > 10 && (id[0:2] == "GH" || id[0:2] == "GB") {
			hasGPU = true
			break
		}
	}
	if !hasGPU {
		t.Log("Warning: No GPU RIMs found (expected GH100, GB100, etc.)")
	}
}

func TestRIMClient_FindRIMForFirmware_NotFound(t *testing.T) {
	client := NewRIMClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// BlueField-3 firmware that won't be found (not available until April 2025)
	_, err := client.FindRIMForFirmware(ctx, "32.47.1088")
	if err == nil {
		t.Log("Unexpectedly found RIM for BF3 firmware - this may mean BF3 CoRIMs are now available")
	} else {
		t.Logf("Expected error for BF3 firmware: %v", err)
	}
}

func TestVerifyRIMIntegrity(t *testing.T) {
	// Test with nil entry
	valid, err := VerifyRIMIntegrity(nil)
	if err == nil {
		t.Error("Expected error for nil entry")
	}
	if valid {
		t.Error("Expected invalid for nil entry")
	}

	// Test with empty entry
	entry := &RIMEntry{}
	valid, err = VerifyRIMIntegrity(entry)
	if err == nil {
		t.Error("Expected error for empty entry")
	}
	if valid {
		t.Error("Expected invalid for empty entry")
	}
}

func TestDigestAlgorithmName(t *testing.T) {
	tests := []struct {
		algID    uint64
		expected string
	}{
		{1, "SHA-256"},
		{2, "SHA-384"},
		{3, "SHA-512"},
		{7, "SHA3-256"},
		{8, "SHA3-384"},
		{9, "SHA3-512"},
		{0, "ALG-0"},
		{4, "ALG-4"},
		{5, "ALG-5"},
		{6, "ALG-6"},
		{10, "ALG-10"},
		{100, "ALG-100"},
		{255, "ALG-255"},
		{1000, "ALG-1000"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := digestAlgorithmName(tt.algID)
			if result != tt.expected {
				t.Errorf("digestAlgorithmName(%d) = %q, want %q", tt.algID, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// RIMClient GetRIM Tests with httptest Mock Server
// =============================================================================

// newTestRIMClient creates a RIMClient pointing to a test server URL.
func newTestRIMClient(baseURL string) *RIMClient {
	return &RIMClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func TestRIMClient_GetRIM_Success(t *testing.T) {
	t.Log("Testing GetRIM success response")

	// Create test RIM data
	testRIMData := []byte("test CoRIM binary data")
	testBase64 := base64.StdEncoding.EncodeToString(testRIMData)
	testHash := sha256.Sum256(testRIMData)
	testHashHex := hex.EncodeToString(testHash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Request path: %s", r.URL.Path)

		if !strings.HasSuffix(r.URL.Path, "/test-rim-id") {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RIMEntry{
			ID:          "test-rim-id",
			RIM:         testBase64,
			SHA256:      testHashHex,
			LastUpdated: "2025-01-15T10:00:00Z",
		})
	}))
	defer server.Close()

	client := newTestRIMClient(server.URL)

	t.Log("Fetching RIM entry")
	entry, err := client.GetRIM(context.Background(), "test-rim-id")
	if err != nil {
		t.Fatalf("GetRIM failed: %v", err)
	}

	t.Logf("Received entry: ID=%s, SHA256=%s", entry.ID, entry.SHA256)

	if entry.ID != "test-rim-id" {
		t.Errorf("expected ID 'test-rim-id', got %s", entry.ID)
	}
	if entry.RIM != testBase64 {
		t.Error("RIM data does not match")
	}
	if entry.SHA256 != testHashHex {
		t.Errorf("expected SHA256 %s, got %s", testHashHex, entry.SHA256)
	}
}

func TestRIMClient_GetRIM_NotFound(t *testing.T) {
	t.Log("Testing GetRIM 404 Not Found response")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Returning 404 Not Found")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "RIM not found"}`))
	}))
	defer server.Close()

	client := newTestRIMClient(server.URL)

	_, err := client.GetRIM(context.Background(), "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}

	t.Logf("Got expected error: %v", err)
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status 404: %v", err)
	}
}

func TestRIMClient_GetRIM_ServerError(t *testing.T) {
	t.Log("Testing GetRIM 500 Server Error response")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Returning 500 Internal Server Error")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal error"}`))
	}))
	defer server.Close()

	client := newTestRIMClient(server.URL)

	_, err := client.GetRIM(context.Background(), "some-id")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	t.Logf("Got expected error: %v", err)
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status 500: %v", err)
	}
}

func TestRIMClient_GetRIM_MalformedJSON(t *testing.T) {
	t.Log("Testing GetRIM with malformed JSON response")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Returning malformed JSON")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": malformed`))
	}))
	defer server.Close()

	client := newTestRIMClient(server.URL)

	_, err := client.GetRIM(context.Background(), "some-id")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}

	t.Logf("Got expected error: %v", err)
}

func TestRIMClient_ListRIMIDs_Success(t *testing.T) {
	t.Log("Testing ListRIMIDs success response")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/ids") {
			t.Errorf("unexpected path: %s, expected to end with /ids", r.URL.Path)
		}

		t.Log("Returning RIM ID list")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RIMListResponse{
			IDs: []string{"GH100_SKU1", "GB100_SKU2", "NV_NIC_BF3"},
		})
	}))
	defer server.Close()

	client := newTestRIMClient(server.URL)

	ids, err := client.ListRIMIDs(context.Background())
	if err != nil {
		t.Fatalf("ListRIMIDs failed: %v", err)
	}

	t.Logf("Got %d IDs", len(ids))
	if len(ids) != 3 {
		t.Errorf("expected 3 IDs, got %d", len(ids))
	}
}

func TestRIMClient_ListRIMIDs_ServerError(t *testing.T) {
	t.Log("Testing ListRIMIDs 500 error")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`service unavailable`))
	}))
	defer server.Close()

	client := newTestRIMClient(server.URL)

	_, err := client.ListRIMIDs(context.Background())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	t.Logf("Got expected error: %v", err)
}

// =============================================================================
// VerifyRIMIntegrity Additional Tests
// =============================================================================

func TestVerifyRIMIntegrity_ValidHash(t *testing.T) {
	t.Log("Testing VerifyRIMIntegrity with valid matching hash")

	testData := []byte("test CoRIM binary data for integrity check")
	testBase64 := base64.StdEncoding.EncodeToString(testData)
	computedHash := sha256.Sum256(testData)
	computedHashHex := hex.EncodeToString(computedHash[:])

	entry := &RIMEntry{
		ID:     "test-rim",
		RIM:    testBase64,
		SHA256: computedHashHex,
	}

	t.Logf("Testing with hash: %s", computedHashHex)
	valid, err := VerifyRIMIntegrity(entry)
	if err != nil {
		t.Fatalf("VerifyRIMIntegrity failed: %v", err)
	}

	if !valid {
		t.Error("expected valid=true for matching hash")
	}
	t.Log("Hash verification passed")
}

func TestVerifyRIMIntegrity_HashMismatch(t *testing.T) {
	t.Log("Testing VerifyRIMIntegrity with hash mismatch")

	testData := []byte("test data")
	testBase64 := base64.StdEncoding.EncodeToString(testData)
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"

	entry := &RIMEntry{
		ID:     "test-rim",
		RIM:    testBase64,
		SHA256: wrongHash,
	}

	t.Log("Testing with wrong hash")
	valid, err := VerifyRIMIntegrity(entry)
	if err != nil {
		t.Fatalf("VerifyRIMIntegrity returned error: %v", err)
	}

	if valid {
		t.Error("expected valid=false for mismatched hash")
	}
	t.Log("Hash mismatch correctly detected")
}

func TestVerifyRIMIntegrity_CaseInsensitiveHash(t *testing.T) {
	t.Log("Testing VerifyRIMIntegrity is case-insensitive for SHA256")

	testData := []byte("case insensitive test")
	testBase64 := base64.StdEncoding.EncodeToString(testData)
	computedHash := sha256.Sum256(testData)
	upperHash := strings.ToUpper(hex.EncodeToString(computedHash[:]))

	entry := &RIMEntry{
		ID:     "test-rim",
		RIM:    testBase64,
		SHA256: upperHash,
	}

	t.Logf("Testing with uppercase hash: %s", upperHash)
	valid, err := VerifyRIMIntegrity(entry)
	if err != nil {
		t.Fatalf("VerifyRIMIntegrity failed: %v", err)
	}

	if !valid {
		t.Error("expected valid=true for case-insensitive hash comparison")
	}
	t.Log("Case-insensitive comparison passed")
}

func TestVerifyRIMIntegrity_InvalidBase64(t *testing.T) {
	t.Log("Testing VerifyRIMIntegrity with invalid base64 RIM data")

	entry := &RIMEntry{
		ID:     "test-rim",
		RIM:    "!!!not-valid-base64!!!",
		SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	_, err := VerifyRIMIntegrity(entry)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}

	t.Logf("Got expected error: %v", err)
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("error should mention decoding failure: %v", err)
	}
}

func TestVerifyRIMIntegrity_EmptyRIM(t *testing.T) {
	t.Log("Testing VerifyRIMIntegrity with empty RIM field")

	entry := &RIMEntry{
		ID:     "test-rim",
		RIM:    "",
		SHA256: "some-hash",
	}

	valid, err := VerifyRIMIntegrity(entry)
	if err == nil {
		t.Fatal("expected error for empty RIM")
	}

	t.Logf("Got expected error: %v", err)
	if valid {
		t.Error("expected valid=false for empty RIM")
	}
}
