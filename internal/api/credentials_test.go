package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/store"
)

// ----- SSH CA Tests -----

// TestSSHCAListEmpty tests listing SSH CAs when none exist.
func TestSSHCAListEmpty(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/credentials/ssh-cas", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result []sshCAResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected empty list, got %d SSH CAs", len(result))
	}
}

// TestSSHCAList tests listing SSH CAs.
func TestSSHCAList(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create SSH CAs directly in the store
	err := server.store.CreateSSHCA("ca1", "production-ca", []byte("ssh-ed25519 AAAA..."), []byte("private-key-1"), "ed25519")
	if err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}
	err = server.store.CreateSSHCA("ca2", "dev-ca", []byte("ssh-ed25519 BBBB..."), []byte("private-key-2"), "ed25519")
	if err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/credentials/ssh-cas", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []sshCAResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 SSH CAs, got %d", len(result))
	}

	// Verify list does not include public key
	for _, ca := range result {
		if ca.PublicKey != "" {
			t.Errorf("list response should not include publicKey, but got: %s", ca.PublicKey)
		}
		if ca.ID == "" {
			t.Error("expected non-empty ID")
		}
		if ca.Name == "" {
			t.Error("expected non-empty Name")
		}
		if ca.KeyType == "" {
			t.Error("expected non-empty KeyType")
		}
	}
}

// TestSSHCAGet tests retrieving a specific SSH CA with public key.
func TestSSHCAGet(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create an SSH CA
	publicKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...")
	err := server.store.CreateSSHCA("ca1", "production-ca", publicKey, []byte("private-key"), "ed25519")
	if err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/credentials/ssh-cas/production-ca", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result sshCAResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Name != "production-ca" {
		t.Errorf("expected name 'production-ca', got '%s'", result.Name)
	}
	if result.KeyType != "ed25519" {
		t.Errorf("expected keyType 'ed25519', got '%s'", result.KeyType)
	}
	if result.PublicKey == "" {
		t.Error("expected publicKey in detail view, got empty string")
	}
	if result.ID != "ca1" {
		t.Errorf("expected ID 'ca1', got '%s'", result.ID)
	}
}

// TestSSHCAGet_NotFound tests retrieving a non-existent SSH CA.
func TestSSHCAGet_NotFound(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/credentials/ssh-cas/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

// TestSSHCAListWithDistributionCount tests that SSH CA list includes distribution counts.
func TestSSHCAListWithDistributionCount(t *testing.T) {
	server, mux := setupTestServer(t)

	// Create an SSH CA
	err := server.store.CreateSSHCA("ca1", "prod-ca", []byte("ssh-ed25519 AAAA..."), []byte("private-key"), "ed25519")
	if err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	// Record some distributions for this CA
	status := "healthy"
	age := 30
	path := "/etc/ssh/ca.pub"
	for i := 0; i < 3; i++ {
		d := &store.Distribution{
			DPUName:            "bf3-test",
			CredentialType:     "ssh-ca",
			CredentialName:     "prod-ca",
			Outcome:            store.DistributionOutcomeSuccess,
			AttestationStatus:  &status,
			AttestationAgeSecs: &age,
			InstalledPath:      &path,
		}
		if err := server.store.RecordDistribution(d); err != nil {
			t.Fatalf("failed to record distribution: %v", err)
		}
	}

	req := httptest.NewRequest("GET", "/api/credentials/ssh-cas", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []sshCAResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 SSH CA, got %d", len(result))
	}

	if result[0].Distributions != 3 {
		t.Errorf("expected 3 distributions, got %d", result[0].Distributions)
	}
}

// ----- Distribution History Tests -----

// TestDistributionHistoryEmpty tests listing distribution history when none exist.
func TestDistributionHistoryEmpty(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/distribution/history", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result []distributionResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected empty list, got %d distributions", len(result))
	}
}

// TestDistributionHistoryList tests listing distribution history.
func TestDistributionHistoryList(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record some distributions
	status := "healthy"
	age := 30
	path := "/etc/ssh/ca.pub"
	d := &store.Distribution{
		DPUName:            "bf3-prod-1",
		CredentialType:     "ssh-ca",
		CredentialName:     "prod-ca",
		Outcome:            store.DistributionOutcomeSuccess,
		AttestationStatus:  &status,
		AttestationAgeSecs: &age,
		InstalledPath:      &path,
	}
	if err := server.store.RecordDistribution(d); err != nil {
		t.Fatalf("failed to record distribution: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/distribution/history", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []distributionResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 distribution, got %d", len(result))
	}

	if result[0].DPUName != "bf3-prod-1" {
		t.Errorf("expected dpuName 'bf3-prod-1', got '%s'", result[0].DPUName)
	}
	if result[0].Outcome != "success" {
		t.Errorf("expected outcome 'success', got '%s'", result[0].Outcome)
	}
	if result[0].AttestationStatus == nil || *result[0].AttestationStatus != "healthy" {
		t.Errorf("expected attestationStatus 'healthy', got '%v'", result[0].AttestationStatus)
	}
	if result[0].InstalledPath == nil || *result[0].InstalledPath != "/etc/ssh/ca.pub" {
		t.Errorf("expected installedPath '/etc/ssh/ca.pub', got '%v'", result[0].InstalledPath)
	}
}

// TestDistributionHistoryFilterByTarget tests filtering by DPU name.
func TestDistributionHistoryFilterByTarget(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record distributions for different DPUs
	for _, dpu := range []string{"bf3-prod-1", "bf3-prod-2", "bf3-prod-1"} {
		d := &store.Distribution{
			DPUName:        dpu,
			CredentialType: "ssh-ca",
			CredentialName: "prod-ca",
			Outcome:        store.DistributionOutcomeSuccess,
		}
		if err := server.store.RecordDistribution(d); err != nil {
			t.Fatalf("failed to record distribution: %v", err)
		}
	}

	req := httptest.NewRequest("GET", "/api/distribution/history?target=bf3-prod-1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []distributionResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 distributions for bf3-prod-1, got %d", len(result))
	}

	for _, d := range result {
		if d.DPUName != "bf3-prod-1" {
			t.Errorf("expected dpuName 'bf3-prod-1', got '%s'", d.DPUName)
		}
	}
}

// TestDistributionHistoryFilterByOutcome tests filtering by outcome.
func TestDistributionHistoryFilterByOutcome(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record distributions with different outcomes
	outcomes := []store.DistributionOutcome{
		store.DistributionOutcomeSuccess,
		store.DistributionOutcomeBlockedStale,
		store.DistributionOutcomeSuccess,
		store.DistributionOutcomeBlockedFailed,
	}
	for _, outcome := range outcomes {
		d := &store.Distribution{
			DPUName:        "bf3-test",
			CredentialType: "ssh-ca",
			CredentialName: "test-ca",
			Outcome:        outcome,
		}
		if err := server.store.RecordDistribution(d); err != nil {
			t.Fatalf("failed to record distribution: %v", err)
		}
	}

	req := httptest.NewRequest("GET", "/api/distribution/history?result=success", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []distributionResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 success distributions, got %d", len(result))
	}

	for _, d := range result {
		if d.Outcome != "success" {
			t.Errorf("expected outcome 'success', got '%s'", d.Outcome)
		}
	}
}

// TestDistributionHistoryFilterByTimeRange tests filtering by time range.
func TestDistributionHistoryFilterByTimeRange(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record a distribution
	d := &store.Distribution{
		DPUName:        "bf3-test",
		CredentialType: "ssh-ca",
		CredentialName: "test-ca",
		Outcome:        store.DistributionOutcomeSuccess,
	}
	if err := server.store.RecordDistribution(d); err != nil {
		t.Fatalf("failed to record distribution: %v", err)
	}

	// Query with time range that includes now
	now := time.Now().UTC()
	from := now.Add(-1 * time.Hour).Format(time.RFC3339)
	to := now.Add(1 * time.Hour).Format(time.RFC3339)

	req := httptest.NewRequest("GET", "/api/distribution/history?from="+from+"&to="+to, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []distributionResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 distribution within time range, got %d", len(result))
	}

	// Query with time range that excludes the record
	oldFrom := now.Add(-2 * time.Hour).Format(time.RFC3339)
	oldTo := now.Add(-1 * time.Hour).Format(time.RFC3339)

	req = httptest.NewRequest("GET", "/api/distribution/history?from="+oldFrom+"&to="+oldTo, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 distributions outside time range, got %d", len(result))
	}
}

// TestDistributionHistoryLimit tests the limit parameter.
func TestDistributionHistoryLimit(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record 10 distributions
	for i := 0; i < 10; i++ {
		d := &store.Distribution{
			DPUName:        "bf3-test",
			CredentialType: "ssh-ca",
			CredentialName: "test-ca",
			Outcome:        store.DistributionOutcomeSuccess,
		}
		if err := server.store.RecordDistribution(d); err != nil {
			t.Fatalf("failed to record distribution: %v", err)
		}
	}

	req := httptest.NewRequest("GET", "/api/distribution/history?limit=5", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []distributionResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 5 {
		t.Errorf("expected 5 distributions with limit=5, got %d", len(result))
	}
}

// TestDistributionHistoryInvalidTimeFormat tests invalid time format handling.
func TestDistributionHistoryInvalidTimeFormat(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/distribution/history?from=invalid-time", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestDistributionHistoryInvalidResultFilter tests invalid result filter handling.
func TestDistributionHistoryInvalidResultFilter(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/distribution/history?result=invalid-outcome", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestDistributionHistoryBlockedWithError tests distributions with error messages.
func TestDistributionHistoryBlockedWithError(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record a blocked distribution with error
	status := "stale"
	age := 3600
	errMsg := "Attestation too old: 3600 seconds (max: 300)"
	d := &store.Distribution{
		DPUName:            "bf3-test",
		CredentialType:     "ssh-ca",
		CredentialName:     "test-ca",
		Outcome:            store.DistributionOutcomeBlockedStale,
		AttestationStatus:  &status,
		AttestationAgeSecs: &age,
		ErrorMessage:       &errMsg,
	}
	if err := server.store.RecordDistribution(d); err != nil {
		t.Fatalf("failed to record distribution: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/distribution/history", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []distributionResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 distribution, got %d", len(result))
	}

	if result[0].Outcome != "blocked-stale" {
		t.Errorf("expected outcome 'blocked-stale', got '%s'", result[0].Outcome)
	}
	if result[0].ErrorMessage == nil {
		t.Error("expected error message, got nil")
	} else if *result[0].ErrorMessage != errMsg {
		t.Errorf("expected error '%s', got '%s'", errMsg, *result[0].ErrorMessage)
	}
	if result[0].AttestationAge == nil || *result[0].AttestationAge != 3600 {
		t.Errorf("expected attestationAgeSeconds 3600, got %v", result[0].AttestationAge)
	}
	if result[0].InstalledPath != nil {
		t.Errorf("expected nil installedPath for blocked distribution, got '%s'", *result[0].InstalledPath)
	}
}
