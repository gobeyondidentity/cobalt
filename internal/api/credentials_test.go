package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/store"
)

// ----- SSH CA Tests -----

// TestSSHCAListEmpty tests listing SSH CAs when none exist.
func TestSSHCAListEmpty(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/credentials/ssh-cas", nil)
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
	err := server.store.CreateSSHCA("ca1", "production-ca", []byte("ssh-ed25519 AAAA..."), []byte("private-key-1"), "ed25519", nil)
	if err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}
	err = server.store.CreateSSHCA("ca2", "dev-ca", []byte("ssh-ed25519 BBBB..."), []byte("private-key-2"), "ed25519", nil)
	if err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/credentials/ssh-cas", nil)
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
	err := server.store.CreateSSHCA("ca1", "production-ca", publicKey, []byte("private-key"), "ed25519", nil)
	if err != nil {
		t.Fatalf("failed to create SSH CA: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/credentials/ssh-cas/production-ca", nil)
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

	req := httptest.NewRequest("GET", "/api/v1/credentials/ssh-cas/nonexistent", nil)
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
	err := server.store.CreateSSHCA("ca1", "prod-ca", []byte("ssh-ed25519 AAAA..."), []byte("private-key"), "ed25519", nil)
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

	req := httptest.NewRequest("GET", "/api/v1/credentials/ssh-cas", nil)
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

	req := httptest.NewRequest("GET", "/api/v1/distribution/history", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result []DistributionHistoryEntry
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
		OperatorID:         "op-123",
		OperatorEmail:      "nelson@acme.com",
		TenantID:           "tenant-1",
	}
	if err := server.store.RecordDistribution(d); err != nil {
		t.Fatalf("failed to record distribution: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/distribution/history", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 distribution, got %d", len(result))
	}

	if result[0].Target != "bf3-prod-1" {
		t.Errorf("expected target 'bf3-prod-1', got '%s'", result[0].Target)
	}
	if result[0].Outcome != "success" {
		t.Errorf("expected outcome 'success', got '%s'", result[0].Outcome)
	}
	if result[0].AttestationStatus != "healthy" {
		t.Errorf("expected attestation_status 'healthy', got '%s'", result[0].AttestationStatus)
	}
	if result[0].AttestationAge != "30s" {
		t.Errorf("expected attestation_age '30s', got '%s'", result[0].AttestationAge)
	}
	if result[0].OperatorID != "op-123" {
		t.Errorf("expected operator_id 'op-123', got '%s'", result[0].OperatorID)
	}
	if result[0].OperatorEmail != "nelson@acme.com" {
		t.Errorf("expected operator_email 'nelson@acme.com', got '%s'", result[0].OperatorEmail)
	}
	if result[0].TenantID != "tenant-1" {
		t.Errorf("expected tenant_id 'tenant-1', got '%s'", result[0].TenantID)
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

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?target=bf3-prod-1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 distributions for bf3-prod-1, got %d", len(result))
	}

	for _, d := range result {
		if d.Target != "bf3-prod-1" {
			t.Errorf("expected target 'bf3-prod-1', got '%s'", d.Target)
		}
	}
}

// TestDistributionHistoryFilterByOperator tests filtering by operator email.
func TestDistributionHistoryFilterByOperator(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record distributions with different operators
	operators := []string{"nelson@acme.com", "alice@acme.com", "nelson@acme.com"}
	for _, op := range operators {
		d := &store.Distribution{
			DPUName:        "bf3-test",
			CredentialType: "ssh-ca",
			CredentialName: "test-ca",
			Outcome:        store.DistributionOutcomeSuccess,
			OperatorID:     "op-" + op[:3],
			OperatorEmail:  op,
		}
		if err := server.store.RecordDistribution(d); err != nil {
			t.Fatalf("failed to record distribution: %v", err)
		}
	}

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?operator=nelson@acme.com", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 distributions for nelson@acme.com, got %d", len(result))
	}

	for _, d := range result {
		if d.OperatorEmail != "nelson@acme.com" {
			t.Errorf("expected operator_email 'nelson@acme.com', got '%s'", d.OperatorEmail)
		}
	}
}

// TestDistributionHistoryFilterByTenant tests filtering by tenant ID.
func TestDistributionHistoryFilterByTenant(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record distributions with different tenants
	tenants := []string{"tenant-a", "tenant-b", "tenant-a"}
	for _, tenant := range tenants {
		d := &store.Distribution{
			DPUName:        "bf3-test",
			CredentialType: "ssh-ca",
			CredentialName: "test-ca",
			Outcome:        store.DistributionOutcomeSuccess,
			TenantID:       tenant,
		}
		if err := server.store.RecordDistribution(d); err != nil {
			t.Fatalf("failed to record distribution: %v", err)
		}
	}

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?tenant=tenant-a", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 distributions for tenant-a, got %d", len(result))
	}

	for _, d := range result {
		if d.TenantID != "tenant-a" {
			t.Errorf("expected tenant_id 'tenant-a', got '%s'", d.TenantID)
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

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?result=success", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
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

// TestDistributionHistoryFilterByBlockedOutcome tests filtering by 'blocked' shorthand.
func TestDistributionHistoryFilterByBlockedOutcome(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record distributions with different outcomes
	outcomes := []store.DistributionOutcome{
		store.DistributionOutcomeSuccess,
		store.DistributionOutcomeBlockedStale,
		store.DistributionOutcomeSuccess,
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

	// 'blocked' should match 'blocked-stale'
	req := httptest.NewRequest("GET", "/api/v1/distribution/history?result=blocked", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 blocked distribution, got %d", len(result))
	}

	if result[0].Outcome != "blocked-stale" {
		t.Errorf("expected outcome 'blocked-stale', got '%s'", result[0].Outcome)
	}
}

// TestDistributionHistoryFilterByTimeRange tests filtering by time range with RFC3339.
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

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?from="+from+"&to="+to, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 distribution within time range, got %d", len(result))
	}

	// Query with time range that excludes the record
	oldFrom := now.Add(-2 * time.Hour).Format(time.RFC3339)
	oldTo := now.Add(-1 * time.Hour).Format(time.RFC3339)

	req = httptest.NewRequest("GET", "/api/v1/distribution/history?from="+oldFrom+"&to="+oldTo, nil)
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

// TestDistributionHistoryFilterByDateFormat tests filtering with YYYY-MM-DD format.
func TestDistributionHistoryFilterByDateFormat(t *testing.T) {
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

	// Query with today's date
	today := time.Now().Format("2006-01-02")
	req := httptest.NewRequest("GET", "/api/v1/distribution/history?from="+today+"&to="+today, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 distribution within today's date range, got %d", len(result))
	}

	// Query with yesterday's date (should exclude today's record)
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	req = httptest.NewRequest("GET", "/api/v1/distribution/history?from="+yesterday+"&to="+yesterday, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 distributions for yesterday, got %d", len(result))
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

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?limit=5", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 5 {
		t.Errorf("expected 5 distributions with limit=5, got %d", len(result))
	}
}

// TestDistributionHistoryMultipleFilters tests combining multiple filters.
func TestDistributionHistoryMultipleFilters(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record distributions with various attributes
	distributions := []struct {
		target   string
		operator string
		outcome  store.DistributionOutcome
	}{
		{"bf3-1", "nelson@acme.com", store.DistributionOutcomeSuccess},
		{"bf3-1", "alice@acme.com", store.DistributionOutcomeSuccess},
		{"bf3-2", "nelson@acme.com", store.DistributionOutcomeSuccess},
		{"bf3-1", "nelson@acme.com", store.DistributionOutcomeBlockedStale},
	}

	for _, dist := range distributions {
		d := &store.Distribution{
			DPUName:        dist.target,
			CredentialType: "ssh-ca",
			CredentialName: "test-ca",
			Outcome:        dist.outcome,
			OperatorID:     "op-" + dist.operator[:3],
			OperatorEmail:  dist.operator,
		}
		if err := server.store.RecordDistribution(d); err != nil {
			t.Fatalf("failed to record distribution: %v", err)
		}
	}

	// Filter by operator AND result AND limit
	req := httptest.NewRequest("GET", "/api/v1/distribution/history?operator=nelson@acme.com&result=success&limit=50", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Should match: bf3-1/nelson/success and bf3-2/nelson/success
	if len(result) != 2 {
		t.Errorf("expected 2 distributions matching filters, got %d", len(result))
	}

	for _, d := range result {
		if d.OperatorEmail != "nelson@acme.com" {
			t.Errorf("expected operator 'nelson@acme.com', got '%s'", d.OperatorEmail)
		}
		if d.Outcome != "success" {
			t.Errorf("expected outcome 'success', got '%s'", d.Outcome)
		}
	}
}

// TestDistributionHistoryInvalidTimeFormat tests invalid time format handling.
func TestDistributionHistoryInvalidTimeFormat(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?from=invalid-time", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestDistributionHistoryInvalidResultFilter tests invalid result filter handling.
func TestDistributionHistoryInvalidResultFilter(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?result=invalid-outcome", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestDistributionHistoryBlockedWithReason tests distributions with blocked reason.
func TestDistributionHistoryBlockedWithReason(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record a blocked distribution with reason
	status := "stale"
	age := 3600
	blockedReason := "Attestation too old: 3600 seconds (max: 300)"
	d := &store.Distribution{
		DPUName:            "bf3-test",
		CredentialType:     "ssh-ca",
		CredentialName:     "test-ca",
		Outcome:            store.DistributionOutcomeBlockedStale,
		AttestationStatus:  &status,
		AttestationAgeSecs: &age,
		BlockedReason:      &blockedReason,
	}
	if err := server.store.RecordDistribution(d); err != nil {
		t.Fatalf("failed to record distribution: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/distribution/history", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 distribution, got %d", len(result))
	}

	if result[0].Outcome != "blocked-stale" {
		t.Errorf("expected outcome 'blocked-stale', got '%s'", result[0].Outcome)
	}
	if result[0].BlockedReason == nil {
		t.Error("expected blocked_reason, got nil")
	} else if *result[0].BlockedReason != blockedReason {
		t.Errorf("expected blocked_reason '%s', got '%s'", blockedReason, *result[0].BlockedReason)
	}
	if result[0].AttestationAge != "1h" {
		t.Errorf("expected attestation_age '1h', got '%s'", result[0].AttestationAge)
	}
}

// TestDistributionHistoryForcedWithBy tests forced distributions with ForcedBy field.
func TestDistributionHistoryForcedWithBy(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record a forced distribution
	status := "stale"
	age := 7200
	forcedBy := "admin@acme.com"
	d := &store.Distribution{
		DPUName:            "bf3-test",
		CredentialType:     "ssh-ca",
		CredentialName:     "test-ca",
		Outcome:            store.DistributionOutcomeForced,
		AttestationStatus:  &status,
		AttestationAgeSecs: &age,
		OperatorID:         "op-123",
		OperatorEmail:      "nelson@acme.com",
		ForcedBy:           &forcedBy,
	}
	if err := server.store.RecordDistribution(d); err != nil {
		t.Fatalf("failed to record distribution: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/distribution/history?result=forced", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result []DistributionHistoryEntry
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 forced distribution, got %d", len(result))
	}

	if result[0].Outcome != "forced" {
		t.Errorf("expected outcome 'forced', got '%s'", result[0].Outcome)
	}
	if result[0].ForcedBy == nil {
		t.Error("expected forced_by, got nil")
	} else if *result[0].ForcedBy != forcedBy {
		t.Errorf("expected forced_by '%s', got '%s'", forcedBy, *result[0].ForcedBy)
	}
	if result[0].AttestationAge != "2h" {
		t.Errorf("expected attestation_age '2h', got '%s'", result[0].AttestationAge)
	}
}

// TestDistributionHistoryVerboseMode tests verbose mode includes attestation snapshot.
func TestDistributionHistoryVerboseMode(t *testing.T) {
	server, mux := setupTestServer(t)

	// Record a distribution with attestation snapshot
	status := "healthy"
	snapshot := `{"pcr0":"abc123","pcr1":"def456"}`
	d := &store.Distribution{
		DPUName:             "bf3-test",
		CredentialType:      "ssh-ca",
		CredentialName:      "test-ca",
		Outcome:             store.DistributionOutcomeSuccess,
		AttestationStatus:   &status,
		AttestationSnapshot: &snapshot,
	}
	if err := server.store.RecordDistribution(d); err != nil {
		t.Fatalf("failed to record distribution: %v", err)
	}

	// Without verbose, snapshot should be nil
	req := httptest.NewRequest("GET", "/api/v1/distribution/history", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result []DistributionHistoryEntry
	json.NewDecoder(w.Body).Decode(&result)

	if result[0].AttestationSnapshot != nil {
		t.Errorf("expected nil attestation_snapshot without verbose, got '%s'", *result[0].AttestationSnapshot)
	}

	// With verbose, snapshot should be present
	req = httptest.NewRequest("GET", "/api/v1/distribution/history?verbose=true", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&result)

	if result[0].AttestationSnapshot == nil {
		t.Error("expected attestation_snapshot with verbose=true, got nil")
	} else if *result[0].AttestationSnapshot != snapshot {
		t.Errorf("expected attestation_snapshot '%s', got '%s'", snapshot, *result[0].AttestationSnapshot)
	}
}

// TestFormatHumanDuration tests the human-readable duration formatting.
func TestFormatHumanDuration(t *testing.T) {
	tests := []struct {
		seconds  int
		expected string
	}{
		{30, "30s"},
		{59, "59s"},
		{60, "1m"},
		{300, "5m"},
		{3599, "59m"},
		{3600, "1h"},
		{7200, "2h"},
		{86399, "23h"},
		{86400, "1d"},
		{172800, "2d"},
		{604799, "6d"},
		{604800, "1w"},
		{1209600, "2w"},
	}

	for _, tt := range tests {
		result := formatHumanDuration(tt.seconds)
		if result != tt.expected {
			t.Errorf("formatHumanDuration(%d) = %s, want %s", tt.seconds, result, tt.expected)
		}
	}
}

// TestParseFlexibleTime tests the flexible time parsing.
func TestParseFlexibleTime(t *testing.T) {
	// Test RFC3339 format (preserves UTC)
	rfc3339Str := "2026-01-15T10:30:00Z"
	result, err := parseFlexibleTime(rfc3339Str, false)
	if err != nil {
		t.Errorf("parseFlexibleTime(%s) error: %v", rfc3339Str, err)
	}
	if result.UTC().Hour() != 10 || result.UTC().Minute() != 30 {
		t.Errorf("parseFlexibleTime(%s) = %v, expected 10:30 UTC", rfc3339Str, result)
	}

	// Test YYYY-MM-DD format (start of day, local time)
	dateStr := "2026-01-15"
	result, err = parseFlexibleTime(dateStr, false)
	if err != nil {
		t.Errorf("parseFlexibleTime(%s) error: %v", dateStr, err)
	}
	// Should be midnight in local timezone
	if result.Hour() != 0 || result.Minute() != 0 || result.Second() != 0 {
		t.Errorf("parseFlexibleTime(%s, false) = %v, expected 00:00:00", dateStr, result)
	}
	if result.Year() != 2026 || result.Month() != 1 || result.Day() != 15 {
		t.Errorf("parseFlexibleTime(%s, false) date = %v, expected 2026-01-15", dateStr, result)
	}

	// Test YYYY-MM-DD format (end of day, local time)
	result, err = parseFlexibleTime(dateStr, true)
	if err != nil {
		t.Errorf("parseFlexibleTime(%s, true) error: %v", dateStr, err)
	}
	// Should be 23:59:59 in local timezone
	if result.Hour() != 23 || result.Minute() != 59 || result.Second() != 59 {
		t.Errorf("parseFlexibleTime(%s, true) = %v, expected 23:59:59", dateStr, result)
	}

	// Test invalid format
	_, err = parseFlexibleTime("invalid-date", false)
	if err == nil {
		t.Error("parseFlexibleTime(invalid-date) expected error, got nil")
	}
}

// TestMapOutcomeFilter tests the outcome filter mapping.
func TestMapOutcomeFilter(t *testing.T) {
	tests := []struct {
		input    string
		expected *store.DistributionOutcome
	}{
		{"success", ptr(store.DistributionOutcomeSuccess)},
		{"SUCCESS", ptr(store.DistributionOutcomeSuccess)},
		{"blocked", ptr(store.DistributionOutcomeBlockedStale)},
		{"blocked-stale", ptr(store.DistributionOutcomeBlockedStale)},
		{"blocked-failed", ptr(store.DistributionOutcomeBlockedFailed)},
		{"forced", ptr(store.DistributionOutcomeForced)},
		{"invalid", nil},
	}

	for _, tt := range tests {
		result := mapOutcomeFilter(tt.input)
		if tt.expected == nil {
			if result != nil {
				t.Errorf("mapOutcomeFilter(%s) = %v, want nil", tt.input, *result)
			}
		} else {
			if result == nil {
				t.Errorf("mapOutcomeFilter(%s) = nil, want %v", tt.input, *tt.expected)
			} else if *result != *tt.expected {
				t.Errorf("mapOutcomeFilter(%s) = %v, want %v", tt.input, *result, *tt.expected)
			}
		}
	}
}

// ptr returns a pointer to the given value.
func ptr(o store.DistributionOutcome) *store.DistributionOutcome {
	return &o
}
