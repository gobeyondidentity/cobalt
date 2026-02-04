package attestation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/gobeyondidentity/cobalt/gen/go/agent/v1"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// mockAttestationClient implements AttestationClient for testing.
type mockAttestationClient struct {
	resp        *agentv1.GetAttestationResponse
	err         error
	closeCalled bool
}

func (m *mockAttestationClient) GetAttestation(ctx context.Context, target string) (*agentv1.GetAttestationResponse, error) {
	return m.resp, m.err
}

func (m *mockAttestationClient) Close() error {
	m.closeCalled = true
	return nil
}

// mockClientFactory creates a factory that returns the provided mock client or error.
func mockClientFactory(client *mockAttestationClient, factoryErr error) AttestationClientFactory {
	return func(address string) (AttestationClient, error) {
		if factoryErr != nil {
			return nil, factoryErr
		}
		return client, nil
	}
}

// setupRefresherTestStore creates a temporary SQLite store for testing.
func setupRefresherTestStore(t *testing.T) (*store.Store, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "attestation-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open store: %v", err)
	}

	cleanup := func() {
		s.Close()
		os.RemoveAll(tmpDir)
	}

	return s, cleanup
}

func TestRefresher_ConnectionError(t *testing.T) {
	t.Log("Testing that connection errors are handled correctly")

	s, cleanup := setupRefresherTestStore(t)
	defer cleanup()

	refresher := NewRefresher(s).WithClientFactory(
		mockClientFactory(nil, errors.New("connection refused")),
	)

	t.Log("Calling Refresh with a factory that returns connection error")
	result := refresher.Refresh(context.Background(), "192.168.1.100:18051", "test-dpu", "test", "operator@test.com")

	t.Logf("Result: Success=%v, Error=%v, Message=%s", result.Success, result.Error, result.Message)

	if result.Success {
		t.Error("expected Success to be false for connection error")
	}
	if result.Error == nil {
		t.Error("expected Error to be set for connection error")
	}
	if !strings.Contains(result.Message, "connection failed") {
		t.Errorf("expected message to contain 'connection failed', got: %s", result.Message)
	}
	if result.Attestation != nil {
		t.Error("expected no Attestation saved for connection error")
	}
}

func TestRefresher_AttestationError(t *testing.T) {
	t.Log("Testing that GetAttestation RPC errors are handled correctly")

	s, cleanup := setupRefresherTestStore(t)
	defer cleanup()

	mockClient := &mockAttestationClient{
		err: errors.New("attestation RPC failed"),
	}
	refresher := NewRefresher(s).WithClientFactory(
		mockClientFactory(mockClient, nil),
	)

	t.Log("Calling Refresh with a client that returns GetAttestation error")
	result := refresher.Refresh(context.Background(), "192.168.1.100:18051", "test-dpu", "test", "operator@test.com")

	t.Logf("Result: Success=%v, Error=%v, Message=%s", result.Success, result.Error, result.Message)

	if result.Success {
		t.Error("expected Success to be false for attestation error")
	}
	if result.Error == nil {
		t.Error("expected Error to be set")
	}
	if !strings.Contains(result.Message, "attestation failed") {
		t.Errorf("expected message to contain 'attestation failed', got: %s", result.Message)
	}
	// Attestation should be saved with failed status
	if result.Attestation == nil {
		t.Error("expected Attestation to be saved even on failure")
	} else if result.Attestation.Status != store.AttestationStatusFailed {
		t.Errorf("expected status %s, got %s", store.AttestationStatusFailed, result.Attestation.Status)
	}

	// Verify client was closed
	if !mockClient.closeCalled {
		t.Error("expected Close() to be called on client")
	}
}

func TestRefresher_NoCertificates(t *testing.T) {
	t.Log("Testing that empty certificate response is handled correctly")

	s, cleanup := setupRefresherTestStore(t)
	defer cleanup()

	mockClient := &mockAttestationClient{
		resp: &agentv1.GetAttestationResponse{
			Certificates: []*agentv1.Certificate{}, // Empty
			Status:       agentv1.AttestationStatus_ATTESTATION_STATUS_VALID,
		},
	}
	refresher := NewRefresher(s).WithClientFactory(
		mockClientFactory(mockClient, nil),
	)

	t.Log("Calling Refresh with empty certificates response")
	result := refresher.Refresh(context.Background(), "192.168.1.100:18051", "test-dpu", "test", "operator@test.com")

	t.Logf("Result: Success=%v, Error=%v, Message=%s", result.Success, result.Error, result.Message)

	if result.Success {
		t.Error("expected Success to be false for no certificates")
	}
	if result.Error == nil {
		t.Error("expected Error to be set")
	}
	if !strings.Contains(result.Message, "no certificates") {
		t.Errorf("expected message to contain 'no certificates', got: %s", result.Message)
	}
	if result.Attestation == nil {
		t.Error("expected Attestation to be saved with unavailable status")
	} else if result.Attestation.Status != store.AttestationStatusUnavailable {
		t.Errorf("expected status %s, got %s", store.AttestationStatusUnavailable, result.Attestation.Status)
	}
}

func TestRefresher_InvalidStatus(t *testing.T) {
	t.Log("Testing that invalid attestation status is handled correctly")

	s, cleanup := setupRefresherTestStore(t)
	defer cleanup()

	mockClient := &mockAttestationClient{
		resp: &agentv1.GetAttestationResponse{
			Certificates: []*agentv1.Certificate{
				{Level: 0, Subject: "test", Pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
			},
			Status: agentv1.AttestationStatus_ATTESTATION_STATUS_INVALID,
		},
	}
	refresher := NewRefresher(s).WithClientFactory(
		mockClientFactory(mockClient, nil),
	)

	t.Log("Calling Refresh with INVALID attestation status")
	result := refresher.Refresh(context.Background(), "192.168.1.100:18051", "test-dpu", "test", "operator@test.com")

	t.Logf("Result: Success=%v, Error=%v, Message=%s", result.Success, result.Error, result.Message)

	if result.Success {
		t.Error("expected Success to be false for invalid status")
	}
	if result.Error == nil {
		t.Error("expected Error to be set")
	}
	if !strings.Contains(result.Error.Error(), "INVALID") {
		t.Errorf("expected error to mention INVALID status, got: %v", result.Error)
	}
	if result.Attestation == nil {
		t.Error("expected Attestation to be saved")
	} else if result.Attestation.Status != store.AttestationStatusFailed {
		t.Errorf("expected status %s, got %s", store.AttestationStatusFailed, result.Attestation.Status)
	}
}

func TestRefresher_Success(t *testing.T) {
	t.Log("Testing successful attestation refresh")

	s, cleanup := setupRefresherTestStore(t)
	defer cleanup()

	testPEM1 := "-----BEGIN CERTIFICATE-----\nMIIBtest1\n-----END CERTIFICATE-----"
	testPEM2 := "-----BEGIN CERTIFICATE-----\nMIIBtest2\n-----END CERTIFICATE-----"

	mockClient := &mockAttestationClient{
		resp: &agentv1.GetAttestationResponse{
			Certificates: []*agentv1.Certificate{
				{Level: 0, Subject: "CN=Leaf", Pem: testPEM1},
				{Level: 1, Subject: "CN=Root", Pem: testPEM2},
			},
			Measurements: map[string]string{
				"1": "abc123",
				"2": "def456",
			},
			Status: agentv1.AttestationStatus_ATTESTATION_STATUS_VALID,
		},
	}
	refresher := NewRefresher(s).WithClientFactory(
		mockClientFactory(mockClient, nil),
	)

	t.Log("Calling Refresh with valid attestation response")
	result := refresher.Refresh(context.Background(), "192.168.1.100:18051", "test-dpu", "auto:distribution", "operator@test.com")

	t.Logf("Result: Success=%v, Message=%s", result.Success, result.Message)

	if !result.Success {
		t.Errorf("expected Success to be true, got error: %v", result.Error)
	}
	if result.Error != nil {
		t.Errorf("expected no error, got: %v", result.Error)
	}
	if result.Message != "attestation verified" {
		t.Errorf("expected message 'attestation verified', got: %s", result.Message)
	}
	if result.Attestation == nil {
		t.Fatal("expected Attestation to be set")
	}

	t.Logf("Attestation: DPUName=%s, Status=%s, DICEHash=%s, MeasHash=%s",
		result.Attestation.DPUName, result.Attestation.Status,
		result.Attestation.DICEChainHash, result.Attestation.MeasurementsHash)

	if result.Attestation.Status != store.AttestationStatusVerified {
		t.Errorf("expected status %s, got %s", store.AttestationStatusVerified, result.Attestation.Status)
	}
	if result.Attestation.DPUName != "test-dpu" {
		t.Errorf("expected DPUName 'test-dpu', got %s", result.Attestation.DPUName)
	}
	// DICE hash should be computed from certificate PEMs
	if result.Attestation.DICEChainHash == "" {
		t.Error("expected DICEChainHash to be computed")
	}
	// Measurements hash should be computed from measurements
	if result.Attestation.MeasurementsHash == "" {
		t.Error("expected MeasurementsHash to be computed")
	}

	// Verify raw data contains expected fields
	if result.Attestation.RawData == nil {
		t.Error("expected RawData to be set")
	} else {
		if result.Attestation.RawData["trigger"] != "auto:distribution" {
			t.Errorf("expected trigger 'auto:distribution', got %v", result.Attestation.RawData["trigger"])
		}
		if result.Attestation.RawData["triggered_by"] != "operator@test.com" {
			t.Errorf("expected triggered_by 'operator@test.com', got %v", result.Attestation.RawData["triggered_by"])
		}
		if result.Attestation.RawData["certificates"].(int) != 2 {
			t.Errorf("expected certificates count 2, got %v", result.Attestation.RawData["certificates"])
		}
	}

	// Verify client was closed
	if !mockClient.closeCalled {
		t.Error("expected Close() to be called on client")
	}

	// Verify attestation was persisted to store
	t.Log("Verifying attestation was persisted to store")
	stored, err := s.GetAttestation("test-dpu")
	if err != nil {
		t.Fatalf("failed to get stored attestation: %v", err)
	}
	if stored.Status != store.AttestationStatusVerified {
		t.Errorf("stored status should be %s, got %s", store.AttestationStatusVerified, stored.Status)
	}
}

func TestRefresher_SuccessNilMeasurements(t *testing.T) {
	t.Log("Testing successful attestation without measurements")

	s, cleanup := setupRefresherTestStore(t)
	defer cleanup()

	mockClient := &mockAttestationClient{
		resp: &agentv1.GetAttestationResponse{
			Certificates: []*agentv1.Certificate{
				{Level: 0, Subject: "CN=Test", Pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
			},
			Measurements: nil, // No measurements
			Status:       agentv1.AttestationStatus_ATTESTATION_STATUS_VALID,
		},
	}
	refresher := NewRefresher(s).WithClientFactory(
		mockClientFactory(mockClient, nil),
	)

	t.Log("Calling Refresh with valid response but no measurements")
	result := refresher.Refresh(context.Background(), "192.168.1.100:18051", "test-dpu", "test", "operator@test.com")

	t.Logf("Result: Success=%v, MeasHash=%s", result.Success, result.Attestation.MeasurementsHash)

	if !result.Success {
		t.Errorf("expected Success to be true, got error: %v", result.Error)
	}
	if result.Attestation.MeasurementsHash != "" {
		t.Errorf("expected empty MeasurementsHash for nil measurements, got: %s", result.Attestation.MeasurementsHash)
	}
	if result.Attestation.DICEChainHash == "" {
		t.Error("expected DICEChainHash to be computed")
	}
}

func TestRefresher_ClientClosed(t *testing.T) {
	t.Log("Testing that client Close() is called on all code paths")

	testCases := []struct {
		name   string
		client *mockAttestationClient
	}{
		{
			name: "on success",
			client: &mockAttestationClient{
				resp: &agentv1.GetAttestationResponse{
					Certificates: []*agentv1.Certificate{{Pem: "test"}},
					Status:       agentv1.AttestationStatus_ATTESTATION_STATUS_VALID,
				},
			},
		},
		{
			name: "on RPC error",
			client: &mockAttestationClient{
				err: errors.New("RPC failed"),
			},
		},
		{
			name: "on no certificates",
			client: &mockAttestationClient{
				resp: &agentv1.GetAttestationResponse{
					Certificates: []*agentv1.Certificate{},
					Status:       agentv1.AttestationStatus_ATTESTATION_STATUS_VALID,
				},
			},
		},
		{
			name: "on invalid status",
			client: &mockAttestationClient{
				resp: &agentv1.GetAttestationResponse{
					Certificates: []*agentv1.Certificate{{Pem: "test"}},
					Status:       agentv1.AttestationStatus_ATTESTATION_STATUS_INVALID,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s, cleanup := setupRefresherTestStore(t)
			defer cleanup()

			refresher := NewRefresher(s).WithClientFactory(
				mockClientFactory(tc.client, nil),
			)

			t.Logf("Testing Close() is called %s", tc.name)
			refresher.Refresh(context.Background(), "192.168.1.100:18051", "test-dpu", "test", "op@test.com")

			if !tc.client.closeCalled {
				t.Errorf("Close() was not called %s", tc.name)
			}
		})
	}
}

func TestRefresher_DefaultTimeout(t *testing.T) {
	t.Log("Testing that default timeout is set correctly")

	s, cleanup := setupRefresherTestStore(t)
	defer cleanup()

	refresher := NewRefresher(s)

	if refresher.Timeout != DefaultRefreshTimeout {
		t.Errorf("expected default timeout %v, got %v", DefaultRefreshTimeout, refresher.Timeout)
	}
	t.Logf("Default timeout correctly set to %v", refresher.Timeout)
}
