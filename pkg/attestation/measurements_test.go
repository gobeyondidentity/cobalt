package attestation

import (
	"strings"
	"testing"
)

func TestParseSPDMMeasurements(t *testing.T) {
	// Test with empty data
	_, err := ParseSPDMMeasurements("", "TPM_ALG_SHA_512")
	if err == nil {
		t.Error("Expected error for empty data")
	}

	// Test with invalid base64
	_, err = ParseSPDMMeasurements("not-valid-base64!!!", "TPM_ALG_SHA_512")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestValidateMeasurements(t *testing.T) {
	// Test with empty inputs
	result := ValidateMeasurements(nil, nil)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if !result.Valid {
		t.Error("Empty comparison should be valid")
	}
	if result.TotalChecked != 0 {
		t.Errorf("Expected 0 checked, got %d", result.TotalChecked)
	}

	// Test with matching measurements
	live := []SPDMMeasurement{
		{Index: 2, Description: "PSC firmware hash", Algorithm: "SHA2-512", Digest: "abc123"},
		{Index: 3, Description: "NIC firmware hash", Algorithm: "SHA2-512", Digest: "def456"},
	}
	ref := []CoRIMMeasurement{
		{Index: 2, Description: "PSC Firmware", Algorithm: "SHA2-512", Digest: "abc123"},
		{Index: 3, Description: "NIC Firmware", Algorithm: "SHA2-512", Digest: "def456"},
	}

	result = ValidateMeasurements(live, ref)
	if !result.Valid {
		t.Error("Expected valid result for matching measurements")
	}
	if result.Matched != 2 {
		t.Errorf("Expected 2 matched, got %d", result.Matched)
	}
	if result.Mismatched != 0 {
		t.Errorf("Expected 0 mismatched, got %d", result.Mismatched)
	}

	// Test with mismatched measurements
	live[1].Digest = "different"
	result = ValidateMeasurements(live, ref)
	if result.Valid {
		t.Error("Expected invalid result for mismatched measurements")
	}
	if result.Mismatched != 1 {
		t.Errorf("Expected 1 mismatched, got %d", result.Mismatched)
	}

	// Test with missing reference
	live = append(live, SPDMMeasurement{Index: 4, Description: "ARM firmware", Digest: "ghi789"})
	result = ValidateMeasurements(live, ref)
	if result.MissingRef != 1 {
		t.Errorf("Expected 1 missing ref, got %d", result.MissingRef)
	}
}

func TestMeasurementDescriptions(t *testing.T) {
	// Verify key measurement indices have descriptions
	expectedIndices := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

	for _, idx := range expectedIndices {
		desc, exists := BlueField3MeasurementDescriptions[idx]
		if !exists {
			t.Errorf("Missing description for index %d", idx)
		}
		if desc == "" {
			t.Errorf("Empty description for index %d", idx)
		}
	}

	// Verify specific descriptions
	if desc := BlueField3MeasurementDescriptions[2]; !strings.Contains(desc, "PSC") {
		t.Errorf("Index 2 should be PSC firmware, got %q", desc)
	}
	if desc := BlueField3MeasurementDescriptions[3]; !strings.Contains(desc, "NIC") {
		t.Errorf("Index 3 should be NIC firmware, got %q", desc)
	}
}

func TestGetHashSize(t *testing.T) {
	tests := []struct {
		alg  string
		size int
	}{
		{"SHA-256", 32},
		{"TPM_ALG_SHA_256", 32},
		{"SHA-384", 48},
		{"TPM_ALG_SHA_384", 48},
		{"SHA-512", 64},
		{"TPM_ALG_SHA_512", 64},
		{"unknown", 0},
	}

	for _, tt := range tests {
		got := getHashSize(tt.alg)
		if got != tt.size {
			t.Errorf("getHashSize(%q) = %d, want %d", tt.alg, got, tt.size)
		}
	}
}
