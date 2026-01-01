package store

import (
	"os"
	"testing"
	"time"
)

func TestAttestationCRUD(t *testing.T) {
	// Create temp database
	tmpFile, err := os.CreateTemp("", "attestation_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	store, err := Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	t.Run("SaveAttestation_New", func(t *testing.T) {
		att := &Attestation{
			DPUName:          "bf3-lab-01",
			Status:           AttestationStatusVerified,
			LastValidated:    time.Now(),
			DICEChainHash:    "abc123",
			MeasurementsHash: "def456",
			RawData:          map[string]any{"key": "value"},
		}

		err := store.SaveAttestation(att)
		if err != nil {
			t.Fatalf("SaveAttestation failed: %v", err)
		}
	})

	t.Run("GetAttestation", func(t *testing.T) {
		att, err := store.GetAttestation("bf3-lab-01")
		if err != nil {
			t.Fatalf("GetAttestation failed: %v", err)
		}

		if att.DPUName != "bf3-lab-01" {
			t.Errorf("DPUName = %q, want %q", att.DPUName, "bf3-lab-01")
		}
		if att.Status != AttestationStatusVerified {
			t.Errorf("Status = %q, want %q", att.Status, AttestationStatusVerified)
		}
		if att.DICEChainHash != "abc123" {
			t.Errorf("DICEChainHash = %q, want %q", att.DICEChainHash, "abc123")
		}
		if att.MeasurementsHash != "def456" {
			t.Errorf("MeasurementsHash = %q, want %q", att.MeasurementsHash, "def456")
		}
		if att.RawData["key"] != "value" {
			t.Errorf("RawData[key] = %v, want %q", att.RawData["key"], "value")
		}
	})

	t.Run("SaveAttestation_Update", func(t *testing.T) {
		// Update existing attestation
		att := &Attestation{
			DPUName:          "bf3-lab-01",
			Status:           AttestationStatusFailed,
			LastValidated:    time.Now(),
			DICEChainHash:    "new-hash",
			MeasurementsHash: "new-measurements",
		}

		err := store.SaveAttestation(att)
		if err != nil {
			t.Fatalf("SaveAttestation update failed: %v", err)
		}

		// Verify update
		updated, err := store.GetAttestation("bf3-lab-01")
		if err != nil {
			t.Fatalf("GetAttestation after update failed: %v", err)
		}
		if updated.Status != AttestationStatusFailed {
			t.Errorf("Status after update = %q, want %q", updated.Status, AttestationStatusFailed)
		}
		if updated.DICEChainHash != "new-hash" {
			t.Errorf("DICEChainHash after update = %q, want %q", updated.DICEChainHash, "new-hash")
		}
	})

	t.Run("GetAttestation_NotFound", func(t *testing.T) {
		_, err := store.GetAttestation("nonexistent")
		if err == nil {
			t.Error("GetAttestation should fail for nonexistent DPU")
		}
	})

	t.Run("AttestationExists", func(t *testing.T) {
		exists, err := store.AttestationExists("bf3-lab-01")
		if err != nil {
			t.Fatalf("AttestationExists failed: %v", err)
		}
		if !exists {
			t.Error("AttestationExists should return true for existing attestation")
		}

		exists, err = store.AttestationExists("nonexistent")
		if err != nil {
			t.Fatalf("AttestationExists failed: %v", err)
		}
		if exists {
			t.Error("AttestationExists should return false for nonexistent attestation")
		}
	})

	t.Run("ListAttestations", func(t *testing.T) {
		// Add another attestation
		att2 := &Attestation{
			DPUName:       "bf3-lab-02",
			Status:        AttestationStatusUnknown,
			LastValidated: time.Now(),
		}
		store.SaveAttestation(att2)

		attestations, err := store.ListAttestations()
		if err != nil {
			t.Fatalf("ListAttestations failed: %v", err)
		}

		if len(attestations) != 2 {
			t.Errorf("ListAttestations returned %d attestations, want 2", len(attestations))
		}
	})

	t.Run("ListAttestationsByStatus", func(t *testing.T) {
		failed, err := store.ListAttestationsByStatus(AttestationStatusFailed)
		if err != nil {
			t.Fatalf("ListAttestationsByStatus failed: %v", err)
		}

		if len(failed) != 1 {
			t.Errorf("ListAttestationsByStatus(failed) returned %d attestations, want 1", len(failed))
		}
		if failed[0].DPUName != "bf3-lab-01" {
			t.Errorf("Expected bf3-lab-01, got %s", failed[0].DPUName)
		}
	})

	t.Run("DeleteAttestation", func(t *testing.T) {
		err := store.DeleteAttestation("bf3-lab-02")
		if err != nil {
			t.Fatalf("DeleteAttestation failed: %v", err)
		}

		exists, _ := store.AttestationExists("bf3-lab-02")
		if exists {
			t.Error("Attestation should not exist after deletion")
		}
	})

	t.Run("DeleteAttestation_NotFound", func(t *testing.T) {
		err := store.DeleteAttestation("nonexistent")
		if err == nil {
			t.Error("DeleteAttestation should fail for nonexistent attestation")
		}
	})
}

func TestAttestationAge(t *testing.T) {
	att := &Attestation{
		LastValidated: time.Now().Add(-30 * time.Minute),
	}

	age := att.Age()
	if age < 29*time.Minute || age > 31*time.Minute {
		t.Errorf("Age() = %v, expected ~30m", age)
	}
}

func TestAttestationRawDataNil(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "attestation_nil_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	store, err := Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	att := &Attestation{
		DPUName:       "test-dpu",
		Status:        AttestationStatusVerified,
		LastValidated: time.Now(),
		RawData:       nil, // No raw data
	}

	err = store.SaveAttestation(att)
	if err != nil {
		t.Fatalf("SaveAttestation with nil RawData failed: %v", err)
	}

	retrieved, err := store.GetAttestation("test-dpu")
	if err != nil {
		t.Fatalf("GetAttestation failed: %v", err)
	}

	if retrieved.RawData != nil {
		t.Errorf("RawData should be nil, got %v", retrieved.RawData)
	}
}
