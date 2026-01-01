package store

import (
	"os"
	"testing"
	"time"
)

func TestDistributionHistory(t *testing.T) {
	// Create temp database
	tmpFile, err := os.CreateTemp("", "distribution_test_*.db")
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

	t.Run("RecordDistribution_Success", func(t *testing.T) {
		d := &Distribution{
			DPUName:             "bf3-lab-01",
			CredentialType:      "ssh-ca",
			CredentialName:      "prod-ca",
			Outcome:             DistributionOutcomeSuccess,
			AttestationStatus:   stringPtr("verified"),
			AttestationAgeSecs:  intPtr(120),
			InstalledPath:       stringPtr("/etc/ssh/ca.pub"),
			ErrorMessage:        nil,
		}

		err := store.RecordDistribution(d)
		if err != nil {
			t.Fatalf("RecordDistribution failed: %v", err)
		}

		if d.ID == 0 {
			t.Error("Distribution ID should be set after insert")
		}
	})

	t.Run("RecordDistribution_BlockedStale", func(t *testing.T) {
		d := &Distribution{
			DPUName:             "bf3-lab-02",
			CredentialType:      "ssh-ca",
			CredentialName:      "prod-ca",
			Outcome:             DistributionOutcomeBlockedStale,
			AttestationStatus:   stringPtr("verified"),
			AttestationAgeSecs:  intPtr(7200), // 2 hours - stale
			InstalledPath:       nil,           // Not installed
			ErrorMessage:        stringPtr("attestation too old: 2h0m0s > 1h0m0s"),
		}

		err := store.RecordDistribution(d)
		if err != nil {
			t.Fatalf("RecordDistribution blocked failed: %v", err)
		}
	})

	t.Run("RecordDistribution_BlockedFailed", func(t *testing.T) {
		d := &Distribution{
			DPUName:             "bf3-lab-03",
			CredentialType:      "ssh-ca",
			CredentialName:      "dev-ca",
			Outcome:             DistributionOutcomeBlockedFailed,
			AttestationStatus:   stringPtr("failed"),
			AttestationAgeSecs:  intPtr(60),
			InstalledPath:       nil,
			ErrorMessage:        stringPtr("attestation status is failed"),
		}

		err := store.RecordDistribution(d)
		if err != nil {
			t.Fatalf("RecordDistribution blocked-failed: %v", err)
		}
	})

	t.Run("RecordDistribution_Forced", func(t *testing.T) {
		d := &Distribution{
			DPUName:             "bf3-lab-01",
			CredentialType:      "ssh-ca",
			CredentialName:      "prod-ca",
			Outcome:             DistributionOutcomeForced,
			AttestationStatus:   stringPtr("failed"),
			AttestationAgeSecs:  intPtr(300),
			InstalledPath:       stringPtr("/etc/ssh/ca.pub"),
			ErrorMessage:        nil,
		}

		err := store.RecordDistribution(d)
		if err != nil {
			t.Fatalf("RecordDistribution forced failed: %v", err)
		}
	})

	t.Run("GetDistributionHistory_ByDPU", func(t *testing.T) {
		history, err := store.GetDistributionHistory("bf3-lab-01")
		if err != nil {
			t.Fatalf("GetDistributionHistory failed: %v", err)
		}

		if len(history) != 2 {
			t.Errorf("GetDistributionHistory returned %d records, want 2", len(history))
		}

		// Most recent first (forced)
		if history[0].Outcome != DistributionOutcomeForced {
			t.Errorf("First record outcome = %q, want %q", history[0].Outcome, DistributionOutcomeForced)
		}
		if history[1].Outcome != DistributionOutcomeSuccess {
			t.Errorf("Second record outcome = %q, want %q", history[1].Outcome, DistributionOutcomeSuccess)
		}
	})

	t.Run("GetDistributionHistory_ByDPU_NotFound", func(t *testing.T) {
		history, err := store.GetDistributionHistory("nonexistent")
		if err != nil {
			t.Fatalf("GetDistributionHistory failed: %v", err)
		}

		if len(history) != 0 {
			t.Errorf("GetDistributionHistory for nonexistent DPU returned %d records, want 0", len(history))
		}
	})

	t.Run("GetDistributionHistoryByCredential", func(t *testing.T) {
		history, err := store.GetDistributionHistoryByCredential("prod-ca")
		if err != nil {
			t.Fatalf("GetDistributionHistoryByCredential failed: %v", err)
		}

		if len(history) != 3 {
			t.Errorf("GetDistributionHistoryByCredential returned %d records, want 3", len(history))
		}

		// Verify all are for prod-ca
		for _, d := range history {
			if d.CredentialName != "prod-ca" {
				t.Errorf("CredentialName = %q, want %q", d.CredentialName, "prod-ca")
			}
		}
	})

	t.Run("GetDistributionHistoryByCredential_NotFound", func(t *testing.T) {
		history, err := store.GetDistributionHistoryByCredential("nonexistent-ca")
		if err != nil {
			t.Fatalf("GetDistributionHistoryByCredential failed: %v", err)
		}

		if len(history) != 0 {
			t.Errorf("GetDistributionHistoryByCredential for nonexistent CA returned %d records, want 0", len(history))
		}
	})

	t.Run("ListRecentDistributions", func(t *testing.T) {
		// We have 4 total distributions
		recent, err := store.ListRecentDistributions(2)
		if err != nil {
			t.Fatalf("ListRecentDistributions failed: %v", err)
		}

		if len(recent) != 2 {
			t.Errorf("ListRecentDistributions returned %d records, want 2", len(recent))
		}

		// Should be ordered by created_at DESC (most recent first)
		// The last insert was forced for bf3-lab-01
		if recent[0].DPUName != "bf3-lab-01" || recent[0].Outcome != DistributionOutcomeForced {
			t.Errorf("First recent = %s/%s, want bf3-lab-01/forced", recent[0].DPUName, recent[0].Outcome)
		}
	})

	t.Run("ListRecentDistributions_All", func(t *testing.T) {
		recent, err := store.ListRecentDistributions(100)
		if err != nil {
			t.Fatalf("ListRecentDistributions failed: %v", err)
		}

		if len(recent) != 4 {
			t.Errorf("ListRecentDistributions returned %d records, want 4", len(recent))
		}
	})
}

func TestDistributionNullableFields(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "distribution_nullable_test_*.db")
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

	// Distribution with no attestation info (e.g., no attestation exists)
	d := &Distribution{
		DPUName:             "bf3-no-attestation",
		CredentialType:      "ssh-ca",
		CredentialName:      "test-ca",
		Outcome:             DistributionOutcomeBlockedFailed,
		AttestationStatus:   nil,
		AttestationAgeSecs:  nil,
		InstalledPath:       nil,
		ErrorMessage:        stringPtr("no attestation found"),
	}

	err = store.RecordDistribution(d)
	if err != nil {
		t.Fatalf("RecordDistribution with nulls failed: %v", err)
	}

	history, err := store.GetDistributionHistory("bf3-no-attestation")
	if err != nil {
		t.Fatalf("GetDistributionHistory failed: %v", err)
	}

	if len(history) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(history))
	}

	retrieved := history[0]
	if retrieved.AttestationStatus != nil {
		t.Errorf("AttestationStatus should be nil, got %v", *retrieved.AttestationStatus)
	}
	if retrieved.AttestationAgeSecs != nil {
		t.Errorf("AttestationAgeSecs should be nil, got %v", *retrieved.AttestationAgeSecs)
	}
	if retrieved.InstalledPath != nil {
		t.Errorf("InstalledPath should be nil, got %v", *retrieved.InstalledPath)
	}
	if retrieved.ErrorMessage == nil || *retrieved.ErrorMessage != "no attestation found" {
		t.Errorf("ErrorMessage = %v, want 'no attestation found'", retrieved.ErrorMessage)
	}
}

func TestDistributionCreatedAt(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "distribution_time_test_*.db")
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

	// Truncate to second precision since SQLite stores Unix timestamps
	before := time.Now().Truncate(time.Second)

	d := &Distribution{
		DPUName:        "bf3-time-test",
		CredentialType: "ssh-ca",
		CredentialName: "time-ca",
		Outcome:        DistributionOutcomeSuccess,
	}

	err = store.RecordDistribution(d)
	if err != nil {
		t.Fatalf("RecordDistribution failed: %v", err)
	}

	// Add 1 second to account for potential second boundary crossing
	after := time.Now().Add(time.Second).Truncate(time.Second)

	history, err := store.GetDistributionHistory("bf3-time-test")
	if err != nil {
		t.Fatalf("GetDistributionHistory failed: %v", err)
	}

	if len(history) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(history))
	}

	createdAt := history[0].CreatedAt
	if createdAt.Before(before) || createdAt.After(after) {
		t.Errorf("CreatedAt %v not between %v and %v", createdAt, before, after)
	}
}

// Helper functions for creating pointers to primitives
func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}
