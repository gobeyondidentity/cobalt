package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestCredentialQueue(t *testing.T) {
	t.Log("Creating temporary database for credential queue tests")
	tmpFile, err := os.CreateTemp("", "credential_queue_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	t.Log("Opening store with credential_queue table migration")
	store, err := Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	t.Log("Creating DPUs used by queue tests")
	for _, dpu := range []struct{ id, name string }{
		{"dpu_test_1", "dpu-test"},
		{"dpu_other_1", "other-dpu"},
		{"dpu_a", "dpu-a"},
		{"dpu_b", "dpu-b"},
	} {
		if err := store.Add(dpu.id, dpu.name, "10.0.0.1", 50051); err != nil {
			t.Fatalf("failed to create DPU %s: %v", dpu.name, err)
		}
	}

	t.Run("QueueCredential_New", func(t *testing.T) {
		t.Log("Queuing a new SSH CA credential for dpu-test")
		err := store.QueueCredential("dpu-test", "ssh-ca", "prod-ca", []byte("ssh-ed25519 AAAAC3..."))
		if err != nil {
			t.Fatalf("QueueCredential failed: %v", err)
		}

		t.Log("Verifying credential was queued")
		count, err := store.CountQueuedCredentials("dpu-test")
		if err != nil {
			t.Fatalf("CountQueuedCredentials failed: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 queued credential, got %d", count)
		}
	})

	t.Run("QueueCredential_Multiple", func(t *testing.T) {
		t.Log("Queuing multiple credentials for the same DPU")
		err := store.QueueCredential("dpu-test", "ssh-ca", "stage-ca", []byte("key2"))
		if err != nil {
			t.Fatalf("QueueCredential failed: %v", err)
		}
		err = store.QueueCredential("dpu-test", "tls-cert", "api-cert", []byte("cert-data"))
		if err != nil {
			t.Fatalf("QueueCredential failed: %v", err)
		}

		count, err := store.CountQueuedCredentials("dpu-test")
		if err != nil {
			t.Fatalf("CountQueuedCredentials failed: %v", err)
		}
		if count != 3 {
			t.Errorf("expected 3 queued credentials, got %d", count)
		}
	})

	t.Run("GetQueuedCredentials", func(t *testing.T) {
		t.Log("Retrieving all queued credentials for dpu-test")
		creds, err := store.GetQueuedCredentials("dpu-test")
		if err != nil {
			t.Fatalf("GetQueuedCredentials failed: %v", err)
		}

		if len(creds) != 3 {
			t.Fatalf("expected 3 credentials, got %d", len(creds))
		}

		t.Log("Verifying credentials are returned in queue order")
		if creds[0].CredName != "prod-ca" {
			t.Errorf("expected first credential to be 'prod-ca', got '%s'", creds[0].CredName)
		}
		if creds[1].CredName != "stage-ca" {
			t.Errorf("expected second credential to be 'stage-ca', got '%s'", creds[1].CredName)
		}
		if creds[2].CredName != "api-cert" {
			t.Errorf("expected third credential to be 'api-cert', got '%s'", creds[2].CredName)
		}

		t.Log("Verifying credential data integrity")
		if !bytes.Equal(creds[0].Data, []byte("ssh-ed25519 AAAAC3...")) {
			t.Errorf("credential data mismatch for prod-ca")
		}

		t.Log("Verifying QueuedAt timestamp is recent")
		if time.Since(creds[0].QueuedAt) > 10*time.Second {
			t.Error("QueuedAt should be within the last 10 seconds")
		}
	})

	t.Run("GetQueuedCredentials_EmptyForOtherDPU", func(t *testing.T) {
		t.Log("Verifying empty result for DPU with no queued credentials")
		creds, err := store.GetQueuedCredentials("other-dpu")
		if err != nil {
			t.Fatalf("GetQueuedCredentials failed: %v", err)
		}
		if len(creds) != 0 {
			t.Errorf("expected 0 credentials for other-dpu, got %d", len(creds))
		}
	})

	t.Run("ClearQueuedCredential_Single", func(t *testing.T) {
		t.Log("Clearing a single credential by ID")
		creds, _ := store.GetQueuedCredentials("dpu-test")
		if len(creds) == 0 {
			t.Fatal("no credentials to test clearing")
		}

		err := store.ClearQueuedCredential(creds[0].ID)
		if err != nil {
			t.Fatalf("ClearQueuedCredential failed: %v", err)
		}

		t.Log("Verifying credential was removed")
		count, _ := store.CountQueuedCredentials("dpu-test")
		if count != 2 {
			t.Errorf("expected 2 credentials after clearing one, got %d", count)
		}
	})

	t.Run("ClearQueuedCredential_NotFound", func(t *testing.T) {
		t.Log("Attempting to clear non-existent credential")
		err := store.ClearQueuedCredential(99999)
		if err == nil {
			t.Error("ClearQueuedCredential should fail for non-existent ID")
		}
	})

	t.Run("ClearQueuedCredentials_AllForDPU", func(t *testing.T) {
		t.Log("Clearing all credentials for dpu-test")
		err := store.ClearQueuedCredentials("dpu-test")
		if err != nil {
			t.Fatalf("ClearQueuedCredentials failed: %v", err)
		}

		t.Log("Verifying all credentials were cleared")
		count, _ := store.CountQueuedCredentials("dpu-test")
		if count != 0 {
			t.Errorf("expected 0 credentials after clearing all, got %d", count)
		}
	})

	t.Run("QueueCredential_DifferentDPUs", func(t *testing.T) {
		t.Log("Queuing credentials for different DPUs")
		store.QueueCredential("dpu-a", "ssh-ca", "ca-a", []byte("key-a"))
		store.QueueCredential("dpu-b", "ssh-ca", "ca-b", []byte("key-b"))
		store.QueueCredential("dpu-a", "tls-cert", "cert-a", []byte("cert-a"))

		t.Log("Verifying DPU isolation")
		countA, _ := store.CountQueuedCredentials("dpu-a")
		countB, _ := store.CountQueuedCredentials("dpu-b")

		if countA != 2 {
			t.Errorf("expected 2 credentials for dpu-a, got %d", countA)
		}
		if countB != 1 {
			t.Errorf("expected 1 credential for dpu-b, got %d", countB)
		}

		t.Log("Clearing dpu-a credentials should not affect dpu-b")
		store.ClearQueuedCredentials("dpu-a")
		countB, _ = store.CountQueuedCredentials("dpu-b")
		if countB != 1 {
			t.Errorf("dpu-b should still have 1 credential, got %d", countB)
		}
	})
}

func TestQueueCredential_RejectsDecommissionedDPU(t *testing.T) {
	t.Log("Testing that QueueCredential rejects writes to decommissioned DPUs")

	tmpFile, err := os.CreateTemp("", "queue_guard_test_*.db")
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

	t.Log("Creating a DPU in the store")
	dpuName := "guard-test-dpu"
	dpuID := "dpu_guard_test"
	if err := store.Add(dpuID, dpuName, "192.168.1.100", 50051); err != nil {
		t.Fatalf("failed to create DPU: %v", err)
	}

	t.Log("Queuing a credential for active DPU should succeed")
	err = store.QueueCredential(dpuName, "ssh-ca", "prod-ca", []byte("pubkey1"))
	if err != nil {
		t.Fatalf("QueueCredential should succeed for active DPU: %v", err)
	}

	t.Log("Decommissioning the DPU")
	_, err = store.DecommissionDPUAtomic(dpuID, "adm_test", "Hardware removal")
	if err != nil {
		t.Fatalf("failed to decommission DPU: %v", err)
	}

	t.Log("Queuing a credential for decommissioned DPU should fail")
	err = store.QueueCredential(dpuName, "ssh-ca", "stage-ca", []byte("pubkey2"))
	if err == nil {
		t.Fatal("QueueCredential should reject writes to decommissioned DPU")
	}
	if err != ErrDPUDecommissioned {
		t.Errorf("expected ErrDPUDecommissioned, got: %v", err)
	}

	t.Log("Verifying only the pre-decommission credential exists (was scrubbed by decommission)")
	count, err := store.CountQueuedCredentials(dpuName)
	if err != nil {
		t.Fatalf("failed to count credentials: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 credentials (scrubbed on decommission), got %d", count)
	}

	t.Log("QueueCredential guard for decommissioned DPUs works correctly")
}

func TestQueueCredential_RejectsUnknownDPU(t *testing.T) {
	t.Log("Testing that QueueCredential rejects writes to DPUs not in the dpus table")

	tmpFile, err := os.CreateTemp("", "queue_unknown_dpu_test_*.db")
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

	t.Log("Queuing credential for a DPU name that does not exist in the dpus table")
	err = store.QueueCredential("nonexistent-dpu", "ssh-ca", "prod-ca", []byte("pubkey"))
	if err == nil {
		t.Fatal("QueueCredential should reject writes to unknown DPUs")
	}
	if !errors.Is(err, ErrDPUNotFound) {
		t.Errorf("expected ErrDPUNotFound, got: %v", err)
	}

	t.Log("Verifying no credential was inserted")
	count, err := store.CountQueuedCredentials("nonexistent-dpu")
	if err != nil {
		t.Fatalf("CountQueuedCredentials failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 queued credentials for unknown DPU, got %d", count)
	}

	t.Log("QueueCredential correctly rejects unknown DPUs")
}

func TestQueueCredential_RaceSafety(t *testing.T) {
	t.Log("Testing that concurrent QueueCredential and DecommissionDPUAtomic cannot leave orphaned credentials")

	tmpFile, err := os.CreateTemp("", "queue_race_test_*.db")
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

	// Run multiple rounds to increase chance of hitting the race window
	const rounds = 50
	for i := 0; i < rounds; i++ {
		dpuName := fmt.Sprintf("race-dpu-%d", i)
		dpuID := fmt.Sprintf("dpu_race_%d", i)

		// Create a fresh active DPU each round
		if err := store.Add(dpuID, dpuName, "10.0.0.1", 50051); err != nil {
			t.Fatalf("round %d: failed to create DPU: %v", i, err)
		}

		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine 1: attempt to queue a credential
		go func() {
			defer wg.Done()
			store.QueueCredential(dpuName, "ssh-ca", "ca", []byte("key"))
		}()

		// Goroutine 2: decommission the DPU (which scrubs its queue)
		go func() {
			defer wg.Done()
			store.DecommissionDPUAtomic(dpuID, "adm_test", "race test")
		}()

		wg.Wait()

		// Invariant: after decommission completes, no credentials should remain queued.
		// Either QueueCredential ran first (credential inserted then scrubbed by decommission),
		// or decommission ran first (QueueCredential returns ErrDPUDecommissioned).
		count, err := store.CountQueuedCredentials(dpuName)
		if err != nil {
			t.Fatalf("round %d: CountQueuedCredentials failed: %v", i, err)
		}
		if count != 0 {
			t.Errorf("round %d: expected 0 credentials after decommission, got %d (TOCTOU race detected)", i, count)
		}
	}

	t.Logf("Completed %d race rounds with no orphaned credentials", rounds)
}

func TestUpdateAgentHostByDPU(t *testing.T) {
	t.Log("Creating temporary database for UpdateAgentHostByDPU tests")
	tmpFile, err := os.CreateTemp("", "update_agent_host_test_*.db")
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

	t.Run("CreateNew", func(t *testing.T) {
		t.Log("Creating new agent host via UpdateAgentHostByDPU")
		err := store.UpdateAgentHostByDPU("bf3-01", "dpu_12345", "workstation-01", "host_abc123")
		if err != nil {
			t.Fatalf("UpdateAgentHostByDPU failed: %v", err)
		}

		t.Log("Verifying host was created")
		host, err := store.GetAgentHostByDPU("bf3-01")
		if err != nil {
			t.Fatalf("GetAgentHostByDPU failed: %v", err)
		}
		if host.Hostname != "workstation-01" {
			t.Errorf("expected hostname 'workstation-01', got '%s'", host.Hostname)
		}
		if host.ID != "host_abc123" {
			t.Errorf("expected ID 'host_abc123', got '%s'", host.ID)
		}
	})

	t.Run("UpdateExisting", func(t *testing.T) {
		t.Log("Updating existing agent host hostname")
		err := store.UpdateAgentHostByDPU("bf3-01", "dpu_12345", "workstation-01-renamed", "host_abc123")
		if err != nil {
			t.Fatalf("UpdateAgentHostByDPU failed: %v", err)
		}

		t.Log("Verifying hostname was updated")
		host, _ := store.GetAgentHostByDPU("bf3-01")
		if host.Hostname != "workstation-01-renamed" {
			t.Errorf("expected hostname 'workstation-01-renamed', got '%s'", host.Hostname)
		}
	})
}
