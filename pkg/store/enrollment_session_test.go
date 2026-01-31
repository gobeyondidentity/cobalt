package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnrollmentSessionWithDPUID tests that enrollment sessions can store and retrieve DPU references.
func TestEnrollmentSessionWithDPUID(t *testing.T) {
	s := setupTestStore(t)

	t.Log("Creating DPU for enrollment session reference")
	err := s.Add("dpu-test-1", "bf3-enroll", "192.168.1.100", 50051)
	require.NoError(t, err)

	dpuID := "dpu-test-1"
	now := time.Now()

	t.Run("CreateWithDPUID", func(t *testing.T) {
		t.Log("Creating enrollment session with DPUID")
		session := &EnrollmentSession{
			ID:            "sess-dpu-1",
			SessionType:   "dpu",
			ChallengeHash: "abc123hash",
			DPUID:         &dpuID,
			IPAddress:     "192.168.1.50",
			CreatedAt:     now,
			ExpiresAt:     now.Add(5 * time.Minute),
		}

		err := s.CreateEnrollmentSession(session)
		require.NoError(t, err)
		t.Log("Session created successfully")
	})

	t.Run("RetrieveWithDPUID", func(t *testing.T) {
		t.Log("Retrieving enrollment session and verifying DPUID")
		session, err := s.GetEnrollmentSession("sess-dpu-1")
		require.NoError(t, err)
		require.NotNil(t, session)

		assert.Equal(t, "sess-dpu-1", session.ID)
		assert.Equal(t, "dpu", session.SessionType)
		require.NotNil(t, session.DPUID, "DPUID should not be nil")
		assert.Equal(t, dpuID, *session.DPUID)
		t.Logf("Retrieved DPUID: %s", *session.DPUID)
	})

	t.Run("CreateWithoutDPUID", func(t *testing.T) {
		t.Log("Creating enrollment session without DPUID (bootstrap type)")
		pubKey := "base64pubkey"
		session := &EnrollmentSession{
			ID:            "sess-bootstrap-1",
			SessionType:   "bootstrap",
			ChallengeHash: "xyz789hash",
			PublicKeyB64:  &pubKey,
			IPAddress:     "192.168.1.51",
			CreatedAt:     now,
			ExpiresAt:     now.Add(5 * time.Minute),
		}

		err := s.CreateEnrollmentSession(session)
		require.NoError(t, err)

		retrieved, err := s.GetEnrollmentSession("sess-bootstrap-1")
		require.NoError(t, err)
		assert.Nil(t, retrieved.DPUID, "DPUID should be nil for bootstrap session")
		require.NotNil(t, retrieved.PublicKeyB64)
		assert.Equal(t, pubKey, *retrieved.PublicKeyB64)
		t.Log("Bootstrap session created without DPUID as expected")
	})
}

// TestGetDPUBySerial tests looking up DPUs by serial number.
func TestGetDPUBySerial(t *testing.T) {
	s := setupTestStore(t)

	t.Log("Setting up DPU with serial number")
	err := s.Add("dpu-serial-1", "bf3-serial-test", "192.168.1.100", 50051)
	require.NoError(t, err)

	err = s.SetDPUSerialNumber("dpu-serial-1", "MLX-BF3-SN12345")
	require.NoError(t, err)
	t.Log("Serial number set: MLX-BF3-SN12345")

	t.Run("FindBySerial", func(t *testing.T) {
		t.Log("Looking up DPU by serial number")
		dpu, err := s.GetDPUBySerial("MLX-BF3-SN12345")
		require.NoError(t, err)
		require.NotNil(t, dpu, "DPU should be found by serial")
		assert.Equal(t, "bf3-serial-test", dpu.Name)
		assert.Equal(t, "MLX-BF3-SN12345", dpu.SerialNumber)
		t.Logf("Found DPU: %s with serial %s", dpu.Name, dpu.SerialNumber)
	})

	t.Run("NotFoundSerial", func(t *testing.T) {
		t.Log("Looking up non-existent serial number")
		dpu, err := s.GetDPUBySerial("NON-EXISTENT-SERIAL")
		require.NoError(t, err)
		assert.Nil(t, dpu, "Should return nil for non-existent serial")
		t.Log("Correctly returned nil for non-existent serial")
	})

	t.Run("NullSerialNotMatched", func(t *testing.T) {
		t.Log("Creating DPU without serial number")
		err := s.Add("dpu-no-serial", "bf3-no-serial", "192.168.1.101", 50051)
		require.NoError(t, err)

		// Should not be found when searching for empty string
		dpu, err := s.GetDPUBySerial("")
		require.NoError(t, err)
		assert.Nil(t, dpu, "Empty serial should not match DPUs with NULL serial")
		t.Log("Empty serial correctly returns nil")
	})
}

// TestSetDPUSerialNumber tests setting the serial number on a DPU.
func TestSetDPUSerialNumber(t *testing.T) {
	s := setupTestStore(t)

	t.Log("Creating DPU for serial number test")
	err := s.Add("dpu-sn-1", "bf3-sn-test", "192.168.1.100", 50051)
	require.NoError(t, err)

	t.Run("SetSerial", func(t *testing.T) {
		t.Log("Setting serial number on DPU")
		err := s.SetDPUSerialNumber("dpu-sn-1", "SN-ABC123")
		require.NoError(t, err)

		dpu, err := s.Get("dpu-sn-1")
		require.NoError(t, err)
		assert.Equal(t, "SN-ABC123", dpu.SerialNumber)
		t.Log("Serial number set successfully")
	})

	t.Run("UpdateSerial", func(t *testing.T) {
		t.Log("Updating serial number on DPU")
		err := s.SetDPUSerialNumber("dpu-sn-1", "SN-XYZ789")
		require.NoError(t, err)

		dpu, err := s.Get("dpu-sn-1")
		require.NoError(t, err)
		assert.Equal(t, "SN-XYZ789", dpu.SerialNumber)
		t.Log("Serial number updated successfully")
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Log("Setting serial on non-existent DPU")
		err := s.SetDPUSerialNumber("non-existent", "SN-XXX")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DPU not found")
		t.Log("Correctly rejected non-existent DPU")
	})
}

// TestUpdateDPUEnrollment tests updating a DPU's enrollment status after successful enrollment.
func TestUpdateDPUEnrollment(t *testing.T) {
	s := setupTestStore(t)

	t.Log("Creating DPU in pending state")
	err := s.Add("dpu-enroll-1", "bf3-enroll-test", "192.168.1.100", 50051)
	require.NoError(t, err)

	// Set enrollment_expires_at to simulate pending enrollment
	now := time.Now()
	expires := now.Add(24 * time.Hour)
	_, err = s.db.Exec("UPDATE dpus SET enrollment_expires_at = ? WHERE id = ?", expires.Unix(), "dpu-enroll-1")
	require.NoError(t, err)

	publicKey := []byte("raw-public-key-bytes-32chars...")
	fingerprint := "sha256:abcdef1234567890"
	kid := "dpu_enroll-1"

	t.Run("EnrollmentSuccess", func(t *testing.T) {
		t.Log("Updating DPU enrollment status")
		err := s.UpdateDPUEnrollment("dpu-enroll-1", publicKey, fingerprint, kid)
		require.NoError(t, err)

		t.Log("Verifying enrollment state")
		dpu, err := s.Get("dpu-enroll-1")
		require.NoError(t, err)

		assert.Equal(t, publicKey, dpu.PublicKey, "Public key should be set")
		require.NotNil(t, dpu.KeyFingerprint)
		assert.Equal(t, fingerprint, *dpu.KeyFingerprint, "Fingerprint should be set")
		require.NotNil(t, dpu.Kid)
		assert.Equal(t, kid, *dpu.Kid, "Kid should be set")
		assert.Equal(t, "active", dpu.Status, "Status should be active")
		assert.Nil(t, dpu.EnrollmentExpiresAt, "EnrollmentExpiresAt should be cleared")

		t.Log("DPU enrollment completed successfully")
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Log("Updating enrollment on non-existent DPU")
		err := s.UpdateDPUEnrollment("non-existent", publicKey, fingerprint, kid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DPU not found")
		t.Log("Correctly rejected non-existent DPU")
	})
}

// TestDPUSerialNumberPersistence tests that serial number persists across list and get operations.
func TestDPUSerialNumberPersistence(t *testing.T) {
	s := setupTestStore(t)

	t.Log("Creating multiple DPUs with serial numbers")
	err := s.Add("dpu-p1", "bf3-persist-1", "192.168.1.100", 50051)
	require.NoError(t, err)
	err = s.SetDPUSerialNumber("dpu-p1", "SN-PERSIST-001")
	require.NoError(t, err)

	err = s.Add("dpu-p2", "bf3-persist-2", "192.168.1.101", 50051)
	require.NoError(t, err)
	err = s.SetDPUSerialNumber("dpu-p2", "SN-PERSIST-002")
	require.NoError(t, err)

	t.Run("ListIncludesSerial", func(t *testing.T) {
		t.Log("Verifying List() includes serial numbers")
		dpus, err := s.List()
		require.NoError(t, err)
		require.Len(t, dpus, 2)

		serialMap := make(map[string]string)
		for _, dpu := range dpus {
			serialMap[dpu.Name] = dpu.SerialNumber
		}

		assert.Equal(t, "SN-PERSIST-001", serialMap["bf3-persist-1"])
		assert.Equal(t, "SN-PERSIST-002", serialMap["bf3-persist-2"])
		t.Log("List() correctly returns serial numbers")
	})

	t.Run("GetIncludesSerial", func(t *testing.T) {
		t.Log("Verifying Get() includes serial number")
		dpu, err := s.Get("bf3-persist-1")
		require.NoError(t, err)
		assert.Equal(t, "SN-PERSIST-001", dpu.SerialNumber)
		t.Log("Get() correctly returns serial number")
	})

	t.Run("GetByAddressIncludesSerial", func(t *testing.T) {
		t.Log("Verifying GetDPUByAddress() includes serial number")
		dpu, err := s.GetDPUByAddress("192.168.1.101", 50051)
		require.NoError(t, err)
		require.NotNil(t, dpu)
		assert.Equal(t, "SN-PERSIST-002", dpu.SerialNumber)
		t.Log("GetDPUByAddress() correctly returns serial number")
	})
}
