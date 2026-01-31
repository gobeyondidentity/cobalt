package enrollment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestComputeBindingNonce tests the binding nonce computation for DPU enrollment.
func TestComputeBindingNonce(t *testing.T) {
	t.Log("Testing binding nonce computation")

	t.Run("BasicComputation", func(t *testing.T) {
		t.Log("Computing binding nonce with known inputs")
		challenge := make([]byte, 32)
		for i := range challenge {
			challenge[i] = byte(i)
		}
		publicKey := make([]byte, 32)
		for i := range publicKey {
			publicKey[i] = byte(i + 32)
		}

		nonce := ComputeBindingNonce(challenge, publicKey)

		t.Logf("Challenge: %s", hex.EncodeToString(challenge))
		t.Logf("PublicKey: %s", hex.EncodeToString(publicKey))
		t.Logf("Nonce: %s", hex.EncodeToString(nonce))

		// Verify it's a valid SHA256 hash (32 bytes)
		if len(nonce) != 32 {
			t.Errorf("Expected nonce length 32, got %d", len(nonce))
		}

		// Manually compute expected result: SHA256(challenge || publicKey)
		h := sha256.New()
		h.Write(challenge)
		h.Write(publicKey)
		expected := h.Sum(nil)

		if !bytes.Equal(nonce, expected) {
			t.Errorf("Nonce mismatch.\nExpected: %s\nGot:      %s",
				hex.EncodeToString(expected), hex.EncodeToString(nonce))
		}
		t.Log("Binding nonce correctly computed")
	})

	t.Run("Deterministic", func(t *testing.T) {
		t.Log("Verifying binding nonce is deterministic")
		challenge := []byte("test-challenge-exactly-32-bytes!")
		publicKey := []byte("test-pubkey-exactly-32-bytes!!")

		nonce1 := ComputeBindingNonce(challenge, publicKey)
		nonce2 := ComputeBindingNonce(challenge, publicKey)

		if !bytes.Equal(nonce1, nonce2) {
			t.Error("Binding nonce should be deterministic for same inputs")
		}
		t.Log("Binding nonce is deterministic")
	})

	t.Run("OrderMatters", func(t *testing.T) {
		t.Log("Verifying input order affects output")
		a := []byte("input-a-exactly-32-bytes-long!!")
		b := []byte("input-b-exactly-32-bytes-long!!")

		nonce1 := ComputeBindingNonce(a, b)
		nonce2 := ComputeBindingNonce(b, a)

		if bytes.Equal(nonce1, nonce2) {
			t.Error("Binding nonce should differ when inputs are swapped")
		}
		t.Log("Input order correctly affects binding nonce")
	})

	t.Run("EmptyInputs", func(t *testing.T) {
		t.Log("Testing with empty inputs")
		// Empty challenge and key should still produce valid hash
		nonce := ComputeBindingNonce([]byte{}, []byte{})

		// SHA256 of empty input
		expected := sha256.Sum256([]byte{})
		if !bytes.Equal(nonce, expected[:]) {
			t.Errorf("Empty input nonce mismatch.\nExpected: %s\nGot:      %s",
				hex.EncodeToString(expected[:]), hex.EncodeToString(nonce))
		}
		t.Log("Empty inputs produce correct hash")
	})

	t.Run("KnownVector", func(t *testing.T) {
		t.Log("Testing with known test vector")
		// Create reproducible test vector
		challenge := bytes.Repeat([]byte{0xAA}, 32)
		publicKey := bytes.Repeat([]byte{0xBB}, 32)

		nonce := ComputeBindingNonce(challenge, publicKey)

		// Pre-compute expected value
		h := sha256.New()
		h.Write(challenge)
		h.Write(publicKey)
		expected := h.Sum(nil)
		expectedHex := hex.EncodeToString(expected)

		gotHex := hex.EncodeToString(nonce)
		t.Logf("Known vector nonce: %s", gotHex)

		if gotHex != expectedHex {
			t.Errorf("Known vector mismatch.\nExpected: %s\nGot:      %s", expectedHex, gotHex)
		}
		t.Log("Known vector test passed")
	})
}

// TestComputeBindingNonceUniqueness verifies different inputs produce different nonces.
func TestComputeBindingNonceUniqueness(t *testing.T) {
	t.Log("Testing binding nonce uniqueness across different challenges")

	const iterations = 1000
	seen := make(map[string]bool, iterations)

	// Fixed public key, varying challenges
	publicKey := bytes.Repeat([]byte{0x42}, 32)

	for i := 0; i < iterations; i++ {
		// Generate unique challenge per iteration
		challenge, err := GenerateChallenge()
		if err != nil {
			t.Fatalf("GenerateChallenge() failed at iteration %d: %v", i, err)
		}

		nonce := ComputeBindingNonce(challenge, publicKey)
		key := string(nonce)

		if seen[key] {
			t.Errorf("Duplicate binding nonce at iteration %d", i)
		}
		seen[key] = true
	}

	t.Logf("All %d binding nonces were unique", iterations)
}
