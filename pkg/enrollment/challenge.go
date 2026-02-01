package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// ChallengeSize is the number of bytes in a generated challenge.
const ChallengeSize = 32

// GenerateChallenge generates a 32-byte cryptographically random challenge.
// Uses crypto/rand for secure entropy; never uses math/rand.
//
// Returns raw bytes; caller is responsible for encoding as needed
// (typically base64url for transmission).
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, ChallengeSize)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	return challenge, nil
}

// ComputeBindingNonce computes the SPDM binding nonce for DPU enrollment.
// Formula: SHA256(challenge_bytes || pubkey_bytes)
// Both inputs must be raw bytes (not base64).
//
// The binding nonce is used to cryptographically bind the enrollment challenge
// to the DPU's public key. The DPU includes this nonce in its SPDM attestation
// response, proving that the attestation was generated specifically for this
// enrollment session.
func ComputeBindingNonce(challenge, publicKey []byte) []byte {
	h := sha256.New()
	h.Write(challenge)
	h.Write(publicKey)
	return h.Sum(nil)
}
