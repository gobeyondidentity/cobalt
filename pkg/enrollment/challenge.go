package enrollment

import (
	"crypto/rand"
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
