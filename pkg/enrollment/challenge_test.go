package enrollment

import (
	"testing"
)

func TestGenerateChallenge(t *testing.T) {
	t.Parallel()
	t.Log("Generating single challenge")
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}

	t.Log("Verifying challenge length is 32 bytes")
	if len(challenge) != 32 {
		t.Errorf("GenerateChallenge() length = %d, want 32", len(challenge))
	}
}

func TestGenerateChallengeUniqueness(t *testing.T) {
	t.Parallel()
	const iterations = 10000
	t.Logf("Generating %d challenges to verify uniqueness", iterations)

	seen := make(map[string]bool, iterations)

	for i := 0; i < iterations; i++ {
		challenge, err := GenerateChallenge()
		if err != nil {
			t.Fatalf("GenerateChallenge() iteration %d error = %v", i, err)
		}

		if len(challenge) != 32 {
			t.Errorf("GenerateChallenge() iteration %d length = %d, want 32", i, len(challenge))
		}

		key := string(challenge)
		if seen[key] {
			t.Errorf("GenerateChallenge() produced duplicate at iteration %d", i)
		}
		seen[key] = true
	}

	t.Logf("All %d challenges were unique", iterations)
}

func TestGenerateChallengeNotZero(t *testing.T) {
	t.Parallel()
	t.Log("Verifying challenge is not all zeros")
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}

	allZero := true
	for _, b := range challenge {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		t.Error("GenerateChallenge() returned all zeros, indicating possible PRNG failure")
	}
}
