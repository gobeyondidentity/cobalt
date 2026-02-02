package sshscan

import (
	"strings"
	"testing"
)

func TestFingerprint(t *testing.T) {
	t.Parallel()
	t.Run("ed25519 fingerprint format", func(t *testing.T) {
		// Parse a key to get its base64 data
		key, err := ParseLine(testEd25519Key)
		if err != nil {
			t.Fatalf("ParseLine failed: %v", err)
		}

		if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
			t.Errorf("Fingerprint should start with SHA256:, got %q", key.Fingerprint)
		}

		// SHA256 base64 without padding is 43 chars, with prefix "SHA256:" = 50 chars
		if len(key.Fingerprint) < 50 {
			t.Errorf("Fingerprint too short: %q", key.Fingerprint)
		}
	})

	t.Run("same key produces same fingerprint", func(t *testing.T) {
		key1, _ := ParseLine(testEd25519Key)
		key2, _ := ParseLine(testEd25519Key)

		if key1.Fingerprint != key2.Fingerprint {
			t.Errorf("Same key should produce same fingerprint: %q != %q", key1.Fingerprint, key2.Fingerprint)
		}
	})

	t.Run("different keys produce different fingerprints", func(t *testing.T) {
		key1, _ := ParseLine(testEd25519Key)
		key2, _ := ParseLine(testECDSA256Key)

		if key1.Fingerprint == key2.Fingerprint {
			t.Errorf("Different keys should produce different fingerprints")
		}
	})

	t.Run("fingerprint excludes padding", func(t *testing.T) {
		key, _ := ParseLine(testEd25519Key)

		// Standard SSH fingerprints use base64 without trailing = padding
		if strings.HasSuffix(key.Fingerprint, "=") {
			t.Errorf("Fingerprint should not have base64 padding: %q", key.Fingerprint)
		}
	})
}

func TestGenerateFingerprint(t *testing.T) {
	t.Parallel()
	t.Run("valid base64 produces fingerprint", func(t *testing.T) {
		// This is the base64 portion of testEd25519Key
		base64Data := "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

		fp, err := GenerateFingerprint(base64Data)
		if err != nil {
			t.Fatalf("GenerateFingerprint failed: %v", err)
		}

		if !strings.HasPrefix(fp, "SHA256:") {
			t.Errorf("Fingerprint should start with SHA256:, got %q", fp)
		}
	})

	t.Run("matches ssh-keygen output", func(t *testing.T) {
		// Fingerprint from: echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test" | ssh-keygen -lf -
		// Output: 256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU test (ED25519)
		expectedFingerprint := "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"

		key, err := ParseLine(testEd25519Key)
		if err != nil {
			t.Fatalf("ParseLine failed: %v", err)
		}

		if key.Fingerprint != expectedFingerprint {
			t.Errorf("Fingerprint = %q, want %q (from ssh-keygen)", key.Fingerprint, expectedFingerprint)
		}
	})

	t.Run("invalid base64 returns error", func(t *testing.T) {
		_, err := GenerateFingerprint("not-valid-base64!!!")
		if err == nil {
			t.Error("GenerateFingerprint should fail for invalid base64")
		}
	})

	t.Run("empty string returns error", func(t *testing.T) {
		_, err := GenerateFingerprint("")
		if err == nil {
			t.Error("GenerateFingerprint should fail for empty string")
		}
	})
}
