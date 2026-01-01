package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func generateTestUserKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create SSH public key: %v", err)
	}

	authorized := ssh.MarshalAuthorizedKey(sshPub)
	return string(authorized[:len(authorized)-1])
}

func TestSignCertificate(t *testing.T) {
	ca, err := GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	userPubKey := generateTestUserKey(t)

	t.Run("valid principal", func(t *testing.T) {
		opts := CertOptions{
			Principal:   "alice",
			ValidBefore: time.Now().Add(8 * time.Hour),
		}

		certStr, err := ca.SignCertificate(userPubKey, opts)
		if err != nil {
			t.Fatalf("SignCertificate failed: %v", err)
		}

		// Should be a certificate (contains -cert-)
		if !strings.Contains(certStr, "-cert-") {
			t.Errorf("certificate should contain '-cert-' in key type, got: %s", certStr[:50])
		}
	})

	t.Run("missing principal returns error", func(t *testing.T) {
		opts := CertOptions{
			ValidBefore: time.Now().Add(8 * time.Hour),
		}

		_, err := ca.SignCertificate(userPubKey, opts)
		if err == nil {
			t.Error("SignCertificate should fail without principal")
		}

		if !strings.Contains(err.Error(), "principal is required") {
			t.Errorf("error should mention principal, got: %v", err)
		}
	})

	t.Run("missing validity returns error", func(t *testing.T) {
		opts := CertOptions{
			Principal: "alice",
		}

		_, err := ca.SignCertificate(userPubKey, opts)
		if err == nil {
			t.Error("SignCertificate should fail without ValidBefore")
		}

		if !strings.Contains(err.Error(), "validity period") {
			t.Errorf("error should mention validity period, got: %v", err)
		}
	})

	t.Run("invalid public key returns error", func(t *testing.T) {
		opts := CertOptions{
			Principal:   "alice",
			ValidBefore: time.Now().Add(8 * time.Hour),
		}

		_, err := ca.SignCertificate("not a valid key", opts)
		if err == nil {
			t.Error("SignCertificate should fail for invalid public key")
		}

		if !strings.Contains(err.Error(), "failed to parse user public key") {
			t.Errorf("error should mention parsing failure, got: %v", err)
		}
	})
}

func TestCertificateValidityPeriod(t *testing.T) {
	ca, err := GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	userPubKey := generateTestUserKey(t)

	validAfter := time.Now().Truncate(time.Second)
	validBefore := validAfter.Add(24 * time.Hour)

	opts := CertOptions{
		Principal:   "bob",
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
	}

	certStr, err := ca.SignCertificate(userPubKey, opts)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	// Parse the certificate
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("parsed key is not a certificate")
	}

	// Verify validity period
	if cert.ValidAfter != uint64(validAfter.Unix()) {
		t.Errorf("ValidAfter = %d, want %d", cert.ValidAfter, validAfter.Unix())
	}

	if cert.ValidBefore != uint64(validBefore.Unix()) {
		t.Errorf("ValidBefore = %d, want %d", cert.ValidBefore, validBefore.Unix())
	}
}

func TestCertificateParseable(t *testing.T) {
	ca, err := GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	userPubKey := generateTestUserKey(t)

	opts := CertOptions{
		Principal:   "charlie",
		ValidBefore: time.Now().Add(8 * time.Hour),
		Extensions:  []string{"permit-pty", "permit-agent-forwarding"},
		KeyID:       "custom-key-id",
	}

	certStr, err := ca.SignCertificate(userPubKey, opts)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	// Parse with golang.org/x/crypto/ssh
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("failed to parse certificate with ssh package: %v", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("parsed key is not a certificate")
	}

	// Verify certificate fields
	if cert.KeyId != "custom-key-id" {
		t.Errorf("KeyId = %q, want %q", cert.KeyId, "custom-key-id")
	}

	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "charlie" {
		t.Errorf("ValidPrincipals = %v, want [charlie]", cert.ValidPrincipals)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want %d (UserCert)", cert.CertType, ssh.UserCert)
	}

	// Verify extensions
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Error("certificate should have permit-pty extension")
	}

	if _, ok := cert.Extensions["permit-agent-forwarding"]; !ok {
		t.Error("certificate should have permit-agent-forwarding extension")
	}
}

func TestCertificateDefaultExtensions(t *testing.T) {
	ca, err := GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	userPubKey := generateTestUserKey(t)

	opts := CertOptions{
		Principal:   "dave",
		ValidBefore: time.Now().Add(8 * time.Hour),
		// Extensions not specified, should use defaults
	}

	certStr, err := ca.SignCertificate(userPubKey, opts)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cert := pubKey.(*ssh.Certificate)

	// Check default extensions
	defaults := DefaultExtensions()
	for _, ext := range defaults {
		if _, ok := cert.Extensions[ext]; !ok {
			t.Errorf("certificate should have default extension %q", ext)
		}
	}
}

func TestCertificateAutoGeneratedKeyID(t *testing.T) {
	ca, err := GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	userPubKey := generateTestUserKey(t)

	opts := CertOptions{
		Principal:   "eve",
		ValidBefore: time.Now().Add(8 * time.Hour),
		// KeyID not specified, should be auto-generated
	}

	certStr, err := ca.SignCertificate(userPubKey, opts)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cert := pubKey.(*ssh.Certificate)

	// KeyID should be in format "{principal}-{unix_timestamp}"
	if !strings.HasPrefix(cert.KeyId, "eve-") {
		t.Errorf("auto-generated KeyId should start with 'eve-', got: %q", cert.KeyId)
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"8h", 8 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"0.5d", 12 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"", 0, true},
		{"invalid", 0, true},
		{"xd", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			d, err := ParseDuration(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if d != tc.expected {
				t.Errorf("ParseDuration(%q) = %v, want %v", tc.input, d, tc.expected)
			}
		})
	}
}

func TestParseDurationWithWhitespace(t *testing.T) {
	d, err := ParseDuration("  8h  ")
	if err != nil {
		t.Fatalf("ParseDuration should handle whitespace: %v", err)
	}

	if d != 8*time.Hour {
		t.Errorf("ParseDuration with whitespace = %v, want %v", d, 8*time.Hour)
	}
}
