package sshca

import (
	"strings"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	t.Run("ed25519 produces valid keypair", func(t *testing.T) {
		ca, err := GenerateCA("ed25519")
		if err != nil {
			t.Fatalf("GenerateCA failed: %v", err)
		}

		if ca.KeyType != "ed25519" {
			t.Errorf("KeyType = %q, want %q", ca.KeyType, "ed25519")
		}

		// ed25519 public key is 32 bytes
		if len(ca.PublicKey) != 32 {
			t.Errorf("PublicKey length = %d, want 32", len(ca.PublicKey))
		}

		// ed25519 private key is 64 bytes
		if len(ca.PrivateKey) != 64 {
			t.Errorf("PrivateKey length = %d, want 64", len(ca.PrivateKey))
		}

		if ca.CreatedAt.IsZero() {
			t.Error("CreatedAt should not be zero")
		}
	})

	t.Run("unsupported key type returns error", func(t *testing.T) {
		_, err := GenerateCA("rsa")
		if err == nil {
			t.Error("GenerateCA should fail for unsupported key type")
		}

		if !strings.Contains(err.Error(), "unsupported key type") {
			t.Errorf("error should mention unsupported key type, got: %v", err)
		}
	})
}

func TestPublicKeyString(t *testing.T) {
	ca, err := GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	pubKeyStr, err := ca.PublicKeyString()
	if err != nil {
		t.Fatalf("PublicKeyString failed: %v", err)
	}

	// Should start with ssh-ed25519
	if !strings.HasPrefix(pubKeyStr, "ssh-ed25519 ") {
		t.Errorf("PublicKeyString should start with 'ssh-ed25519 ', got: %s", pubKeyStr)
	}

	// Should be base64 encoded after the prefix
	parts := strings.Split(pubKeyStr, " ")
	if len(parts) < 2 {
		t.Error("PublicKeyString should have at least key type and base64 data")
	}

	// Base64 part should start with AAAA (standard SSH key encoding)
	if !strings.HasPrefix(parts[1], "AAAA") {
		t.Errorf("Base64 portion should start with AAAA, got: %s", parts[1][:4])
	}
}

func TestPublicKeyStringEmptyKey(t *testing.T) {
	ca := &CA{}
	_, err := ca.PublicKeyString()
	if err == nil {
		t.Error("PublicKeyString should fail for empty public key")
	}
}

func TestMarshalUnmarshalPrivateKey(t *testing.T) {
	ca, err := GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Marshal the private key
	marshaled, err := ca.MarshalPrivateKey()
	if err != nil {
		t.Fatalf("MarshalPrivateKey failed: %v", err)
	}

	// Check PEM format
	if !strings.Contains(string(marshaled), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("MarshalPrivateKey should produce OpenSSH PEM format")
	}

	if !strings.Contains(string(marshaled), "-----END OPENSSH PRIVATE KEY-----") {
		t.Error("MarshalPrivateKey should produce complete PEM block")
	}

	// Unmarshal and verify round-trip
	unmarshaled, err := UnmarshalPrivateKey(marshaled)
	if err != nil {
		t.Fatalf("UnmarshalPrivateKey failed: %v", err)
	}

	if len(unmarshaled) != len(ca.PrivateKey) {
		t.Errorf("Unmarshaled key length = %d, want %d", len(unmarshaled), len(ca.PrivateKey))
	}

	for i := range unmarshaled {
		if unmarshaled[i] != ca.PrivateKey[i] {
			t.Errorf("Unmarshaled key differs at byte %d", i)
			break
		}
	}
}

func TestMarshalPrivateKeyEmpty(t *testing.T) {
	ca := &CA{}
	_, err := ca.MarshalPrivateKey()
	if err == nil {
		t.Error("MarshalPrivateKey should fail for empty private key")
	}
}

func TestUnmarshalPrivateKeyInvalid(t *testing.T) {
	_, err := UnmarshalPrivateKey([]byte("not a valid key"))
	if err == nil {
		t.Error("UnmarshalPrivateKey should fail for invalid data")
	}
}

func TestSigner(t *testing.T) {
	ca, err := GenerateCA("ed25519")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	signer, err := ca.Signer()
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	if signer == nil {
		t.Error("Signer should not be nil")
	}

	// Verify the signer's public key matches
	signerPubKey := signer.PublicKey()
	if signerPubKey.Type() != "ssh-ed25519" {
		t.Errorf("Signer public key type = %q, want %q", signerPubKey.Type(), "ssh-ed25519")
	}
}

func TestSignerEmptyKey(t *testing.T) {
	ca := &CA{}
	_, err := ca.Signer()
	if err == nil {
		t.Error("Signer should fail for empty private key")
	}
}
