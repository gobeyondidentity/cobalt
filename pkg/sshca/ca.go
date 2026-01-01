// Package sshca provides SSH Certificate Authority functionality.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// CA represents an SSH Certificate Authority.
type CA struct {
	ID         string
	Name       string
	KeyType    string    // "ed25519"
	PublicKey  []byte    // Raw public key bytes
	PrivateKey []byte    // Raw private key bytes (encrypted at rest, decrypted in memory)
	CreatedAt  time.Time
}

// GenerateCA creates a new Ed25519 SSH CA keypair.
func GenerateCA(keyType string) (*CA, error) {
	if keyType != "ed25519" {
		return nil, fmt.Errorf("unsupported key type: %s (only ed25519 is supported)", keyType)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}

	return &CA{
		KeyType:    keyType,
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now(),
	}, nil
}

// PublicKeyString returns the public key in OpenSSH authorized_keys format.
// e.g., "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
func (ca *CA) PublicKeyString() (string, error) {
	if len(ca.PublicKey) == 0 {
		return "", fmt.Errorf("public key is empty")
	}

	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(ca.PublicKey))
	if err != nil {
		return "", fmt.Errorf("failed to create SSH public key: %w", err)
	}

	// MarshalAuthorizedKey returns the key in authorized_keys format with a trailing newline
	return string(ssh.MarshalAuthorizedKey(sshPub)[:len(ssh.MarshalAuthorizedKey(sshPub))-1]), nil
}

// MarshalPrivateKey serializes the private key for storage.
// Returns the private key in OpenSSH PEM format.
func (ca *CA) MarshalPrivateKey() ([]byte, error) {
	if len(ca.PrivateKey) == 0 {
		return nil, fmt.Errorf("private key is empty")
	}

	// Convert to crypto.Signer for ssh.MarshalPrivateKey
	privKey := ed25519.PrivateKey(ca.PrivateKey)

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// UnmarshalPrivateKey deserializes a private key from storage.
// Accepts OpenSSH PEM format and returns raw ed25519 private key bytes.
func UnmarshalPrivateKey(data []byte) ([]byte, error) {
	rawKey, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519Key, ok := rawKey.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ed25519")
	}

	return *ed25519Key, nil
}

// Signer returns an ssh.Signer for signing certificates.
func (ca *CA) Signer() (ssh.Signer, error) {
	if len(ca.PrivateKey) == 0 {
		return nil, fmt.Errorf("private key is empty")
	}

	signer, err := ssh.NewSignerFromKey(ed25519.PrivateKey(ca.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return signer, nil
}
