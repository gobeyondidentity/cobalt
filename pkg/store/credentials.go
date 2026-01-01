// Package store provides SQLite-based storage for DPU registry.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// SSHCA represents a stored SSH Certificate Authority.
type SSHCA struct {
	ID         string
	Name       string
	PublicKey  []byte
	PrivateKey []byte // Decrypted in memory
	KeyType    string
	CreatedAt  time.Time
}

// CreateSSHCA stores a new SSH CA with encrypted private key.
func (s *Store) CreateSSHCA(id, name string, publicKey, privateKey []byte, keyType string) error {
	encryptedPrivateKey, err := EncryptPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO ssh_cas (id, name, public_key, encrypted_private_key, key_type) VALUES (?, ?, ?, ?, ?)`,
		id, name, publicKey, encryptedPrivateKey, keyType,
	)
	if err != nil {
		return fmt.Errorf("failed to create SSH CA: %w", err)
	}
	return nil
}

// GetSSHCA retrieves an SSH CA by name, decrypting the private key.
func (s *Store) GetSSHCA(name string) (*SSHCA, error) {
	row := s.db.QueryRow(
		`SELECT id, name, public_key, encrypted_private_key, key_type, created_at FROM ssh_cas WHERE name = ?`,
		name,
	)
	return s.scanSSHCA(row)
}

// GetSSHCAByID retrieves an SSH CA by ID, decrypting the private key.
func (s *Store) GetSSHCAByID(id string) (*SSHCA, error) {
	row := s.db.QueryRow(
		`SELECT id, name, public_key, encrypted_private_key, key_type, created_at FROM ssh_cas WHERE id = ?`,
		id,
	)
	return s.scanSSHCA(row)
}

// ListSSHCAs returns all SSH CAs (without private keys for listing).
func (s *Store) ListSSHCAs() ([]*SSHCA, error) {
	rows, err := s.db.Query(
		`SELECT id, name, public_key, key_type, created_at FROM ssh_cas ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list SSH CAs: %w", err)
	}
	defer rows.Close()

	var cas []*SSHCA
	for rows.Next() {
		ca, err := s.scanSSHCAListRow(rows)
		if err != nil {
			return nil, err
		}
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

// DeleteSSHCA removes an SSH CA by name.
func (s *Store) DeleteSSHCA(name string) error {
	result, err := s.db.Exec(`DELETE FROM ssh_cas WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("failed to delete SSH CA: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("SSH CA not found: %s", name)
	}
	return nil
}

// DeleteSSHCAByID removes an SSH CA by ID.
func (s *Store) DeleteSSHCAByID(id string) error {
	result, err := s.db.Exec(`DELETE FROM ssh_cas WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete SSH CA: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("SSH CA not found: %s", id)
	}
	return nil
}

// SSHCAExists checks if an SSH CA with the given name exists.
func (s *Store) SSHCAExists(name string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM ssh_cas WHERE name = ?`, name).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check SSH CA existence: %w", err)
	}
	return count > 0, nil
}

func (s *Store) scanSSHCA(row *sql.Row) (*SSHCA, error) {
	var ca SSHCA
	var encryptedPrivateKey []byte
	var createdAt int64

	err := row.Scan(&ca.ID, &ca.Name, &ca.PublicKey, &encryptedPrivateKey, &ca.KeyType, &createdAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("SSH CA not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan SSH CA: %w", err)
	}

	ca.PrivateKey, err = DecryptPrivateKey(encryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	ca.CreatedAt = time.Unix(createdAt, 0)
	return &ca, nil
}

func (s *Store) scanSSHCAListRow(rows *sql.Rows) (*SSHCA, error) {
	var ca SSHCA
	var createdAt int64

	err := rows.Scan(&ca.ID, &ca.Name, &ca.PublicKey, &ca.KeyType, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to scan SSH CA: %w", err)
	}

	ca.CreatedAt = time.Unix(createdAt, 0)
	// PrivateKey intentionally left nil for list operations
	return &ca, nil
}
