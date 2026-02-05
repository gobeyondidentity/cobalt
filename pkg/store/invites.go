// InviteCode store methods.
package store

import (
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ----- Invite Code Methods -----

// CreateInviteCode stores a new invite code.
func (s *Store) CreateInviteCode(ic *InviteCode) error {
	_, err := s.db.Exec(
		`INSERT INTO invite_codes (id, code_hash, operator_email, tenant_id, role, created_by, expires_at, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ic.ID, ic.CodeHash, ic.OperatorEmail, ic.TenantID, ic.Role, ic.CreatedBy,
		ic.ExpiresAt.Unix(), ic.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to create invite code: %w", err)
	}
	return nil
}

// GetInviteCodeByHash retrieves an invite code by its hash.
func (s *Store) GetInviteCodeByHash(hash string) (*InviteCode, error) {
	row := s.db.QueryRow(
		`SELECT id, code_hash, operator_email, tenant_id, role, created_by, created_at, expires_at, used_at, used_by_keymaker, status
		 FROM invite_codes WHERE code_hash = ?`,
		hash,
	)
	return s.scanInviteCode(row)
}

// GetInviteCodeByID retrieves an invite code by its ID.
func (s *Store) GetInviteCodeByID(id string) (*InviteCode, error) {
	row := s.db.QueryRow(
		`SELECT id, code_hash, operator_email, tenant_id, role, created_by, created_at, expires_at, used_at, used_by_keymaker, status
		 FROM invite_codes WHERE id = ?`,
		id,
	)
	return s.scanInviteCode(row)
}

// ListInviteCodes returns all invite codes.
func (s *Store) ListInviteCodes() ([]*InviteCode, error) {
	rows, err := s.db.Query(
		`SELECT id, code_hash, operator_email, tenant_id, role, created_by, created_at, expires_at, used_at, used_by_keymaker, status
		 FROM invite_codes ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list invite codes: %w", err)
	}
	defer rows.Close()

	var codes []*InviteCode
	for rows.Next() {
		ic, err := s.scanInviteCodeRows(rows)
		if err != nil {
			return nil, err
		}
		codes = append(codes, ic)
	}
	return codes, rows.Err()
}

// ListInviteCodesByTenant returns all invite codes for a specific tenant.
func (s *Store) ListInviteCodesByTenant(tenantID string) ([]*InviteCode, error) {
	rows, err := s.db.Query(
		`SELECT id, code_hash, operator_email, tenant_id, role, created_by, created_at, expires_at, used_at, used_by_keymaker, status
		 FROM invite_codes WHERE tenant_id = ? ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list invite codes by tenant: %w", err)
	}
	defer rows.Close()

	var codes []*InviteCode
	for rows.Next() {
		ic, err := s.scanInviteCodeRows(rows)
		if err != nil {
			return nil, err
		}
		codes = append(codes, ic)
	}
	return codes, rows.Err()
}

// MarkInviteCodeUsed marks an invite code as used by a KeyMaker.
func (s *Store) MarkInviteCodeUsed(id, keymakerID string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE invite_codes SET status = 'used', used_at = ?, used_by_keymaker = ? WHERE id = ?`,
		now, keymakerID, id,
	)
	if err != nil {
		return fmt.Errorf("failed to mark invite code used: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("invite code not found: %s", id)
	}
	return nil
}

// ConsumeInviteCode atomically marks an invite code as consumed.
// Uses UPDATE WHERE status='pending' AND expires_at > now to prevent race conditions.
// Returns error if code not found, already consumed, or expired.
//
// This follows the pattern from CompleteEnrollmentSession for atomic state transitions.
func (s *Store) ConsumeInviteCode(id, keymakerID string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE invite_codes SET status = 'used', used_at = ?, used_by_keymaker = ?
		 WHERE id = ? AND status = 'pending' AND expires_at > ?`,
		now, keymakerID, id, now,
	)
	if err != nil {
		return fmt.Errorf("failed to consume invite code: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("invite code not found, already consumed, or expired")
	}
	return nil
}

// RevokeInviteCode marks an invite code as revoked.
func (s *Store) RevokeInviteCode(id string) error {
	result, err := s.db.Exec(
		`UPDATE invite_codes SET status = 'revoked' WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke invite code: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("invite code not found: %s", id)
	}
	return nil
}

// CleanupExpiredInvites marks all expired invite codes as expired.
func (s *Store) CleanupExpiredInvites() error {
	now := time.Now().Unix()
	_, err := s.db.Exec(
		`UPDATE invite_codes SET status = 'expired' WHERE status = 'pending' AND expires_at < ?`,
		now,
	)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired invites: %w", err)
	}
	return nil
}

// DeleteInviteCode deletes an invite code by ID.
func (s *Store) DeleteInviteCode(id string) error {
	result, err := s.db.Exec(`DELETE FROM invite_codes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete invite code: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("invite code not found: %s", id)
	}
	return nil
}

func (s *Store) scanInviteCode(row *sql.Row) (*InviteCode, error) {
	var ic InviteCode
	var createdAt, expiresAt int64
	var usedAt sql.NullInt64
	var usedByKeyMaker sql.NullString

	err := row.Scan(&ic.ID, &ic.CodeHash, &ic.OperatorEmail, &ic.TenantID, &ic.Role,
		&ic.CreatedBy, &createdAt, &expiresAt, &usedAt, &usedByKeyMaker, &ic.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invite code not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan invite code: %w", err)
	}

	ic.CreatedAt = time.Unix(createdAt, 0)
	ic.ExpiresAt = time.Unix(expiresAt, 0)
	if usedAt.Valid {
		t := time.Unix(usedAt.Int64, 0)
		ic.UsedAt = &t
	}
	if usedByKeyMaker.Valid {
		ic.UsedByKeyMaker = &usedByKeyMaker.String
	}

	return &ic, nil
}

func (s *Store) scanInviteCodeRows(rows *sql.Rows) (*InviteCode, error) {
	var ic InviteCode
	var createdAt, expiresAt int64
	var usedAt sql.NullInt64
	var usedByKeyMaker sql.NullString

	err := rows.Scan(&ic.ID, &ic.CodeHash, &ic.OperatorEmail, &ic.TenantID, &ic.Role,
		&ic.CreatedBy, &createdAt, &expiresAt, &usedAt, &usedByKeyMaker, &ic.Status)
	if err != nil {
		return nil, fmt.Errorf("failed to scan invite code: %w", err)
	}

	ic.CreatedAt = time.Unix(createdAt, 0)
	ic.ExpiresAt = time.Unix(expiresAt, 0)
	if usedAt.Valid {
		t := time.Unix(usedAt.Int64, 0)
		ic.UsedAt = &t
	}
	if usedByKeyMaker.Valid {
		ic.UsedByKeyMaker = &usedByKeyMaker.String
	}

	return &ic, nil
}

// ----- Invite Code Helpers -----

// GenerateInviteCode creates a new invite code with the given prefix.
// Format: PREFIX-XXXX-XXXX where X is uppercase alphanumeric.
func GenerateInviteCode(prefix string) string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude confusing chars: 0,O,1,I
	code := make([]byte, 8)
	randomBytes := make([]byte, 8)
	cryptoRand.Read(randomBytes)

	for i := range code {
		code[i] = charset[randomBytes[i]%byte(len(charset))]
	}

	// Strip trailing dashes from prefix to avoid double-dash in output
	cleanPrefix := strings.TrimRight(strings.ToUpper(prefix), "-")

	return fmt.Sprintf("%s-%s-%s", cleanPrefix, string(code[:4]), string(code[4:]))
}

// HashInviteCode returns the SHA-256 hash of an invite code.
func HashInviteCode(code string) string {
	hash := sha256.Sum256([]byte(code))
	return hex.EncodeToString(hash[:])
}
