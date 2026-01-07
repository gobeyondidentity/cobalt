// Package store provides SQLite-based storage for DPU registry.
// This file contains methods for identity entities: Operators, OperatorTenants, KeyMakers, and InviteCodes.
// Type definitions are in sqlite.go.
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

// ----- Operator Methods -----

// CreateOperator creates a new operator with pending status.
func (s *Store) CreateOperator(id, email, displayName string) error {
	_, err := s.db.Exec(
		`INSERT INTO operators (id, email, display_name, status) VALUES (?, ?, ?, 'pending')`,
		id, email, displayName,
	)
	if err != nil {
		return fmt.Errorf("failed to create operator: %w", err)
	}
	return nil
}

// GetOperator retrieves an operator by ID or email.
func (s *Store) GetOperator(idOrEmail string) (*Operator, error) {
	row := s.db.QueryRow(
		`SELECT id, email, display_name, status, created_at, last_login FROM operators WHERE id = ? OR email = ?`,
		idOrEmail, idOrEmail,
	)
	return s.scanOperator(row)
}

// GetOperatorByEmail retrieves an operator by email address.
func (s *Store) GetOperatorByEmail(email string) (*Operator, error) {
	row := s.db.QueryRow(
		`SELECT id, email, display_name, status, created_at, last_login FROM operators WHERE email = ?`,
		email,
	)
	return s.scanOperator(row)
}

// ListOperators returns all operators.
func (s *Store) ListOperators() ([]*Operator, error) {
	rows, err := s.db.Query(
		`SELECT id, email, display_name, status, created_at, last_login FROM operators ORDER BY email`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list operators: %w", err)
	}
	defer rows.Close()

	var operators []*Operator
	for rows.Next() {
		op, err := s.scanOperatorRows(rows)
		if err != nil {
			return nil, err
		}
		operators = append(operators, op)
	}
	return operators, rows.Err()
}

// ListOperatorsByTenant returns all operators for a specific tenant.
func (s *Store) ListOperatorsByTenant(tenantID string) ([]*Operator, error) {
	rows, err := s.db.Query(
		`SELECT o.id, o.email, o.display_name, o.status, o.created_at, o.last_login
		 FROM operators o
		 INNER JOIN operator_tenants ot ON o.id = ot.operator_id
		 WHERE ot.tenant_id = ?
		 ORDER BY o.email`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list operators by tenant: %w", err)
	}
	defer rows.Close()

	var operators []*Operator
	for rows.Next() {
		op, err := s.scanOperatorRows(rows)
		if err != nil {
			return nil, err
		}
		operators = append(operators, op)
	}
	return operators, rows.Err()
}

// UpdateOperatorStatus updates an operator's status.
func (s *Store) UpdateOperatorStatus(id, status string) error {
	result, err := s.db.Exec(
		`UPDATE operators SET status = ? WHERE id = ?`,
		status, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update operator status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// UpdateOperatorLastLogin updates the last login timestamp for an operator.
func (s *Store) UpdateOperatorLastLogin(id string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE operators SET last_login = ? WHERE id = ?`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update operator last login: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

func (s *Store) scanOperator(row *sql.Row) (*Operator, error) {
	var op Operator
	var displayName sql.NullString
	var lastLogin sql.NullInt64
	var createdAt int64

	err := row.Scan(&op.ID, &op.Email, &displayName, &op.Status, &createdAt, &lastLogin)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("operator not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan operator: %w", err)
	}

	if displayName.Valid {
		op.DisplayName = displayName.String
	}
	if lastLogin.Valid {
		t := time.Unix(lastLogin.Int64, 0)
		op.LastLogin = &t
	}
	op.CreatedAt = time.Unix(createdAt, 0)

	return &op, nil
}

func (s *Store) scanOperatorRows(rows *sql.Rows) (*Operator, error) {
	var op Operator
	var displayName sql.NullString
	var lastLogin sql.NullInt64
	var createdAt int64

	err := rows.Scan(&op.ID, &op.Email, &displayName, &op.Status, &createdAt, &lastLogin)
	if err != nil {
		return nil, fmt.Errorf("failed to scan operator: %w", err)
	}

	if displayName.Valid {
		op.DisplayName = displayName.String
	}
	if lastLogin.Valid {
		t := time.Unix(lastLogin.Int64, 0)
		op.LastLogin = &t
	}
	op.CreatedAt = time.Unix(createdAt, 0)

	return &op, nil
}

// ----- Operator-Tenant Methods -----

// AddOperatorToTenant adds an operator to a tenant with a specific role.
func (s *Store) AddOperatorToTenant(operatorID, tenantID, role string) error {
	_, err := s.db.Exec(
		`INSERT INTO operator_tenants (operator_id, tenant_id, role) VALUES (?, ?, ?)`,
		operatorID, tenantID, role,
	)
	if err != nil {
		return fmt.Errorf("failed to add operator to tenant: %w", err)
	}
	return nil
}

// RemoveOperatorFromTenant removes an operator from a tenant.
func (s *Store) RemoveOperatorFromTenant(operatorID, tenantID string) error {
	result, err := s.db.Exec(
		`DELETE FROM operator_tenants WHERE operator_id = ? AND tenant_id = ?`,
		operatorID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove operator from tenant: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator-tenant membership not found")
	}
	return nil
}

// GetOperatorTenants returns all tenant memberships for an operator.
func (s *Store) GetOperatorTenants(operatorID string) ([]*OperatorTenant, error) {
	rows, err := s.db.Query(
		`SELECT operator_id, tenant_id, role, created_at FROM operator_tenants WHERE operator_id = ?`,
		operatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get operator tenants: %w", err)
	}
	defer rows.Close()

	var memberships []*OperatorTenant
	for rows.Next() {
		var ot OperatorTenant
		var createdAt int64
		err := rows.Scan(&ot.OperatorID, &ot.TenantID, &ot.Role, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan operator tenant: %w", err)
		}
		ot.CreatedAt = time.Unix(createdAt, 0)
		memberships = append(memberships, &ot)
	}
	return memberships, rows.Err()
}

// GetOperatorRole returns the role of an operator in a specific tenant.
func (s *Store) GetOperatorRole(operatorID, tenantID string) (string, error) {
	var role string
	err := s.db.QueryRow(
		`SELECT role FROM operator_tenants WHERE operator_id = ? AND tenant_id = ?`,
		operatorID, tenantID,
	).Scan(&role)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("operator-tenant membership not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get operator role: %w", err)
	}
	return role, nil
}

// ----- KeyMaker Methods -----

// CreateKeyMaker stores a new KeyMaker binding.
func (s *Store) CreateKeyMaker(km *KeyMaker) error {
	_, err := s.db.Exec(
		`INSERT INTO keymakers (id, operator_id, name, platform, secure_element, device_fingerprint, public_key, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		km.ID, km.OperatorID, km.Name, km.Platform, km.SecureElement, km.DeviceFingerprint, km.PublicKey, km.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to create keymaker: %w", err)
	}
	return nil
}

// GetKeyMaker retrieves a KeyMaker by ID.
func (s *Store) GetKeyMaker(id string) (*KeyMaker, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status
		 FROM keymakers WHERE id = ?`,
		id,
	)
	return s.scanKeyMaker(row)
}

// GetKeyMakerByPublicKey retrieves a KeyMaker by its public key.
func (s *Store) GetKeyMakerByPublicKey(pubKey string) (*KeyMaker, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status
		 FROM keymakers WHERE public_key = ?`,
		pubKey,
	)
	return s.scanKeyMaker(row)
}

// ListKeyMakersByOperator returns all KeyMakers for an operator.
func (s *Store) ListKeyMakersByOperator(operatorID string) ([]*KeyMaker, error) {
	rows, err := s.db.Query(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status
		 FROM keymakers WHERE operator_id = ? ORDER BY bound_at DESC`,
		operatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list keymakers: %w", err)
	}
	defer rows.Close()

	var keymakers []*KeyMaker
	for rows.Next() {
		km, err := s.scanKeyMakerRows(rows)
		if err != nil {
			return nil, err
		}
		keymakers = append(keymakers, km)
	}
	return keymakers, rows.Err()
}

// UpdateKeyMakerLastSeen updates the last seen timestamp for a KeyMaker.
func (s *Store) UpdateKeyMakerLastSeen(id string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE keymakers SET last_seen = ? WHERE id = ?`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update keymaker last seen: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("keymaker not found: %s", id)
	}
	return nil
}

// RevokeKeyMaker marks a KeyMaker as revoked.
func (s *Store) RevokeKeyMaker(id string) error {
	result, err := s.db.Exec(
		`UPDATE keymakers SET status = 'revoked' WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke keymaker: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("keymaker not found: %s", id)
	}
	return nil
}

func (s *Store) scanKeyMaker(row *sql.Row) (*KeyMaker, error) {
	var km KeyMaker
	var boundAt int64
	var lastSeen sql.NullInt64

	err := row.Scan(&km.ID, &km.OperatorID, &km.Name, &km.Platform, &km.SecureElement,
		&km.DeviceFingerprint, &km.PublicKey, &boundAt, &lastSeen, &km.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("keymaker not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan keymaker: %w", err)
	}

	km.BoundAt = time.Unix(boundAt, 0)
	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		km.LastSeen = &t
	}

	return &km, nil
}

func (s *Store) scanKeyMakerRows(rows *sql.Rows) (*KeyMaker, error) {
	var km KeyMaker
	var boundAt int64
	var lastSeen sql.NullInt64

	err := rows.Scan(&km.ID, &km.OperatorID, &km.Name, &km.Platform, &km.SecureElement,
		&km.DeviceFingerprint, &km.PublicKey, &boundAt, &lastSeen, &km.Status)
	if err != nil {
		return nil, fmt.Errorf("failed to scan keymaker: %w", err)
	}

	km.BoundAt = time.Unix(boundAt, 0)
	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		km.LastSeen = &t
	}

	return &km, nil
}

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
