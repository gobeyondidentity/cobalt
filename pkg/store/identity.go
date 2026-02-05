// This file contains methods for identity entities: Operators, OperatorTenants, KeyMakers, and InviteCodes.
// Type definitions are in sqlite.go.
package store

import (
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
		`SELECT id, email, display_name, status, created_at, last_login, suspended_at, suspended_by, suspended_reason FROM operators WHERE id = ? OR email = ?`,
		idOrEmail, idOrEmail,
	)
	return s.scanOperator(row)
}

// GetOperatorByEmail retrieves an operator by email address.
func (s *Store) GetOperatorByEmail(email string) (*Operator, error) {
	row := s.db.QueryRow(
		`SELECT id, email, display_name, status, created_at, last_login, suspended_at, suspended_by, suspended_reason FROM operators WHERE email = ?`,
		email,
	)
	return s.scanOperator(row)
}

// ListOperators returns all operators.
func (s *Store) ListOperators() ([]*Operator, error) {
	rows, err := s.db.Query(
		`SELECT id, email, display_name, status, created_at, last_login, suspended_at, suspended_by, suspended_reason FROM operators ORDER BY email`,
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
		`SELECT o.id, o.email, o.display_name, o.status, o.created_at, o.last_login, o.suspended_at, o.suspended_by, o.suspended_reason
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

// SuspendOperator suspends an operator, blocking all their KeyMakers.
// Records who performed the suspension and why for audit compliance.
func (s *Store) SuspendOperator(id, suspendedBy, reason string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE operators SET status = 'suspended', suspended_at = ?, suspended_by = ?, suspended_reason = ? WHERE id = ?`,
		now, suspendedBy, reason, id,
	)
	if err != nil {
		return fmt.Errorf("failed to suspend operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// UnsuspendOperator restores a suspended operator to active status.
// Clears the suspension tracking fields.
func (s *Store) UnsuspendOperator(id string) error {
	result, err := s.db.Exec(
		`UPDATE operators SET status = 'active', suspended_at = NULL, suspended_by = NULL, suspended_reason = NULL WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to unsuspend operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// SuspendOperatorAtomic atomically suspends an operator if not already suspended.
// Returns ErrOperatorAlreadySuspended if the operator is already suspended (for 409 response).
// Returns "operator not found" error if the operator does not exist.
func (s *Store) SuspendOperatorAtomic(id, suspendedBy, reason string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE operators SET status = 'suspended', suspended_at = ?, suspended_by = ?, suspended_reason = ?
		 WHERE id = ? AND status != 'suspended'`,
		now, suspendedBy, reason, id,
	)
	if err != nil {
		return fmt.Errorf("failed to suspend operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Check if the operator exists but is already suspended
		op, err := s.GetOperator(id)
		if err != nil {
			return fmt.Errorf("operator not found: %s", id)
		}
		if op.Status == "suspended" {
			return ErrOperatorAlreadySuspended
		}
		// This shouldn't happen, but handle it
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// UnsuspendOperatorAtomic atomically unsuspends an operator if currently suspended.
// Returns ErrOperatorNotSuspended if the operator is not suspended (for 409 response).
// Returns "operator not found" error if the operator does not exist.
func (s *Store) UnsuspendOperatorAtomic(id string) error {
	result, err := s.db.Exec(
		`UPDATE operators SET status = 'active', suspended_at = NULL, suspended_by = NULL, suspended_reason = NULL
		 WHERE id = ? AND status = 'suspended'`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to unsuspend operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Check if the operator exists but is not suspended
		op, err := s.GetOperator(id)
		if err != nil {
			return fmt.Errorf("operator not found: %s", id)
		}
		if op.Status != "suspended" {
			return ErrOperatorNotSuspended
		}
		// This shouldn't happen, but handle it
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

func (s *Store) scanOperator(row *sql.Row) (*Operator, error) {
	var op Operator
	var displayName sql.NullString
	var lastLogin sql.NullInt64
	var createdAt int64
	var suspendedAt sql.NullInt64
	var suspendedBy sql.NullString
	var suspendedReason sql.NullString

	err := row.Scan(&op.ID, &op.Email, &displayName, &op.Status, &createdAt, &lastLogin,
		&suspendedAt, &suspendedBy, &suspendedReason)
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
	if suspendedAt.Valid {
		t := time.Unix(suspendedAt.Int64, 0)
		op.SuspendedAt = &t
	}
	if suspendedBy.Valid {
		op.SuspendedBy = &suspendedBy.String
	}
	if suspendedReason.Valid {
		op.SuspendedReason = &suspendedReason.String
	}

	return &op, nil
}

func (s *Store) scanOperatorRows(rows *sql.Rows) (*Operator, error) {
	var op Operator
	var displayName sql.NullString
	var lastLogin sql.NullInt64
	var createdAt int64
	var suspendedAt sql.NullInt64
	var suspendedBy sql.NullString
	var suspendedReason sql.NullString

	err := rows.Scan(&op.ID, &op.Email, &displayName, &op.Status, &createdAt, &lastLogin,
		&suspendedAt, &suspendedBy, &suspendedReason)
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
	if suspendedAt.Valid {
		t := time.Unix(suspendedAt.Int64, 0)
		op.SuspendedAt = &t
	}
	if suspendedBy.Valid {
		op.SuspendedBy = &suspendedBy.String
	}
	if suspendedReason.Valid {
		op.SuspendedReason = &suspendedReason.String
	}

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

// UpdateOperatorRole updates or creates an operator's role in a tenant.
// Uses upsert semantics: if the membership exists, updates the role;
// if it doesn't exist, creates a new membership.
func (s *Store) UpdateOperatorRole(operatorID, tenantID, role string) error {
	_, err := s.db.Exec(
		`INSERT INTO operator_tenants (operator_id, tenant_id, role) VALUES (?, ?, ?)
		 ON CONFLICT(operator_id, tenant_id) DO UPDATE SET role = excluded.role`,
		operatorID, tenantID, role,
	)
	if err != nil {
		return fmt.Errorf("failed to update operator role: %w", err)
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

// IsSuperAdmin checks if an operator has super:admin role in any tenant.
// Per ADR-011, super:admin in any tenant grants global access.
func (s *Store) IsSuperAdmin(operatorID string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM operator_tenants WHERE operator_id = ? AND role = 'super:admin'`,
		operatorID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check super admin status: %w", err)
	}
	return count > 0, nil
}

// ----- KeyMaker Methods -----

// CreateKeyMaker stores a new KeyMaker binding.
func (s *Store) CreateKeyMaker(km *KeyMaker) error {
	_, err := s.db.Exec(
		`INSERT INTO keymakers (id, operator_id, name, platform, secure_element, device_fingerprint, public_key, status, kid, key_fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		km.ID, km.OperatorID, km.Name, km.Platform, km.SecureElement, km.DeviceFingerprint, km.PublicKey, km.Status, km.Kid, km.KeyFingerprint,
	)
	if err != nil {
		return fmt.Errorf("failed to create keymaker: %w", err)
	}
	return nil
}

// GetKeyMaker retrieves a KeyMaker by ID.
func (s *Store) GetKeyMaker(id string) (*KeyMaker, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status, revoked_at, revoked_by, revoked_reason
		 FROM keymakers WHERE id = ?`,
		id,
	)
	return s.scanKeyMaker(row)
}

// GetKeyMakerByPublicKey retrieves a KeyMaker by its public key.
func (s *Store) GetKeyMakerByPublicKey(pubKey string) (*KeyMaker, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status, revoked_at, revoked_by, revoked_reason
		 FROM keymakers WHERE public_key = ?`,
		pubKey,
	)
	return s.scanKeyMaker(row)
}

// GetKeyMakerByFingerprint retrieves a KeyMaker by its key fingerprint.
// Used for duplicate key detection during enrollment.
func (s *Store) GetKeyMakerByFingerprint(fingerprint string) (*KeyMaker, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status, kid, key_fingerprint, revoked_at, revoked_by, revoked_reason
		 FROM keymakers WHERE key_fingerprint = ?`,
		fingerprint,
	)
	return s.scanKeyMakerWithDPoP(row)
}

// ListKeyMakersByOperator returns all KeyMakers for an operator.
func (s *Store) ListKeyMakersByOperator(operatorID string) ([]*KeyMaker, error) {
	rows, err := s.db.Query(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status, revoked_at, revoked_by, revoked_reason
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

// ListAllKeyMakers returns all KeyMakers regardless of status, ordered by bound_at DESC.
func (s *Store) ListAllKeyMakers() ([]*KeyMaker, error) {
	rows, err := s.db.Query(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status, revoked_at, revoked_by, revoked_reason
		 FROM keymakers ORDER BY bound_at DESC`,
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
// Deprecated: Use RevokeKeyMakerWithReason for proper audit tracking.
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

// RevokeKeyMakerWithReason marks a KeyMaker as revoked with full audit tracking.
// Records who performed the revocation and why for audit compliance.
func (s *Store) RevokeKeyMakerWithReason(id, revokedBy, reason string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE keymakers SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = ? WHERE id = ?`,
		now, revokedBy, reason, id,
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

// ErrAlreadyRevoked is returned when attempting to revoke an already-revoked KeyMaker.
var ErrAlreadyRevoked = fmt.Errorf("keymaker already revoked")

// ErrAdminKeyAlreadyRevoked is returned when attempting to revoke an already-revoked AdminKey.
var ErrAdminKeyAlreadyRevoked = fmt.Errorf("admin key already revoked")

// ErrOperatorAlreadySuspended is returned when attempting to suspend an already-suspended Operator.
var ErrOperatorAlreadySuspended = fmt.Errorf("operator already suspended")

// ErrOperatorNotSuspended is returned when attempting to unsuspend an Operator that is not suspended.
var ErrOperatorNotSuspended = fmt.Errorf("operator is not suspended")

// ErrWouldCauseLockout is returned when revoking an admin key would leave zero active super:admin keys.
var ErrWouldCauseLockout = fmt.Errorf("would cause system lockout")

// RevokeKeyMakerAtomic atomically revokes a KeyMaker if it is not already revoked.
// Returns ErrAlreadyRevoked if the KeyMaker is already revoked (for 409 response).
// Returns "keymaker not found" error if the KeyMaker does not exist.
func (s *Store) RevokeKeyMakerAtomic(id, revokedBy, reason string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE keymakers SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = ?
		 WHERE id = ? AND status != 'revoked'`,
		now, revokedBy, reason, id,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke keymaker: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Check if the KeyMaker exists but is already revoked
		km, err := s.GetKeyMaker(id)
		if err != nil {
			return fmt.Errorf("keymaker not found: %s", id)
		}
		if km.Status == "revoked" {
			return ErrAlreadyRevoked
		}
		// This shouldn't happen, but handle it
		return fmt.Errorf("keymaker not found: %s", id)
	}
	return nil
}

func (s *Store) scanKeyMaker(row *sql.Row) (*KeyMaker, error) {
	var km KeyMaker
	var boundAt int64
	var lastSeen sql.NullInt64
	var revokedAt sql.NullInt64
	var revokedBy sql.NullString
	var revokedReason sql.NullString

	err := row.Scan(&km.ID, &km.OperatorID, &km.Name, &km.Platform, &km.SecureElement,
		&km.DeviceFingerprint, &km.PublicKey, &boundAt, &lastSeen, &km.Status,
		&revokedAt, &revokedBy, &revokedReason)
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
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		km.RevokedAt = &t
	}
	if revokedBy.Valid {
		km.RevokedBy = &revokedBy.String
	}
	if revokedReason.Valid {
		km.RevokedReason = &revokedReason.String
	}

	return &km, nil
}

func (s *Store) scanKeyMakerRows(rows *sql.Rows) (*KeyMaker, error) {
	var km KeyMaker
	var boundAt int64
	var lastSeen sql.NullInt64
	var revokedAt sql.NullInt64
	var revokedBy sql.NullString
	var revokedReason sql.NullString

	err := rows.Scan(&km.ID, &km.OperatorID, &km.Name, &km.Platform, &km.SecureElement,
		&km.DeviceFingerprint, &km.PublicKey, &boundAt, &lastSeen, &km.Status,
		&revokedAt, &revokedBy, &revokedReason)
	if err != nil {
		return nil, fmt.Errorf("failed to scan keymaker: %w", err)
	}

	km.BoundAt = time.Unix(boundAt, 0)
	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		km.LastSeen = &t
	}
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		km.RevokedAt = &t
	}
	if revokedBy.Valid {
		km.RevokedBy = &revokedBy.String
	}
	if revokedReason.Valid {
		km.RevokedReason = &revokedReason.String
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

// DeleteOperator deletes an operator by ID.
// Returns error if operator has dependencies (keymakers, authorizations).
// Tenant memberships are removed automatically.
func (s *Store) DeleteOperator(id string) error {
	// Check for keymakers
	keymakers, err := s.ListKeyMakersByOperator(id)
	if err != nil {
		return fmt.Errorf("failed to check keymakers: %w", err)
	}
	if len(keymakers) > 0 {
		return fmt.Errorf("operator has %d keymaker(s) that must be removed first", len(keymakers))
	}

	// Check for authorizations
	auths, err := s.ListAuthorizationsByOperator(id)
	if err != nil {
		return fmt.Errorf("failed to check authorizations: %w", err)
	}
	if len(auths) > 0 {
		return fmt.Errorf("operator has %d authorization(s) that must be revoked first", len(auths))
	}

	// Remove all tenant memberships first
	_, err = s.db.Exec(`DELETE FROM operator_tenants WHERE operator_id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to remove tenant memberships: %w", err)
	}

	// Delete operator
	result, err := s.db.Exec(`DELETE FROM operators WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
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

// ----- DPoP Key Lookup Methods -----

// KeyFingerprint computes SHA256 of raw public key bytes, returns hex-encoded string.
// Used for duplicate key detection and DPoP binding.
func KeyFingerprint(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString(hash[:])
}

// ----- Admin Key Methods -----

// CreateAdminKey stores a new admin key binding.
func (s *Store) CreateAdminKey(ak *AdminKey) error {
	_, err := s.db.Exec(
		`INSERT INTO admin_keys (id, operator_id, name, public_key, kid, key_fingerprint, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ak.ID, ak.OperatorID, ak.Name, ak.PublicKey, ak.Kid, ak.KeyFingerprint, ak.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to create admin key: %w", err)
	}
	return nil
}

// GetAdminKey retrieves an admin key by ID.
func (s *Store) GetAdminKey(id string) (*AdminKey, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, public_key, kid, key_fingerprint, status, bound_at, last_seen, revoked_at, revoked_by, revoked_reason
		 FROM admin_keys WHERE id = ?`,
		id,
	)
	return s.scanAdminKey(row)
}

// GetAdminKeyByKid retrieves an admin key by its DPoP key identifier.
// Used for O(1) lookup during DPoP token validation.
func (s *Store) GetAdminKeyByKid(kid string) (*AdminKey, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, public_key, kid, key_fingerprint, status, bound_at, last_seen, revoked_at, revoked_by, revoked_reason
		 FROM admin_keys WHERE kid = ?`,
		kid,
	)
	return s.scanAdminKey(row)
}

// GetAdminKeyByFingerprint retrieves an admin key by its key fingerprint.
// Used for duplicate key detection during enrollment.
func (s *Store) GetAdminKeyByFingerprint(fingerprint string) (*AdminKey, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, public_key, kid, key_fingerprint, status, bound_at, last_seen, revoked_at, revoked_by, revoked_reason
		 FROM admin_keys WHERE key_fingerprint = ?`,
		fingerprint,
	)
	return s.scanAdminKey(row)
}

// ListAdminKeysByOperator returns all admin keys for an operator.
func (s *Store) ListAdminKeysByOperator(operatorID string) ([]*AdminKey, error) {
	rows, err := s.db.Query(
		`SELECT id, operator_id, name, public_key, kid, key_fingerprint, status, bound_at, last_seen, revoked_at, revoked_by, revoked_reason
		 FROM admin_keys WHERE operator_id = ? ORDER BY bound_at DESC`,
		operatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list admin keys: %w", err)
	}
	defer rows.Close()

	var keys []*AdminKey
	for rows.Next() {
		ak, err := s.scanAdminKeyRows(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ak)
	}
	return keys, rows.Err()
}

// ListAdminKeys returns all admin keys, optionally filtered by status.
func (s *Store) ListAdminKeys(status string) ([]*AdminKey, error) {
	var query string
	var args []interface{}

	if status != "" {
		query = `SELECT id, operator_id, name, public_key, kid, key_fingerprint, status, bound_at, last_seen, revoked_at, revoked_by, revoked_reason
		         FROM admin_keys WHERE status = ? ORDER BY bound_at DESC`
		args = append(args, status)
	} else {
		query = `SELECT id, operator_id, name, public_key, kid, key_fingerprint, status, bound_at, last_seen, revoked_at, revoked_by, revoked_reason
		         FROM admin_keys ORDER BY bound_at DESC`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list admin keys: %w", err)
	}
	defer rows.Close()

	var keys []*AdminKey
	for rows.Next() {
		ak, err := s.scanAdminKeyRows(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ak)
	}
	return keys, rows.Err()
}

// UpdateAdminKeyLastSeen updates the last seen timestamp for an admin key.
func (s *Store) UpdateAdminKeyLastSeen(id string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE admin_keys SET last_seen = ? WHERE id = ?`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update admin key last seen: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("admin key not found: %s", id)
	}
	return nil
}

// RevokeAdminKey marks an admin key as revoked.
// Deprecated: Use RevokeAdminKeyWithReason for proper audit tracking.
func (s *Store) RevokeAdminKey(id string) error {
	result, err := s.db.Exec(
		`UPDATE admin_keys SET status = 'revoked' WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke admin key: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("admin key not found: %s", id)
	}
	return nil
}

// RevokeAdminKeyWithReason marks an admin key as revoked with full audit tracking.
// Records who performed the revocation and why for audit compliance.
func (s *Store) RevokeAdminKeyWithReason(id, revokedBy, reason string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE admin_keys SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = ? WHERE id = ?`,
		now, revokedBy, reason, id,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke admin key: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("admin key not found: %s", id)
	}
	return nil
}

// RevokeAdminKeyAtomic atomically revokes an AdminKey if it is not already revoked.
// Returns ErrAdminKeyAlreadyRevoked if the AdminKey is already revoked (for 409 response).
// Returns ErrWouldCauseLockout if revoking would leave zero active super:admin keys.
// Returns "admin key not found" error if the AdminKey does not exist.
func (s *Store) RevokeAdminKeyAtomic(id, revokedBy, reason string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if this admin key is active and belongs to a super:admin
	var isSuperAdminKey int
	err = tx.QueryRow(`
		SELECT COUNT(*)
		FROM admin_keys ak
		INNER JOIN operator_tenants ot ON ak.operator_id = ot.operator_id
		WHERE ak.id = ? AND ak.status = 'active' AND ot.role = 'super:admin'
	`, id).Scan(&isSuperAdminKey)
	if err != nil {
		return fmt.Errorf("failed to check super admin status: %w", err)
	}

	// If this key belongs to a super:admin, check if revoking would cause lockout
	if isSuperAdminKey > 0 {
		var totalActiveSuperAdminKeys int
		err = tx.QueryRow(`
			SELECT COUNT(DISTINCT ak.id)
			FROM admin_keys ak
			INNER JOIN operator_tenants ot ON ak.operator_id = ot.operator_id
			WHERE ak.status = 'active' AND ot.role = 'super:admin'
		`).Scan(&totalActiveSuperAdminKeys)
		if err != nil {
			return fmt.Errorf("failed to count active super admin keys: %w", err)
		}

		// If this is the only active super:admin key, reject
		if totalActiveSuperAdminKeys <= 1 {
			return ErrWouldCauseLockout
		}
	}

	// Perform the revocation
	now := time.Now().Unix()
	result, err := tx.Exec(
		`UPDATE admin_keys SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = ?
		 WHERE id = ? AND status != 'revoked'`,
		now, revokedBy, reason, id,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke admin key: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Check if the AdminKey exists but is already revoked
		var status string
		err := tx.QueryRow(`SELECT status FROM admin_keys WHERE id = ?`, id).Scan(&status)
		if err != nil {
			return fmt.Errorf("admin key not found: %s", id)
		}
		if status == "revoked" {
			return ErrAdminKeyAlreadyRevoked
		}
		// This shouldn't happen, but handle it
		return fmt.Errorf("admin key not found: %s", id)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// CountActiveSuperAdminKeys returns the count of active admin keys belonging to
// operators who have super:admin role in any tenant. Used to prevent revoking the
// last active super:admin key, which would cause system lockout.
func (s *Store) CountActiveSuperAdminKeys() (int, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(DISTINCT ak.id)
		FROM admin_keys ak
		INNER JOIN operator_tenants ot ON ak.operator_id = ot.operator_id
		WHERE ak.status = 'active' AND ot.role = 'super:admin'
	`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active super admin keys: %w", err)
	}
	return count, nil
}

// IsAdminKeyLastActiveSuperAdmin checks if the given admin key is the only active
// admin key for a super:admin operator. Returns true if revoking this key would
// cause system lockout.
func (s *Store) IsAdminKeyLastActiveSuperAdmin(adminKeyID string) (bool, error) {
	// First check if this admin key belongs to a super:admin
	var isSuperAdminKey int
	err := s.db.QueryRow(`
		SELECT COUNT(*)
		FROM admin_keys ak
		INNER JOIN operator_tenants ot ON ak.operator_id = ot.operator_id
		WHERE ak.id = ? AND ak.status = 'active' AND ot.role = 'super:admin'
	`, adminKeyID).Scan(&isSuperAdminKey)
	if err != nil {
		return false, fmt.Errorf("failed to check if key is super admin: %w", err)
	}

	// If this key doesn't belong to a super:admin, it's safe to revoke
	if isSuperAdminKey == 0 {
		return false, nil
	}

	// Count all active super:admin keys
	totalActive, err := s.CountActiveSuperAdminKeys()
	if err != nil {
		return false, err
	}

	// If this is the only active super:admin key, revocation would cause lockout
	return totalActive <= 1, nil
}

func (s *Store) scanAdminKey(row *sql.Row) (*AdminKey, error) {
	var ak AdminKey
	var boundAt int64
	var lastSeen sql.NullInt64
	var name sql.NullString
	var revokedAt sql.NullInt64
	var revokedBy sql.NullString
	var revokedReason sql.NullString

	err := row.Scan(&ak.ID, &ak.OperatorID, &name, &ak.PublicKey, &ak.Kid,
		&ak.KeyFingerprint, &ak.Status, &boundAt, &lastSeen,
		&revokedAt, &revokedBy, &revokedReason)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("admin key not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan admin key: %w", err)
	}

	if name.Valid {
		ak.Name = name.String
	}
	ak.BoundAt = time.Unix(boundAt, 0)
	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		ak.LastSeen = &t
	}
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		ak.RevokedAt = &t
	}
	if revokedBy.Valid {
		ak.RevokedBy = &revokedBy.String
	}
	if revokedReason.Valid {
		ak.RevokedReason = &revokedReason.String
	}

	return &ak, nil
}

func (s *Store) scanAdminKeyRows(rows *sql.Rows) (*AdminKey, error) {
	var ak AdminKey
	var boundAt int64
	var lastSeen sql.NullInt64
	var name sql.NullString
	var revokedAt sql.NullInt64
	var revokedBy sql.NullString
	var revokedReason sql.NullString

	err := rows.Scan(&ak.ID, &ak.OperatorID, &name, &ak.PublicKey, &ak.Kid,
		&ak.KeyFingerprint, &ak.Status, &boundAt, &lastSeen,
		&revokedAt, &revokedBy, &revokedReason)
	if err != nil {
		return nil, fmt.Errorf("failed to scan admin key: %w", err)
	}

	if name.Valid {
		ak.Name = name.String
	}
	ak.BoundAt = time.Unix(boundAt, 0)
	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		ak.LastSeen = &t
	}
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		ak.RevokedAt = &t
	}
	if revokedBy.Valid {
		ak.RevokedBy = &revokedBy.String
	}
	if revokedReason.Valid {
		ak.RevokedReason = &revokedReason.String
	}

	return &ak, nil
}

// ----- KeyMaker DPoP Lookup Methods -----

// GetKeyMakerByKid retrieves a KeyMaker by its DPoP key identifier.
// Used for O(1) lookup during DPoP token validation.
func (s *Store) GetKeyMakerByKid(kid string) (*KeyMaker, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, name, platform, secure_element, device_fingerprint, public_key, bound_at, last_seen, status, kid, key_fingerprint, revoked_at, revoked_by, revoked_reason
		 FROM keymakers WHERE kid = ?`,
		kid,
	)
	return s.scanKeyMakerWithDPoP(row)
}

func (s *Store) scanKeyMakerWithDPoP(row *sql.Row) (*KeyMaker, error) {
	var km KeyMaker
	var boundAt int64
	var lastSeen sql.NullInt64
	var kid sql.NullString
	var keyFingerprint sql.NullString
	var revokedAt sql.NullInt64
	var revokedBy sql.NullString
	var revokedReason sql.NullString

	err := row.Scan(&km.ID, &km.OperatorID, &km.Name, &km.Platform, &km.SecureElement,
		&km.DeviceFingerprint, &km.PublicKey, &boundAt, &lastSeen, &km.Status, &kid, &keyFingerprint,
		&revokedAt, &revokedBy, &revokedReason)
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
	if kid.Valid {
		km.Kid = kid.String
	}
	if keyFingerprint.Valid {
		km.KeyFingerprint = keyFingerprint.String
	}
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		km.RevokedAt = &t
	}
	if revokedBy.Valid {
		km.RevokedBy = &revokedBy.String
	}
	if revokedReason.Valid {
		km.RevokedReason = &revokedReason.String
	}

	return &km, nil
}

// ----- DPU DPoP Lookup Methods -----

// GetDPUByKid retrieves a DPU by its DPoP key identifier.
// Used for O(1) lookup during DPoP token validation.
func (s *Store) GetDPUByKid(kid string) (*DPU, error) {
	row := s.db.QueryRow(
		`SELECT id, name, host, port, status, last_seen, created_at, tenant_id, labels, public_key, kid, key_fingerprint, enrollment_expires_at, decommissioned_at, decommissioned_by, decommissioned_reason
		 FROM dpus WHERE kid = ?`,
		kid,
	)
	return s.scanDPUWithDPoP(row)
}

// GetDPUByFingerprint retrieves a DPU by its key fingerprint.
// Used for duplicate key detection during DPU enrollment.
// Returns nil, nil if not found (does not return error for not-found case).
func (s *Store) GetDPUByFingerprint(fingerprint string) (*DPU, error) {
	row := s.db.QueryRow(
		`SELECT id, name, host, port, status, last_seen, created_at, tenant_id, labels, public_key, kid, key_fingerprint, enrollment_expires_at, decommissioned_at, decommissioned_by, decommissioned_reason
		 FROM dpus WHERE key_fingerprint = ?`,
		fingerprint,
	)
	dpu, err := s.scanDPUWithDPoP(row)
	if err != nil && strings.Contains(err.Error(), "not found") {
		return nil, nil
	}
	return dpu, err
}

func (s *Store) scanDPUWithDPoP(row *sql.Row) (*DPU, error) {
	var dpu DPU
	var lastSeen sql.NullInt64
	var createdAt int64
	var tenantID sql.NullString
	var labelsJSON string
	var publicKey []byte
	var kid sql.NullString
	var keyFingerprint sql.NullString
	var enrollmentExpiresAt sql.NullInt64
	var decommissionedAt sql.NullInt64
	var decommissionedBy sql.NullString
	var decommissionedReason sql.NullString

	err := row.Scan(&dpu.ID, &dpu.Name, &dpu.Host, &dpu.Port, &dpu.Status, &lastSeen,
		&createdAt, &tenantID, &labelsJSON, &publicKey, &kid, &keyFingerprint, &enrollmentExpiresAt,
		&decommissionedAt, &decommissionedBy, &decommissionedReason)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("DPU not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan DPU: %w", err)
	}

	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		dpu.LastSeen = &t
	}
	dpu.CreatedAt = time.Unix(createdAt, 0)
	if tenantID.Valid {
		dpu.TenantID = &tenantID.String
	}
	dpu.Labels = make(map[string]string)
	if labelsJSON != "" {
		json.Unmarshal([]byte(labelsJSON), &dpu.Labels)
	}
	dpu.PublicKey = publicKey
	if kid.Valid {
		dpu.Kid = &kid.String
	}
	if keyFingerprint.Valid {
		dpu.KeyFingerprint = &keyFingerprint.String
	}
	if enrollmentExpiresAt.Valid {
		t := time.Unix(enrollmentExpiresAt.Int64, 0)
		dpu.EnrollmentExpiresAt = &t
	}
	if decommissionedAt.Valid {
		t := time.Unix(decommissionedAt.Int64, 0)
		dpu.DecommissionedAt = &t
	}
	if decommissionedBy.Valid {
		dpu.DecommissionedBy = &decommissionedBy.String
	}
	if decommissionedReason.Valid {
		dpu.DecommissionedReason = &decommissionedReason.String
	}

	return &dpu, nil
}

// ----- Filtered List Methods for Admin Endpoints -----

// ListOptions contains options for filtered list queries.
type ListOptions struct {
	Status   string // Filter by status (e.g., "active", "suspended", "revoked")
	TenantID string // Filter by tenant ID
	Limit    int    // Maximum number of results (0 = no limit)
	Offset   int    // Number of results to skip
}

// ListOperatorsFiltered returns operators with optional status and tenant filters.
// If tenantID is provided, only returns operators who are members of that tenant.
// Returns operators ordered by email with lifecycle fields populated.
func (s *Store) ListOperatorsFiltered(opts ListOptions) ([]*Operator, int, error) {
	// Build query based on filters
	var query string
	var countQuery string
	var args []interface{}

	if opts.TenantID != "" {
		// Join with operator_tenants to filter by tenant
		query = `SELECT DISTINCT o.id, o.email, o.display_name, o.status, o.created_at, o.last_login,
				o.suspended_at, o.suspended_by, o.suspended_reason
				FROM operators o
				INNER JOIN operator_tenants ot ON o.id = ot.operator_id
				WHERE ot.tenant_id = ?`
		countQuery = `SELECT COUNT(DISTINCT o.id) FROM operators o
				INNER JOIN operator_tenants ot ON o.id = ot.operator_id
				WHERE ot.tenant_id = ?`
		args = append(args, opts.TenantID)
	} else {
		query = `SELECT id, email, display_name, status, created_at, last_login,
				suspended_at, suspended_by, suspended_reason
				FROM operators WHERE 1=1`
		countQuery = `SELECT COUNT(*) FROM operators WHERE 1=1`
	}

	// Add status filter
	if opts.Status != "" {
		query += " AND o.status = ?"
		countQuery += " AND o.status = ?"
		if opts.TenantID == "" {
			// Adjust for non-joined query
			query = strings.Replace(query, "AND o.status", "AND status", 1)
			countQuery = strings.Replace(countQuery, "AND o.status", "AND status", 1)
		}
		args = append(args, opts.Status)
	}

	// Get total count first
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count operators: %w", err)
	}

	// Add ordering and pagination
	query += " ORDER BY email"
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list operators: %w", err)
	}
	defer rows.Close()

	var operators []*Operator
	for rows.Next() {
		op, err := s.scanOperatorRows(rows)
		if err != nil {
			return nil, 0, err
		}
		operators = append(operators, op)
	}
	return operators, total, rows.Err()
}

// ListKeyMakersFiltered returns keymakers with optional status and tenant filters.
// If tenantID is provided, only returns keymakers for operators who are members of that tenant.
// Returns keymakers ordered by bound_at DESC with lifecycle fields populated.
func (s *Store) ListKeyMakersFiltered(opts ListOptions) ([]*KeyMaker, int, error) {
	// Build query based on filters
	var query string
	var countQuery string
	var args []interface{}

	if opts.TenantID != "" {
		// Join with operator_tenants to filter by tenant
		query = `SELECT DISTINCT k.id, k.operator_id, k.name, k.platform, k.secure_element,
				k.device_fingerprint, k.public_key, k.bound_at, k.last_seen, k.status,
				k.revoked_at, k.revoked_by, k.revoked_reason
				FROM keymakers k
				INNER JOIN operator_tenants ot ON k.operator_id = ot.operator_id
				WHERE ot.tenant_id = ?`
		countQuery = `SELECT COUNT(DISTINCT k.id) FROM keymakers k
				INNER JOIN operator_tenants ot ON k.operator_id = ot.operator_id
				WHERE ot.tenant_id = ?`
		args = append(args, opts.TenantID)
	} else {
		query = `SELECT id, operator_id, name, platform, secure_element,
				device_fingerprint, public_key, bound_at, last_seen, status,
				revoked_at, revoked_by, revoked_reason
				FROM keymakers WHERE 1=1`
		countQuery = `SELECT COUNT(*) FROM keymakers WHERE 1=1`
	}

	// Add status filter
	if opts.Status != "" {
		if opts.TenantID != "" {
			query += " AND k.status = ?"
			countQuery += " AND k.status = ?"
		} else {
			query += " AND status = ?"
			countQuery += " AND status = ?"
		}
		args = append(args, opts.Status)
	}

	// Get total count first
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count keymakers: %w", err)
	}

	// Add ordering and pagination
	if opts.TenantID != "" {
		query += " ORDER BY k.bound_at DESC"
	} else {
		query += " ORDER BY bound_at DESC"
	}
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list keymakers: %w", err)
	}
	defer rows.Close()

	var keymakers []*KeyMaker
	for rows.Next() {
		km, err := s.scanKeyMakerRows(rows)
		if err != nil {
			return nil, 0, err
		}
		keymakers = append(keymakers, km)
	}
	return keymakers, total, rows.Err()
}
