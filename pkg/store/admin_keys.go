// AdminKey store methods.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// ErrAdminKeyAlreadyRevoked is returned when attempting to revoke an already-revoked AdminKey.
var ErrAdminKeyAlreadyRevoked = fmt.Errorf("admin key already revoked")

// ErrWouldCauseLockout is returned when revoking an admin key would leave zero active super:admin keys.
var ErrWouldCauseLockout = fmt.Errorf("would cause system lockout")

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
