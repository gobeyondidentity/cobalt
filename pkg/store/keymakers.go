// KeyMaker store methods.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// ErrAlreadyRevoked is returned when attempting to revoke an already-revoked KeyMaker.
var ErrAlreadyRevoked = fmt.Errorf("keymaker already revoked")

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

// ----- KeyMaker Filtered List -----

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

// ----- Key Fingerprint Helper -----

// KeyFingerprint computes SHA256 of raw public key bytes, returns hex-encoded string.
// Used for duplicate key detection and DPoP binding.
func KeyFingerprint(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString(hash[:])
}
